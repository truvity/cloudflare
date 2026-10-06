// Package edge is the edge stack factory: per Cloudflare account a
// provider, per zone its settings (pkg/zone), and per cluster and account
// one remotely managed tunnel (pkg/tunnel) with its ingress rules and DNS
// records, from one plain Args value.
//
// The library's contract holds here too. Mechanism only: nothing names an
// account, a zone, a host or a cluster, Args carries them. Credentials come
// in (each account's token is resolved by the caller, because reading it is
// a plain call at program time that configures a provider, not an Output)
// and secrets go out: each tunnel's token is handed to the caller's
// [TokenSink], which decides where it lives.
//
// An estate adopting this over resources it already has passes the
// *Options hooks, which add pulumi.Aliases (or any other resource option)
// to the accounts, zones and tunnels, so that the first preview is empty.
package edge

import (
	"fmt"
	"log/slog"
	"sort"

	"github.com/pulumi/pulumi-random/sdk/v4/go/random"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/cloudflare/v2/pkg/account"
	"github.com/truvity/cloudflare/v2/pkg/tunnel"
	"github.com/truvity/cloudflare/v2/pkg/zone"
)

const (
	// DefaultCAPoolPath is where the cloudflared chart mounts the origin CA
	// root (charts/cloudflared). The remote tunnel config names it, so the
	// mount must exist before a path that uses it ships.
	DefaultCAPoolPath = "/etc/cloudflared/certs/ca.pem"
	// DefaultOriginPort is the HTTPS port of an origin service.
	DefaultOriginPort = 443
)

type (
	// Account is one Cloudflare account and the already-resolved token its
	// provider authenticates with.
	Account struct {
		Name      string
		AccountID string
		Token     string
	}

	// Zone is one zone's settings, in the library's own shape. The account
	// that owns it is named by Account.
	Zone struct {
		// Name is the zone's own name; its slug names the Pulumi resources.
		Name    string
		Account string
		Args    zone.Args
	}

	// Tunnel is one tunnel: the hosts one cluster serves through one
	// account's zone.
	Tunnel struct {
		// Name is the tunnel's name and the Pulumi name of every resource
		// built for it.
		Name    string
		Cluster string
		Account string
		Zone    string
		// Hosts arrive derived and in ingress order, all in Zone.
		Hosts []string
		// DNSDomain is the cluster's Kubernetes DNS domain, for the origin
		// service address. Empty falls back to "cluster."+Cluster.
		DNSDomain string
	}

	// Origin is the in-cluster service every ingress rule routes to.
	Origin struct {
		Service   string
		Namespace string
	}

	// TokenSink stores one tunnel's token where its cluster reads it. The
	// token is the library's secret Output.
	TokenSink func(ctx *pulumi.Context, t Tunnel, token pulumi.StringOutput) error

	// Args is the whole edge stack.
	Args struct {
		Accounts []Account
		Zones    []Zone
		Tunnels  []Tunnel
		Origin   Origin
		// CAPoolPath defaults to DefaultCAPoolPath.
		CAPoolPath string
		// Sink receives each tunnel's token. Required.
		Sink TokenSink

		// AccountOptions, ZoneOptions and TunnelOptions add resource
		// options (typically aliases) to what is registered for each.
		AccountOptions func(Account) []pulumi.ResourceOption
		ZoneOptions    func(Zone) []pulumi.ResourceOption
		TunnelOptions  func(Tunnel) []pulumi.ResourceOption

		Logger *slog.Logger
	}
)

// Deploy registers the stack and exports "tunnelIds", the tunnel ids by
// name.
func Deploy(ctx *pulumi.Context, args Args) error {
	if args.Sink == nil {
		return fmt.Errorf("edge: a TokenSink is required: where a tunnel token lives is the caller's decision")
	}

	logger := args.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	accountConfigs := make(map[string]Account, len(args.Accounts))
	for _, a := range args.Accounts {
		accountConfigs[a.Name] = a
	}

	accounts := make(map[string]*account.Account, len(args.Accounts))

	for _, a := range sortedAccounts(args.Accounts) {
		acct, err := newAccount(ctx, logger, args, a)
		if err != nil {
			return fmt.Errorf("account %s: %w", a.Name, err)
		}

		accounts[a.Name] = acct
	}

	zoneIDs := make(map[string]string, len(args.Zones))

	for _, z := range sortedZones(args.Zones) {
		zoneIDs[z.Name] = z.Args.ZoneID

		acct, ok := accounts[z.Account]
		if !ok {
			return fmt.Errorf("zone %s: account %q is not declared", z.Name, z.Account)
		}

		opts := []pulumi.ResourceOption{acct.Use()}
		if args.ZoneOptions != nil {
			opts = append(opts, args.ZoneOptions(z)...)
		}

		if _, err := zone.New(ctx, tunnel.Slug(z.Name), z.Args, opts...); err != nil {
			return fmt.Errorf("zone %s: %w", z.Name, err)
		}
	}

	tunnelIDs := make(pulumi.StringMap)

	for _, t := range args.Tunnels {
		acct, ok := accounts[t.Account]
		if !ok {
			return fmt.Errorf("tunnel %s: account %q is not declared", t.Name, t.Account)
		}

		if err := deployTunnel(ctx, logger, args, acct, accountConfigs[t.Account], zoneIDs, t, tunnelIDs); err != nil {
			return fmt.Errorf("deploy tunnel %s: %w", t.Name, err)
		}
	}

	ctx.Export("tunnelIds", tunnelIDs)

	logger.InfoContext(ctx.Context(), "cloudflare tunnel stack deployed",
		slog.Int("accounts", len(args.Accounts)),
		slog.Int("zones", len(args.Zones)),
		slog.Int("tunnels", len(args.Tunnels)),
	)

	return nil
}

func newAccount(ctx *pulumi.Context, logger *slog.Logger, args Args, a Account) (*account.Account, error) {
	if a.Token == "" {
		return nil, fmt.Errorf("no resolved API token (the caller must resolve it before Deploy)")
	}

	var opts []pulumi.ResourceOption
	if args.AccountOptions != nil {
		opts = args.AccountOptions(a)
	}

	acct, err := account.New(ctx, a.Name, account.Args{AccountID: a.AccountID}, pulumi.String(a.Token), opts...)
	if err != nil {
		return nil, err
	}

	logger.InfoContext(ctx.Context(), "cloudflare provider created from the resolved child token",
		slog.String("account", a.Name),
	)

	return acct, nil
}

// TunnelArgs maps one tunnel onto the library's Args: pure translation, no
// resources.
func TunnelArgs(args Args, accountID, zoneID string, t Tunnel) tunnel.Args {
	dnsDomain := t.DNSDomain
	if dnsDomain == "" {
		dnsDomain = "cluster." + t.Cluster
	}

	caPool := args.CAPoolPath
	if caPool == "" {
		caPool = DefaultCAPoolPath
	}

	origin := fmt.Sprintf("https://%s.%s.svc.%s:%d", args.Origin.Service, args.Origin.Namespace, dnsDomain, DefaultOriginPort)

	ingress := make([]tunnel.Ingress, 0, len(t.Hosts))
	for _, host := range t.Hosts {
		ingress = append(ingress, tunnel.Ingress{
			Hostname:         host,
			Service:          origin,
			OriginServerName: host,
			CAPool:           caPool,
		})
	}

	// No certificate packs: the zone's Total TLS issues a certificate for
	// every proxied hostname, including the ones deeper than Universal SSL's
	// wildcard.
	return tunnel.Args{
		AccountID: accountID,
		Name:      t.Name,
		Ingress:   ingress,
		DNS:       &tunnel.DNS{ZoneID: zoneID, Names: t.Hosts},
	}
}

func deployTunnel(
	ctx *pulumi.Context,
	logger *slog.Logger,
	args Args,
	acct *account.Account,
	acctCfg Account,
	zoneIDs map[string]string,
	t Tunnel,
	tunnelIDs pulumi.StringMap,
) error {
	zoneID, ok := zoneIDs[t.Zone]
	if !ok {
		return fmt.Errorf("zone %q is not declared", t.Zone)
	}

	// Random bytes held in Pulumi state, never derived from anything public.
	secret, err := random.NewRandomBytes(ctx, "tunnel-secret-"+t.Name, &random.RandomBytesArgs{
		Length: pulumi.Int(32),
	})
	if err != nil {
		return fmt.Errorf("tunnel secret for %s: %w", t.Name, err)
	}

	opts := []pulumi.ResourceOption{acct.Use()}
	if args.TunnelOptions != nil {
		opts = append(opts, args.TunnelOptions(t)...)
	}

	tun, err := tunnel.New(ctx, t.Name, TunnelArgs(args, acctCfg.AccountID, zoneID, t), secret.Base64, opts...)
	if err != nil {
		return err
	}

	tunnelIDs[t.Name] = tun.ID

	if err := args.Sink(ctx, t, tun.Token); err != nil {
		return err
	}

	logger.InfoContext(ctx.Context(), "cluster tunnel deployed",
		slog.String("cluster", t.Cluster),
		slog.String("account", t.Account),
		slog.String("tunnel_name", t.Name),
		slog.Int("hosts", len(t.Hosts)),
	)

	return nil
}

func sortedAccounts(in []Account) []Account {
	out := append([]Account(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })

	return out
}

func sortedZones(in []Zone) []Zone {
	out := append([]Zone(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })

	return out
}
