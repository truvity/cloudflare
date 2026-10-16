// Package instancetunnel is the tunnel of one instance: a remotely managed
// Cloudflare tunnel whose connector runs on a single host (cloudflare/
// instanceconnector) and reaches its origins on that host's loopback, with
// the proxied CNAME of every route that asks for one. It is the stack of a
// box outside any cluster (a status box), its own Pulumi stack and token.
//
// The registered names are Name's: the tunnel component and its children are
// named Name, the secret "<Name>-tunnel-secret", the provider
// "provider-<Name>" (unless the caller supplies one). Every record is
// written in the zone its route names; the resource name carries no zone.
package instancetunnel

import (
	"fmt"

	"github.com/pulumi/pulumi-random/sdk/v4/go/random"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/edge/v4/cloudflare/account"
	"github.com/truvity/edge/v4/cloudflare/tunnel"
)

type (
	// Route is one hostname the tunnel serves and where on the instance it
	// goes.
	Route struct {
		// Host is the exact or wildcard hostname of the ingress rule.
		Host string
		// Service is the origin on the instance, e.g. "http://127.0.0.1:8080".
		Service string
		// Zone is the name of the zone (one of Args.Zones) the route's proxied
		// CNAME is written in. Empty writes no record: something else answers
		// for the name.
		Zone string
	}

	// Args is the whole instance tunnel.
	Args struct {
		// Name is the Pulumi name of the tunnel component, of its provider
		// ("provider-<Name>") and of its secret ("<Name>-tunnel-secret").
		// Required.
		Name string
		// TunnelName is the tunnel's name in Cloudflare. Empty is Name.
		TunnelName string
		// AccountID owns the tunnel. Required.
		AccountID string
		// Routes are the ingress rules, in order. At least one.
		Routes []Route
		// Zones are the zones the routes' records are written in. Each Route.Zone
		// must be one of them.
		Zones []tunnel.DNSZone
		// Account is the provider of the tunnel's account, when the caller
		// has one. Otherwise Token builds one named "provider-<Name>".
		Account *account.Account
		// Token is the account's already-resolved API token, used when Account
		// is nil.
		Token string
		// Sink receives the tunnel's token (the library's secret Output).
		// Optional: the caller may use Tunnel.Token from the result instead.
		Sink func(ctx *pulumi.Context, token pulumi.StringOutput) error
	}
)

// Deploy registers the tunnel and hands its token to the sink.
func Deploy(ctx *pulumi.Context, args Args) (*tunnel.Tunnel, error) {
	if args.Name == "" || args.AccountID == "" {
		return nil, fmt.Errorf("instancetunnel: Name and AccountID are required")
	}

	ingress, dns, err := routing(args)
	if err != nil {
		return nil, err
	}

	acct := args.Account
	if acct == nil {
		if args.Token == "" {
			return nil, fmt.Errorf("instancetunnel %s: no account provider and no resolved API token", args.Name)
		}

		acct, err = account.New(ctx, args.Name, account.Args{AccountID: args.AccountID}, pulumi.String(args.Token))
		if err != nil {
			return nil, fmt.Errorf("instancetunnel %s: cloudflare account: %w", args.Name, err)
		}
	}

	secret, err := random.NewRandomBytes(ctx, args.Name+"-tunnel-secret", &random.RandomBytesArgs{Length: pulumi.Int(32)})
	if err != nil {
		return nil, fmt.Errorf("instancetunnel %s: tunnel secret: %w", args.Name, err)
	}

	cfName := args.TunnelName
	if cfName == "" {
		cfName = args.Name
	}

	tun, err := tunnel.New(ctx, args.Name, tunnel.Args{
		AccountID: args.AccountID,
		Name:      cfName,
		Ingress:   ingress,
		DNS:       dns,
	}, secret.Base64, acct.Use())
	if err != nil {
		return nil, fmt.Errorf("instancetunnel %s: %w", args.Name, err)
	}

	if args.Sink != nil {
		if err := args.Sink(ctx, tun.Token); err != nil {
			return nil, fmt.Errorf("instancetunnel %s: %w", args.Name, err)
		}
	}

	return tun, nil
}

// routing is the ingress (one rule per route, in order) and the DNS: every
// route with a zone gets the proxied CNAME, in that zone. The zones are those
// the routes use, in order of first use. Nil DNS when no route asks for a
// record.
func routing(args Args) ([]tunnel.Ingress, *tunnel.DNS, error) {
	if len(args.Routes) == 0 {
		return nil, nil, fmt.Errorf("instancetunnel %s: at least one route is required", args.Name)
	}

	byName := make(map[string]tunnel.DNSZone, len(args.Zones))
	for _, z := range args.Zones {
		byName[z.Name] = z
	}

	var (
		ingress = make([]tunnel.Ingress, 0, len(args.Routes))
		names   []string
		zones   []tunnel.DNSZone
		used    = map[string]bool{}
	)

	for _, r := range args.Routes {
		// The instance's own origin: no origin CA, no server name.
		ingress = append(ingress, tunnel.Ingress{Hostname: r.Host, Service: r.Service})

		if r.Zone == "" {
			continue
		}

		z, ok := byName[r.Zone]
		if !ok {
			return nil, nil, fmt.Errorf("instancetunnel %s: route %s names zone %q, which is not among Zones", args.Name, r.Host, r.Zone)
		}

		names = append(names, r.Host)

		if !used[z.Name] {
			used[z.Name] = true
			zones = append(zones, z)
		}
	}

	if len(names) == 0 {
		return ingress, nil, nil
	}

	return ingress, &tunnel.DNS{Names: names, Zones: zones}, nil
}
