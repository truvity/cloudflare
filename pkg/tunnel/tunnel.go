// Package tunnel provisions a remotely-managed Cloudflare Tunnel — the
// tunnel itself, its ingress rules, the DNS records that point hostnames
// at it, and (opt-in) the Advanced Certificate packs — from one config
// struct.
//
// The library's contract, shared by every public truvity module:
//
//   - Mechanism only. Nothing here knows an account, a zone or a
//     hostname; Args carries them all, and Args is a plain yaml-taggable
//     struct so a consumer can unmarshal its own config file straight
//     into it.
//   - Credentials come in, secrets go out. The Cloudflare provider is
//     the caller's (pass it via pulumi.Provider). The tunnel secret is a
//     caller INPUT — random bytes from pulumi-random, or a value the
//     caller manages; this package never derives one. The tunnel token
//     is returned as a secret Output and the CALLER decides where it
//     lives (a Kubernetes Secret, SSM, SOPS — not this package's
//     business).
//   - No zone-level configuration. Plenty of Cloudflare plans have none:
//     zone settings are never touched, and Advanced Certificate packs
//     are an opt-in block that is off by default.
//
// The in-cluster half is charts/cloudflared in this repository: the
// remote tunnel config built here routes hostnames to origins, the chart
// runs the daemon that carries them.
package tunnel

import (
	"fmt"
	"strings"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type (
	// Ingress is one ordered rule of the remote tunnel configuration:
	// requests for Hostname are proxied to Service. First match wins,
	// and Cloudflare's `*` spans dots — list exact hostnames before
	// wildcards, and deeper wildcards before broader ones. The library
	// appends the catch-all `http_status:404` rule itself.
	Ingress struct {
		// Hostname the rule matches (exact or wildcard). Required.
		Hostname string `json:"hostname" yaml:"hostname"`
		// Service the matched requests are proxied to, e.g.
		// "https://gateway-internal.envoy-gateway-system.svc:443".
		Service string `json:"service" yaml:"service"`
		// OriginServerName is the TLS SNI presented to the origin.
		// Defaults to the rule's hostname when TLS settings are in play;
		// set explicitly when the origin's certificate says otherwise.
		OriginServerName string `json:"originServerName,omitempty" yaml:"originServerName,omitempty"`
		// CAPool is a file path INSIDE the cloudflared container holding
		// the CA that signed the origin's certificate (the chart mounts
		// caSecretName at /etc/cloudflared/certs/ca.pem). Set it and
		// cloudflared VERIFIES the origin instead of noTLSVerify.
		CAPool string `json:"caPool,omitempty" yaml:"caPool,omitempty"`
		// NoTLSVerify disables origin certificate verification for this
		// rule. Prefer CAPool.
		NoTLSVerify bool `json:"noTLSVerify,omitempty" yaml:"noTLSVerify,omitempty"`
	}

	// DNS declares the proxied CNAME records pointing hostnames at the
	// tunnel (<tunnel-id>.cfargotunnel.com).
	DNS struct {
		// ZoneID of the zone the records are created in. Required when
		// DNS is set.
		ZoneID string `json:"zoneId" yaml:"zoneId"`
		// Names to create, verbatim (exact hosts and wildcards alike).
		Names []string `json:"names" yaml:"names"`
	}

	// Certificates opts in to an Advanced Certificate pack per DNS name
	// — needed when hostnames sit DEEPER than one label under the zone
	// apex (Universal SSL covers only `*.<zone>`). Requires a plan with
	// Advanced Certificate Manager; the block is off by default because
	// plenty of plans have no zone-level features at all.
	Certificates struct {
		// ZoneID of the zone the packs are ordered in. Required when set.
		ZoneID string `json:"zoneId" yaml:"zoneId"`
		// Zone apex, appended to every pack's host list and used to skip
		// the top-level wildcard (`*.<zone>` — Universal SSL's job).
		Zone string `json:"zone" yaml:"zone"`
		// Hosts to order packs for. Defaults to DNS.Names.
		Hosts []string `json:"hosts,omitempty" yaml:"hosts,omitempty"`
		// ValidityDays per pack. Default 90.
		ValidityDays int `json:"validityDays,omitempty" yaml:"validityDays,omitempty"`
		// CertificateAuthority issuing the packs. Default "lets_encrypt".
		CertificateAuthority string `json:"certificateAuthority,omitempty" yaml:"certificateAuthority,omitempty"`
	}

	// Args configures one tunnel. Plain data, yaml/json-taggable — the
	// tunnel secret is deliberately NOT here (it is a credential, passed
	// separately to New).
	Args struct {
		// AccountID owning the tunnel. Required.
		AccountID string `json:"accountId" yaml:"accountId"`
		// Name of the tunnel as Cloudflare shows it. Required.
		Name string `json:"name" yaml:"name"`
		// Ingress rules, ordered. At least one required; the catch-all
		// 404 rule is appended by the library.
		Ingress []Ingress `json:"ingress" yaml:"ingress"`
		// DNS records for the tunnel. Optional — nil creates none.
		DNS *DNS `json:"dns,omitempty" yaml:"dns,omitempty"`
		// Certificates is the opt-in Advanced Certificate block.
		Certificates *Certificates `json:"certificates,omitempty" yaml:"certificates,omitempty"`
	}

	// Tunnel is the component. Child resources are named after the
	// component instance: `tunnel-<name>`, `ingress-<name>`,
	// `cname-<name>-<host-slug>`, `acm-<name>-<host-slug>` — documented
	// because a consumer migrating existing top-level resources maps
	// aliases onto exactly these names.
	Tunnel struct {
		pulumi.ResourceState

		// ID of the tunnel.
		ID pulumi.StringOutput `pulumi:"id"`
		// CNAMETarget is `<id>.cfargotunnel.com` — what DNS points at.
		CNAMETarget pulumi.StringOutput `pulumi:"cnameTarget"`
		// Token authenticates cloudflared (`--token-file`). Secret; the
		// caller stores it where their estate keeps secrets.
		Token pulumi.StringOutput `pulumi:"token"`
	}
)

// Validate reports the first configuration error. New calls it; callers
// unmarshaling YAML may want the error before a Pulumi run.
func (a *Args) Validate() error {
	if a.AccountID == "" {
		return fmt.Errorf("tunnel: accountId is required")
	}

	if a.Name == "" {
		return fmt.Errorf("tunnel: name is required")
	}

	if len(a.Ingress) == 0 {
		return fmt.Errorf("tunnel %q: at least one ingress rule is required", a.Name)
	}

	for i, r := range a.Ingress {
		if r.Hostname == "" || r.Service == "" {
			return fmt.Errorf("tunnel %q: ingress[%d] needs hostname and service (the catch-all rule is appended by the library)", a.Name, i)
		}
	}

	if a.DNS != nil {
		if a.DNS.ZoneID == "" {
			return fmt.Errorf("tunnel %q: dns.zoneId is required when dns is set", a.Name)
		}

		if len(a.DNS.Names) == 0 {
			return fmt.Errorf("tunnel %q: dns.names is empty — omit the dns block instead", a.Name)
		}
	}

	if c := a.Certificates; c != nil {
		if c.ZoneID == "" || c.Zone == "" {
			return fmt.Errorf("tunnel %q: certificates.zoneId and certificates.zone are required when certificates is set", a.Name)
		}

		if len(c.Hosts) == 0 && (a.DNS == nil || len(a.DNS.Names) == 0) {
			return fmt.Errorf("tunnel %q: certificates.hosts is empty and there are no dns.names to default from", a.Name)
		}
	}

	return nil
}

// Slug renders a hostname as a stable resource-name fragment
// ("*.devel.example.com" → "star-devel-example-com").
func Slug(host string) string {
	return strings.ReplaceAll(strings.ReplaceAll(host, "*", "star"), ".", "-")
}

// New provisions the tunnel. `secret` is the tunnel secret — 32 random
// bytes, base64 — supplied by the caller (pulumi-random's
// RandomBytes.Base64 is the usual source); it is marked secret
// regardless. Pass the Cloudflare provider and any transformations via
// opts; children inherit them through the component.
func New(ctx *pulumi.Context, name string, args Args, secret pulumi.StringInput, opts ...pulumi.ResourceOption) (*Tunnel, error) {
	if err := args.Validate(); err != nil {
		return nil, err
	}

	if secret == nil {
		return nil, fmt.Errorf("tunnel %q: secret is required (the library never derives one)", args.Name)
	}

	comp := &Tunnel{}
	if err := ctx.RegisterComponentResource("truvity:cloudflare:Tunnel", name, comp, opts...); err != nil {
		return nil, err
	}

	child := []pulumi.ResourceOption{pulumi.Parent(comp)}

	tun, err := cloudflare.NewZeroTrustTunnelCloudflared(ctx, "tunnel-"+name, &cloudflare.ZeroTrustTunnelCloudflaredArgs{
		AccountId: pulumi.String(args.AccountID),
		Name:      pulumi.String(args.Name),
		// Remotely managed: the ingress rules below ARE the config, and
		// cloudflared runs with nothing but the token (charts/cloudflared).
		ConfigSrc:    pulumi.String("cloudflare"),
		TunnelSecret: pulumi.ToSecret(secret).(pulumi.StringOutput),
	}, child...)
	if err != nil {
		return nil, fmt.Errorf("tunnel %q: %w", args.Name, err)
	}

	comp.ID = tun.ID().ToStringOutput()
	comp.CNAMETarget = comp.ID.ApplyT(func(id string) string { return id + ".cfargotunnel.com" }).(pulumi.StringOutput)
	comp.Token = pulumi.ToSecret(cloudflare.GetZeroTrustTunnelCloudflaredTokenOutput(ctx, cloudflare.GetZeroTrustTunnelCloudflaredTokenOutputArgs{
		AccountId: pulumi.String(args.AccountID),
		TunnelId:  tun.ID(),
	}, pulumi.Parent(comp)).Token()).(pulumi.StringOutput)

	if args.DNS != nil {
		for _, host := range args.DNS.Names {
			_, err := cloudflare.NewDnsRecord(ctx, "cname-"+name+"-"+Slug(host), &cloudflare.DnsRecordArgs{
				ZoneId:  pulumi.String(args.DNS.ZoneID),
				Name:    pulumi.String(host),
				Type:    pulumi.String("CNAME"),
				Content: comp.CNAMETarget,
				Proxied: pulumi.Bool(true),
				// 1 = automatic — required for proxied records.
				Ttl: pulumi.Float64(1),
			}, child...)
			if err != nil {
				return nil, fmt.Errorf("tunnel %q: cname %s: %w", args.Name, host, err)
			}
		}
	}

	if c := args.Certificates; c != nil {
		hosts := c.Hosts
		if len(hosts) == 0 {
			hosts = args.DNS.Names
		}

		validity := c.ValidityDays
		if validity == 0 {
			validity = 90
		}

		ca := c.CertificateAuthority
		if ca == "" {
			ca = "lets_encrypt"
		}

		for _, host := range hosts {
			// Universal SSL covers the top-level wildcard.
			if host == "*."+c.Zone {
				continue
			}

			_, err := cloudflare.NewCertificatePack(ctx, "acm-"+name+"-"+Slug(host), &cloudflare.CertificatePackArgs{
				ZoneId:               pulumi.String(c.ZoneID),
				Type:                 pulumi.String("advanced"),
				Hosts:                pulumi.ToStringArray([]string{host, c.Zone}),
				ValidationMethod:     pulumi.String("txt"),
				ValidityDays:         pulumi.Int(validity),
				CertificateAuthority: pulumi.String(ca),
			}, child...)
			if err != nil {
				return nil, fmt.Errorf("tunnel %q: certificate pack %s: %w", args.Name, host, err)
			}
		}
	}

	ingresses := cloudflare.ZeroTrustTunnelCloudflaredConfigConfigIngressArray{}
	for _, r := range args.Ingress {
		or := &cloudflare.ZeroTrustTunnelCloudflaredConfigConfigIngressOriginRequestArgs{}
		if r.OriginServerName != "" {
			or.OriginServerName = pulumi.String(r.OriginServerName)
		}

		if r.CAPool != "" {
			or.CaPool = pulumi.String(r.CAPool)
		}

		if r.NoTLSVerify {
			or.NoTlsVerify = pulumi.Bool(true)
		}

		ingresses = append(ingresses, &cloudflare.ZeroTrustTunnelCloudflaredConfigConfigIngressArgs{
			Hostname:      pulumi.String(r.Hostname),
			Service:       pulumi.String(r.Service),
			OriginRequest: or,
		})
	}

	ingresses = append(ingresses, &cloudflare.ZeroTrustTunnelCloudflaredConfigConfigIngressArgs{
		Service: pulumi.String("http_status:404"),
	})

	if _, err := cloudflare.NewZeroTrustTunnelCloudflaredConfig(ctx, "ingress-"+name, &cloudflare.ZeroTrustTunnelCloudflaredConfigArgs{
		AccountId: pulumi.String(args.AccountID),
		TunnelId:  tun.ID(),
		Config: &cloudflare.ZeroTrustTunnelCloudflaredConfigConfigArgs{
			Ingresses: ingresses,
		},
	}, child...); err != nil {
		return nil, fmt.Errorf("tunnel %q: ingress config: %w", args.Name, err)
	}

	if err := ctx.RegisterResourceOutputs(comp, pulumi.Map{
		"id":          comp.ID,
		"cnameTarget": comp.CNAMETarget,
		"token":       comp.Token,
	}); err != nil {
		return nil, err
	}

	return comp, nil
}
