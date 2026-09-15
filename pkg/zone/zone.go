// Package zone applies the handful of zone-level settings an estate
// actually decides: how Cloudflare talks to the origin, the floor it will
// negotiate with a browser, and whether every proxied hostname gets a
// certificate without anyone asking for one.
//
// This is deliberately small. A Cloudflare zone has scores of settings and
// most are defaults nobody should be managing from a deployment tool; the
// three here change what traffic is and is not accepted, so they belong in
// the same review as the routes that depend on them.
//
// Total TLS is the reason this package exists. Without it every proxied
// hostname needs its own Advanced Certificate pack, so adding a hostname
// means creating a certificate resource and waiting for validation. With
// it, the zone issues per-hostname certificates itself and adding a
// hostname is a DNS record and nothing else. It requires Advanced
// Certificate Manager on the zone's plan, which is why it is opt-in.
//
// The library's contract, shared by every public truvity module:
//
//   - Mechanism only. Nothing here knows a zone id or a domain; Args is a
//     plain yaml-taggable struct a consumer unmarshals its own config into.
//   - Credentials come in. The provider is the caller's — pass it with
//     pulumi.Provider, or account.Use() from this module's account package.
//   - Nothing implicit. An unset field is not managed: a zone whose SSL
//     mode this estate does not decide keeps whatever it has.
package zone

import (
	"fmt"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// Setting identifiers, as Cloudflare names them.
const (
	settingSSL           = "ssl"
	settingMinTLSVersion = "min_tls_version"
)

var (
	validSSL           = []string{"off", "flexible", "full", "strict"}
	validMinTLSVersion = []string{"1.0", "1.1", "1.2", "1.3"}
	validCA            = []string{"google", "lets_encrypt", "ssl_com"}
)

type (
	// TotalTLS asks the zone to issue a certificate for every proxied A,
	// AAAA or CNAME record, so a new hostname needs no certificate
	// resource of its own. Requires Advanced Certificate Manager.
	TotalTLS struct {
		// Enabled turns per-hostname issuance on. Required.
		Enabled bool `json:"enabled" yaml:"enabled"`
		// CertificateAuthority to issue through: google, lets_encrypt or
		// ssl_com. Empty leaves Cloudflare's default.
		CertificateAuthority string `json:"certificateAuthority,omitempty" yaml:"certificateAuthority,omitempty"`
	}

	// Args is one zone's settings. Every field is optional: an unset
	// field is a setting this estate does not manage.
	Args struct {
		// ZoneID the settings apply to. Required.
		ZoneID string `json:"zoneId" yaml:"zoneId"`
		// SSL is how Cloudflare connects to the origin: off, flexible,
		// full or strict. "full" encrypts to the origin and accepts any
		// certificate; "strict" also verifies it, which needs a
		// certificate the public CAs or Cloudflare's own origin CA
		// signed.
		SSL string `json:"ssl,omitempty" yaml:"ssl,omitempty"`
		// MinTLSVersion a browser must offer: 1.0, 1.1, 1.2 or 1.3.
		MinTLSVersion string `json:"minTlsVersion,omitempty" yaml:"minTlsVersion,omitempty"`
		// TotalTLS issues a certificate per proxied hostname. Nil leaves
		// the zone alone.
		TotalTLS *TotalTLS `json:"totalTls,omitempty" yaml:"totalTls,omitempty"`
	}

	// Zone is the applied settings for one zone.
	Zone struct {
		pulumi.ResourceState

		// ZoneID the settings were applied to.
		ZoneID pulumi.StringOutput `pulumi:"zoneId"`
	}
)

func oneOf(value string, allowed []string) bool {
	for _, a := range allowed {
		if value == a {
			return true
		}
	}

	return false
}

// Validate reports the first problem with args.
func (a *Args) Validate() error {
	if a.ZoneID == "" {
		return fmt.Errorf("zone: zoneId is required")
	}

	if a.SSL != "" && !oneOf(a.SSL, validSSL) {
		return fmt.Errorf("zone %q: ssl %q must be one of %v", a.ZoneID, a.SSL, validSSL)
	}

	if a.MinTLSVersion != "" && !oneOf(a.MinTLSVersion, validMinTLSVersion) {
		return fmt.Errorf("zone %q: minTlsVersion %q must be one of %v", a.ZoneID, a.MinTLSVersion, validMinTLSVersion)
	}

	if a.TotalTLS != nil {
		ca := a.TotalTLS.CertificateAuthority
		if ca != "" && !oneOf(ca, validCA) {
			return fmt.Errorf("zone %q: totalTls.certificateAuthority %q must be one of %v", a.ZoneID, ca, validCA)
		}
	}

	if a.SSL == "" && a.MinTLSVersion == "" && a.TotalTLS == nil {
		return fmt.Errorf("zone %q: nothing to apply — omit the zone instead of declaring one that manages no setting", a.ZoneID)
	}

	return nil
}

// New applies one zone's settings. Children are named "setting-<name>-ssl",
// "setting-<name>-min-tls-version" and "total-tls-<name>", a documented
// contract: consumers alias existing resources onto these names.
func New(ctx *pulumi.Context, name string, args Args, opts ...pulumi.ResourceOption) (*Zone, error) {
	if err := args.Validate(); err != nil {
		return nil, err
	}

	comp := &Zone{}
	if err := ctx.RegisterComponentResource("truvity:cloudflare:Zone", name, comp, opts...); err != nil {
		return nil, err
	}

	child := []pulumi.ResourceOption{pulumi.Parent(comp)}
	zoneID := pulumi.String(args.ZoneID)

	if args.SSL != "" {
		if _, err := cloudflare.NewZoneSetting(ctx, "setting-"+name+"-ssl", &cloudflare.ZoneSettingArgs{
			ZoneId:    zoneID,
			SettingId: pulumi.String(settingSSL),
			Value:     pulumi.String(args.SSL),
		}, child...); err != nil {
			return nil, fmt.Errorf("zone %q: ssl: %w", name, err)
		}
	}

	if args.MinTLSVersion != "" {
		if _, err := cloudflare.NewZoneSetting(ctx, "setting-"+name+"-min-tls-version", &cloudflare.ZoneSettingArgs{
			ZoneId:    zoneID,
			SettingId: pulumi.String(settingMinTLSVersion),
			Value:     pulumi.String(args.MinTLSVersion),
		}, child...); err != nil {
			return nil, fmt.Errorf("zone %q: minTlsVersion: %w", name, err)
		}
	}

	if args.TotalTLS != nil {
		tArgs := &cloudflare.TotalTlsArgs{
			ZoneId:  zoneID,
			Enabled: pulumi.Bool(args.TotalTLS.Enabled),
		}
		if args.TotalTLS.CertificateAuthority != "" {
			tArgs.CertificateAuthority = pulumi.String(args.TotalTLS.CertificateAuthority)
		}

		if _, err := cloudflare.NewTotalTls(ctx, "total-tls-"+name, tArgs, child...); err != nil {
			return nil, fmt.Errorf("zone %q: totalTls: %w", name, err)
		}
	}

	comp.ZoneID = zoneID.ToStringOutput()

	if err := ctx.RegisterResourceOutputs(comp, pulumi.Map{
		"zoneId": comp.ZoneID,
	}); err != nil {
		return nil, err
	}

	return comp, nil
}
