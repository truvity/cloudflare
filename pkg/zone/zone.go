// Package zone applies the handful of zone-level settings an estate
// actually decides: how Cloudflare talks to the origin, the floor it will
// negotiate with a browser, and whether every proxied hostname gets a
// certificate without anyone asking for one.
//
// This is deliberately small. A Cloudflare zone has scores of settings and
// most are defaults nobody should be managing from a deployment tool; the
// few here change what traffic is and is not accepted, and which of it is
// stored at the edge, so they belong in the same review as the routes that
// depend on them.
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
	"strings"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// Setting identifiers, as Cloudflare names them.
const (
	settingSSL             = "ssl"
	settingMinTLSVersion   = "min_tls_version"
	settingBrowserCacheTTL = "browser_cache_ttl"
)

// The cache ruleset. A zone has one ruleset per phase, so a zone that
// declares a cache policy here owns the whole phase: rules added beside
// these in the dashboard are not merged with them, they are replaced.
const (
	cacheRulesetKind = "zone"
	cachePhase       = "http_request_cache_settings"
	// Cloudflare names the entry point ruleset of a phase "default".
	cacheRulesetName = "default"

	actionSetCacheSettings = "set_cache_settings"

	// Edge TTL: use the origin's Cache-Control when it sent one, and
	// bypass the cache when it did not. Cloudflare spells this
	// "bypass_by_default", which reads like "never cache" and is not:
	// the bypass is the FALLBACK, for a response whose origin said
	// nothing.
	edgeTTLOriginElseBypass = "bypass_by_default"
	// Browser TTL: hand the origin's Cache-Control to the browser
	// unchanged.
	browserTTLRespectOrigin = "respect_origin"

	// Browser Cache TTL, the zone setting: 0 is Cloudflare's "Respect
	// Existing Headers".
	browserCacheTTLRespectHeaders = 0
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

	// Cache decides WHICH of a zone's hostnames may be cached at all, and
	// leaves HOW LONG to the origin that serves them.
	//
	// The default it replaces is the reason it exists. A zone caches by
	// file extension: a response under a name ending in .js or .css is
	// stored at the edge whether or not its origin asked for that, and
	// where the origin sent no Cache-Control the zone tells the browser
	// to keep it for four hours. An application that answers its own
	// unknown paths — a single-page console serving its shell under every
	// name — then has one page cached under another page's name, and
	// nobody wrote that down anywhere.
	//
	// So a zone with this block caches the hostnames it lists and nothing
	// else, and each of those only as far as its own Cache-Control goes.
	// A response with no Cache-Control is not cached. Which means the
	// decision belongs where it can be read: in the application that
	// serves the bytes and knows whether they are content-addressed.
	Cache struct {
		// Hosts whose responses may be cached: an exact name
		// ("app.example") or one leading wildcard label
		// ("*.app.example").
		//
		// An EMPTY list is a policy and not an omission — the zone
		// caches nothing at all, which is what a zone serving only
		// applications that authenticate every request wants. To leave
		// caching unmanaged, omit the block.
		Hosts []string `json:"hosts" yaml:"hosts"`
		// RespectOriginBrowserTTL sets the zone setting Browser Cache
		// TTL to "Respect Existing Headers".
		//
		// The rules above decide what the EDGE stores. This is the
		// `Cache-Control` Cloudflare writes on the way out when the
		// origin sent none, and left alone it claims four hours for
		// every response of the zone — including the ones no rule here
		// caches, which is a browser holding what the edge would not.
		// False leaves the zone's setting as it is.
		RespectOriginBrowserTTL bool `json:"respectOriginBrowserTtl,omitempty" yaml:"respectOriginBrowserTtl,omitempty"`
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
		// Cache is which hostnames may be cached at all. Nil leaves the
		// zone's caching as it is, extensions and all.
		Cache *Cache `json:"cache,omitempty" yaml:"cache,omitempty"`
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

	if a.Cache != nil {
		if err := a.Cache.validate(a.ZoneID); err != nil {
			return err
		}
	}

	if a.SSL == "" && a.MinTLSVersion == "" && a.TotalTLS == nil && a.Cache == nil {
		return fmt.Errorf("zone %q: nothing to apply — omit the zone instead of declaring one that manages no setting", a.ZoneID)
	}

	return nil
}

// validate reports the first problem with a cache policy. Every rule here
// is a host that would be written into a Cloudflare filter expression and
// then match nothing, which is the failure this component exists to make
// impossible: a rule that is applied, reported healthy, and silent.
func (c *Cache) validate(zoneID string) error {
	seen := make(map[string]struct{}, len(c.Hosts))

	for i, host := range c.Hosts {
		switch {
		case host == "":
			return fmt.Errorf("zone %q: cache.hosts[%d] is empty", zoneID, i)

		case strings.ToLower(host) != host:
			return fmt.Errorf(
				"zone %q: cache.hosts[%d] %q must be lower case: Cloudflare compares a lower-cased host, so this rule would match nothing",
				zoneID, i, host)

		case strings.ContainsAny(host, `/:"\ `):
			return fmt.Errorf("zone %q: cache.hosts[%d] %q must be a hostname, not a URL", zoneID, i, host)

		case host == "*." || strings.Contains(strings.TrimPrefix(host, "*."), "*"):
			return fmt.Errorf(
				"zone %q: cache.hosts[%d] %q: a wildcard is one leading label and a name after it, as in \"*.app.example\"",
				zoneID, i, host)
		}

		if _, duplicate := seen[host]; duplicate {
			return fmt.Errorf("zone %q: cache.hosts[%d] %q is listed twice", zoneID, i, host)
		}

		seen[host] = struct{}{}
	}

	return nil
}

// hostExpression is the Cloudflare filter that matches the listed hosts.
// Exact names go in one set literal; each wildcard becomes a suffix test,
// because a set literal takes no wildcards.
func hostExpression(hosts []string) string {
	var (
		exact []string
		terms []string
	)

	for _, host := range hosts {
		if suffix, isWildcard := strings.CutPrefix(host, "*."); isWildcard {
			terms = append(terms, fmt.Sprintf("ends_with(http.host, %q)", "."+suffix))

			continue
		}

		exact = append(exact, fmt.Sprintf("%q", host))
	}

	if len(exact) > 0 {
		terms = append([]string{fmt.Sprintf("http.host in {%s}", strings.Join(exact, " "))}, terms...)
	}

	return strings.Join(terms, " or ")
}

// cacheRules is the phase's whole ruleset: one rule for the hostnames that
// may be cached, one for everything else.
//
// The two expressions PARTITION the zone — the second is the negation of
// the first — so exactly one of them matches any request. That costs a
// repeated expression and buys the thing worth having: the outcome does
// not depend on how Cloudflare merges two cache rules that both match, or
// on the order they happen to be in.
func cacheRules(hosts []string) cloudflare.RulesetRuleArray {
	bypass := cloudflare.RulesetRuleArgs{
		Action:      pulumi.String(actionSetCacheSettings),
		Description: pulumi.String("Not a cacheable hostname"),
		Expression:  pulumi.String("true"),
		ActionParameters: &cloudflare.RulesetRuleActionParametersArgs{
			Cache: pulumi.Bool(false),
		},
	}

	// No hosts: the catch-all is the whole policy, and the zone caches
	// nothing.
	if len(hosts) == 0 {
		return cloudflare.RulesetRuleArray{bypass}
	}

	cacheable := hostExpression(hosts)
	bypass.Expression = pulumi.String("not (" + cacheable + ")")

	return cloudflare.RulesetRuleArray{
		cloudflare.RulesetRuleArgs{
			Action:      pulumi.String(actionSetCacheSettings),
			Description: pulumi.String("Cacheable hostname: the origin's Cache-Control decides"),
			Expression:  pulumi.String(cacheable),
			ActionParameters: &cloudflare.RulesetRuleActionParametersArgs{
				Cache: pulumi.Bool(true),
				EdgeTtl: &cloudflare.RulesetRuleActionParametersEdgeTtlArgs{
					Mode: pulumi.String(edgeTTLOriginElseBypass),
				},
				BrowserTtl: &cloudflare.RulesetRuleActionParametersBrowserTtlArgs{
					Mode: pulumi.String(browserTTLRespectOrigin),
				},
			},
		},
		bypass,
	}
}

// New applies one zone's settings. Children are named "setting-<name>-ssl",
// "setting-<name>-min-tls-version", "setting-<name>-browser-cache-ttl",
// "total-tls-<name>" and "cache-rules-<name>", a documented contract:
// consumers alias existing resources onto these names.
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

	if args.Cache != nil {
		if _, err := cloudflare.NewRuleset(ctx, "cache-rules-"+name, &cloudflare.RulesetArgs{
			ZoneId: zoneID,
			Kind:   pulumi.String(cacheRulesetKind),
			Phase:  pulumi.String(cachePhase),
			Name:   pulumi.String(cacheRulesetName),
			Rules:  cacheRules(args.Cache.Hosts),
		}, child...); err != nil {
			return nil, fmt.Errorf("zone %q: cache: %w", name, err)
		}

		if args.Cache.RespectOriginBrowserTTL {
			if _, err := cloudflare.NewZoneSetting(ctx, "setting-"+name+"-browser-cache-ttl", &cloudflare.ZoneSettingArgs{
				ZoneId:    zoneID,
				SettingId: pulumi.String(settingBrowserCacheTTL),
				Value:     pulumi.Int(browserCacheTTLRespectHeaders),
			}, child...); err != nil {
				return nil, fmt.Errorf("zone %q: browser cache ttl: %w", name, err)
			}
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
