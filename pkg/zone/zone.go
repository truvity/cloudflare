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
// Rate limiting rules protect public endpoints from a single noisy client.
// The plan decides how many rules a zone may hold and what they can count,
// so the plan is part of the declaration and every limit is checked before
// the apply, not after it.
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

	"github.com/truvity/cloudflare/v2/pkg/zonespec"
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

// The trusted-clients ruleset. Same rule as the cache ruleset: a zone has
// ONE entry point ruleset per phase, so a zone that declares trusted
// clients owns the whole http_request_firewall_custom phase.
const (
	firewallPhase       = "http_request_firewall_custom"
	firewallRulesetName = "default"
	// skipRuleset also skips the rest of the custom ruleset itself.
	skipRuleset = "current"

	rateLimitPhase       = "http_ratelimit"
	rateLimitRulesetName = "default"
)

// What a trusted client is exempted from, besides the rest of the custom
// rules. Phases: rate limiting, managed rules, Super Bot Fight Mode.
// Products: the legacy security products (browser integrity check,
// hotlink protection, legacy rate limiting, security level, user-agent
// rules, WAF, zone lockdown).
var (
	skipPhases   = []string{"http_ratelimit", "http_request_firewall_managed", "http_request_sbfm"}
	skipProducts = []string{"bic", "hot", "rateLimit", "securityLevel", "uaBlock", "waf", "zoneLockdown"}
)

// The declaration types and their validation live in pkg/zonespec, which
// links no Pulumi or Cloudflare SDK; they are aliased here so existing
// callers keep compiling. A caller that only validates a declaration should
// import pkg/zonespec directly.
type (
	// TotalTLS asks the zone to issue a certificate for every proxied A,
	// AAAA or CNAME record. See zonespec.TotalTLS.
	TotalTLS = zonespec.TotalTLS
	// Cache decides WHICH of a zone's hostnames may be cached at all. See
	// zonespec.Cache.
	Cache = zonespec.Cache
	// TrustedClients exempts client address ranges on named hosts. See
	// zonespec.TrustedClients.
	TrustedClients = zonespec.TrustedClients
	// Args is one zone's settings. See zonespec.Args.
	Args = zonespec.Args
	// RateLimits is the zone's whole http_ratelimit ruleset. See
	// zonespec.RateLimits.
	RateLimits = zonespec.RateLimits
	// RateLimitRule is one rate limiting rule. See zonespec.RateLimitRule.
	RateLimitRule = zonespec.RateLimitRule
	// Endpoint is one host and path a rate limit protects. See
	// zonespec.Endpoint.
	Endpoint = zonespec.Endpoint
)

// Plan names, as Cloudflare names the zone plans this library models.
const (
	PlanFree     = zonespec.PlanFree
	PlanPro      = zonespec.PlanPro
	PlanBusiness = zonespec.PlanBusiness
)

type (
	// Zone is the applied settings for one zone.
	Zone struct {
		pulumi.ResourceState

		// ZoneID the settings were applied to.
		ZoneID pulumi.StringOutput `pulumi:"zoneId"`
	}
)

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

	cacheable := zonespec.HostExpression(hosts)
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
// "total-tls-<name>", "cache-rules-<name>", "firewall-custom-<name>" and "ratelimit-<name>", a documented contract:
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

	if args.TrustedClients.Managed() {
		description := args.TrustedClients.Description
		if description == "" {
			description = zonespec.DefaultTrustedDescription
		}

		if _, err := cloudflare.NewRuleset(ctx, "firewall-custom-"+name, &cloudflare.RulesetArgs{
			ZoneId: zoneID,
			Kind:   pulumi.String(cacheRulesetKind),
			Phase:  pulumi.String(firewallPhase),
			Name:   pulumi.String(firewallRulesetName),
			Rules: cloudflare.RulesetRuleArray{
				cloudflare.RulesetRuleArgs{
					Action:      pulumi.String("skip"),
					Description: pulumi.String(description),
					Expression:  pulumi.String(zonespec.TrustedExpression(args.TrustedClients)),
					ActionParameters: &cloudflare.RulesetRuleActionParametersArgs{
						Ruleset:  pulumi.String(skipRuleset),
						Phases:   pulumi.ToStringArray(skipPhases),
						Products: pulumi.ToStringArray(skipProducts),
					},
					Logging: &cloudflare.RulesetRuleLoggingArgs{Enabled: pulumi.Bool(true)},
				},
			},
		}, child...); err != nil {
			return nil, fmt.Errorf("zone %q: trusted clients: %w", name, err)
		}
	}

	if args.RateLimits.Managed() {
		if _, err := cloudflare.NewRuleset(ctx, "ratelimit-"+name, &cloudflare.RulesetArgs{
			ZoneId: zoneID,
			Kind:   pulumi.String(cacheRulesetKind),
			Phase:  pulumi.String(rateLimitPhase),
			Name:   pulumi.String(rateLimitRulesetName),
			Rules:  rateLimitRules(args.RateLimits.Rules),
		}, child...); err != nil {
			return nil, fmt.Errorf("zone %q: rate limits: %w", name, err)
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

// rateLimitRules is the phase's whole ruleset, in the order declared.
func rateLimitRules(rules []RateLimitRule) cloudflare.RulesetRuleArray {
	out := cloudflare.RulesetRuleArray{}

	for i := range rules {
		r := &rules[i]

		limit := &cloudflare.RulesetRuleRatelimitArgs{
			Characteristics:   pulumi.ToStringArray(r.CharacteristicList()),
			Period:            pulumi.Int(r.Period),
			RequestsPerPeriod: pulumi.Int(r.Requests),
			MitigationTimeout: pulumi.Int(r.MitigationTimeout),
		}
		if r.CountingExpression != "" {
			limit.CountingExpression = pulumi.String(r.CountingExpression)
		}

		out = append(out, cloudflare.RulesetRuleArgs{
			Action:      pulumi.String(r.Action),
			Description: pulumi.String(r.Name),
			Enabled:     pulumi.Bool(true),
			Expression:  pulumi.String(r.MatchExpression()),
			Ratelimit:   limit,
		})
	}

	return out
}
