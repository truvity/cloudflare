package zonestack_test

import (
	"fmt"
	"log/slog"
	"os"
	"sort"
	"testing"

	cf "github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/edge/v3/catalog"
	"github.com/truvity/edge/v3/cloudflare/account"
	"github.com/truvity/edge/v3/cloudflare/config"
	"github.com/truvity/edge/v3/cloudflare/edge"
	"github.com/truvity/edge/v3/cloudflare/internal/stacktest"
	"github.com/truvity/edge/v3/cloudflare/rules"
	"github.com/truvity/edge/v3/cloudflare/services"
	"github.com/truvity/edge/v3/cloudflare/tunnel"
	"github.com/truvity/edge/v3/cloudflare/zone"
	"github.com/truvity/edge/v3/cloudflare/zonestack"
)

// The split of one stack into a zone stack and a services stack is
// zero-replace only if the two register what the one registered: the same
// type, logical name, parent, provider and inputs for every resource. This
// file proves it on the config fixture. The "before" is cloudflare/edge.Deploy
// plus the glue an estate wrote around it (legacyProgram below, which
// reproduces that glue: the zone mapping by blocks, the origin-pull and
// SSL-mode resources under their own provider, the public-documents cache
// rule appended to the library's cache ruleset, the origin CNAME rewrite);
// the "after" is zonestack.Deploy and services.Deploy once per company.

var fixtureProjects = []catalog.Project{{Name: "dms"}, {Name: "eudi"}, {Name: "url-shortener"}, {Name: "landing"}}

func fixture(t *testing.T) *config.Config {
	t.Helper()

	cat, err := catalog.Load(os.DirFS("../config/testdata"))
	require.NoError(t, err)

	cfg, err := config.Load(os.DirFS("../config/testdata"), cat, fixtureProjects)
	require.NoError(t, err)

	return cfg
}

func tokens(cfg *config.Config) map[string]string {
	out := map[string]string{}
	for name := range cfg.Accounts {
		out[name] = "token-" + name
	}

	return out
}

func nopSink(*pulumi.Context, services.Tunnel, pulumi.StringOutput) error { return nil }

func TestSplitStacksRegisterWhatTheSingleStackRegisters(t *testing.T) {
	assertSplitEquivalent(t, fixture(t))
}

// A configuration rule whose ref nobody pinned: Cloudflare assigns the ref,
// so the split registers none, as the single stack does.
func TestSplitStacksEquivalentWithAnUnpinnedSSLModeRef(t *testing.T) {
	cfg := fixture(t)
	z := cfg.Zones["example.com"]
	z.SSLModeRuleRefs = nil
	z.SSLModeRules = map[string]string{"access.example.com": "strict", "gemaal.example.com": "full"}
	cfg.Zones["example.com"] = z

	assertSplitEquivalent(t, cfg)
}

func assertSplitEquivalent(t *testing.T, cfg *config.Config) {
	t.Helper()

	before, err := stacktest.Run(legacyProgram(cfg, tokens(cfg)))
	require.NoError(t, err)

	want := before.ByKey()

	got := map[string]stacktest.Resource{}

	companies := []string{"example", "partner-co"}
	for _, company := range companies {
		for name, program := range map[string]func(*pulumi.Context) error{
			"zonestack": func(ctx *pulumi.Context) error {
				return zonestack.Deploy(ctx, zonestack.Args{Config: cfg, Company: company, Tokens: tokens(cfg)})
			},
			"services": func(ctx *pulumi.Context) error {
				return services.Deploy(ctx, services.Args{
					Config: cfg, Company: company, Tokens: tokens(cfg), Sink: nopSink,
					Clusters: []services.Cluster{{Name: "kernel", DNSDomain: "cluster.kernel"}},
				})
			},
		} {
			after, err := stacktest.Run(program)
			require.NoError(t, err, "%s %s", name, company)

			for key, res := range after.ByKey() {
				// Only a provider is in two stacks: the zone stack and the
				// services stack each hold their own provider-<account>.
				if prev, dup := got[key]; dup {
					assert.Equal(t, "pulumi:providers:cloudflare", res.Type, "%s is registered by two of the split stacks", key)
					assert.Equal(t, prev, res, "the two stacks' %s", key)
				}

				got[key] = res
			}
		}
	}

	// Two top-level resources of the single stack become children of the
	// zone component, and move there by an alias (zone Compat.TopLevelAliases):
	// the name, the type and the inputs stay.
	for _, name := range []string{"tls-client-auth-example-com", "ssl-mode-example-com"} {
		for _, typ := range []string{"cloudflare:index/zoneSetting:ZoneSetting", "cloudflare:index/ruleset:Ruleset"} {
			key := typ + "::" + name

			w, ok := want[key]
			if !ok {
				continue
			}

			assert.Empty(t, w.Parent, "%s is top-level in the single stack", key)
			assert.Equal(t, "truvity:cloudflare:Zone::example-com", got[key].Parent, key)

			w.Parent = got[key].Parent
			want[key] = w
		}
	}

	assert.Equal(t, keys(want), keys(got), "the split registers the same resources")

	for _, key := range keys(want) {
		assert.Equal(t, want[key], got[key], key)
	}

	// The fixture reaches the corners the split could lose.
	assert.Contains(t, want, "cloudflare:index/zoneSetting:ZoneSetting::tls-client-auth-example-com")
	assert.Contains(t, want, "cloudflare:index/ruleset:Ruleset::cache-rules-example-com")
	assert.Contains(t, want, "cloudflare:index/dnsRecord:DnsRecord::record-example-org-docs-example-org-cname")
	assert.Contains(t, want, "pulumi:providers:cloudflare::provider-aop-provider-example-com")

	for i := range cfg.Tunnels {
		tun := &cfg.Tunnels[i]

		assert.Contains(t, want, "random:index/randomBytes:RandomBytes::tunnel-secret-"+tun.Name())
		assert.Contains(t, want, "truvity:cloudflare:Tunnel::"+tun.Name())
	}

	assert.NotContains(t, want, "cloudflare:index/dnsRecord:DnsRecord::cname-devel-old-devel-example-com",
		"a dns_elsewhere name has an ingress rule and no CNAME")

	assert.Contains(t, fmt.Sprint(want["cloudflare:index/zeroTrustTunnelCloudflaredConfig:ZeroTrustTunnelCloudflaredConfig::ingress-devel"].Inputs),
		"old.devel.example.com")

	origin := want["cloudflare:index/dnsRecord:DnsRecord::cname-kernel-access-example-com"]
	assert.Equal(t, "d-abcdef1234.execute-api.eu-central-1.amazonaws.com", origin.Inputs["content"], "origin_cnames rewrites the CNAME in place")

	t.Logf("single stack: %d resources, split stacks (union): %d", len(want), len(got))
	assert.Greater(t, len(want), 60, "the fixture exercises the whole model")
}

func keys(m map[string]stacktest.Resource) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}

	sort.Strings(out)

	return out
}

// legacyProgram is the single stack: cloudflare/edge.Deploy over the whole
// registry plus the estate glue around it.
func legacyProgram(cfg *config.Config, toks map[string]string) func(*pulumi.Context) error {
	return func(ctx *pulumi.Context) error {
		cacheRules := map[string]rules.CacheRule{}

		for name := range cfg.Zones {
			if p := cfg.Zones[name].PublicCache; p != nil {
				rule, err := rules.PublicPathsCache(p.Host, rules.PublicPathsArgs{TTL: p.EdgeTTL()})
				if err != nil {
					return err
				}

				cacheRules[tunnel.Slug(name)] = rule
			}
		}

		var accounts []edge.Account
		for name, a := range cfg.Accounts {
			accounts = append(accounts, edge.Account{Name: name, AccountID: a.AccountID, Token: toks[name]})
		}

		var zones []edge.Zone
		for name := range cfg.Zones {
			z := cfg.Zones[name]
			zones = append(zones, edge.Zone{Name: name, Account: z.Account, Args: legacyZoneArgs(name, z)})
		}

		var tunnels []edge.Tunnel
		for i := range cfg.Tunnels {
			t := &cfg.Tunnels[i]
			dom := ""
			if t.Cluster == "kernel" {
				dom = "cluster.kernel"
			}

			tunnels = append(tunnels, edge.Tunnel{
				Name: t.Name(), Cluster: t.Cluster, Account: t.Account, Zone: t.Zone, Zones: t.Zones, Hosts: t.Hosts,
				DNSElsewhere: t.DNSElsewhere, DNSDomain: dom,
			})
		}

		err := edge.Deploy(ctx, edge.Args{
			Accounts: accounts, Zones: zones, Tunnels: tunnels,
			Origin: edge.Origin{Service: cfg.Fleets.Internal.Service, Namespace: cfg.Fleets.Internal.Namespace},
			Sink:   func(*pulumi.Context, edge.Tunnel, pulumi.StringOutput) error { return nil },
			ZoneOptions: func(z edge.Zone) []pulumi.ResourceOption {
				slug := tunnel.Slug(z.Name)
				if rule, ok := cacheRules[slug]; ok {
					return []pulumi.ResourceOption{pulumi.Transformations([]pulumi.ResourceTransformation{legacyPublicCache(slug, rule)})}
				}

				return nil
			},
			TunnelOptions: func(t edge.Tunnel) []pulumi.ResourceOption {
				origins := map[string]string{}

				for _, host := range t.Hosts {
					if o, ok := cfg.Zones[cfg.ZoneOf(host)].ActiveOrigins()[host]; ok {
						origins[host] = o
					}
				}

				return []pulumi.ResourceOption{pulumi.Transformations([]pulumi.ResourceTransformation{legacyOriginCNAMEs(t.Name, origins)})}
			},
			Logger: slog.New(slog.DiscardHandler),
		})
		if err != nil {
			return err
		}

		return legacyZoneEdge(ctx, cfg, toks)
	}
}

// legacyZoneArgs is the estate's mapping of a registry zone onto the zone
// component: the firewall, rate limit and managed WAF blocks as blocks.
func legacyZoneArgs(name string, z config.Zone) zone.Args {
	out := zone.Args{ZoneID: z.ZoneID, SSL: z.SSLMode, MinTLSVersion: z.MinTLSVersion}
	if z.TotalTLS != nil {
		out.TotalTLS = &zone.TotalTLS{Enabled: z.TotalTLS.Enabled, CertificateAuthority: z.TotalTLS.CertificateAuthority}
	}

	if z.Cache != nil {
		out.Cache = &zone.Cache{Hosts: z.CacheHosts, RespectOriginBrowserTTL: z.Cache.RespectOriginBrowserTTL}
	}

	if z.TrustedClients != nil {
		out.TrustedClients = &zone.TrustedClients{
			Zone: name, Hosts: z.TrustedClients.Hosts, Ranges: z.TrustedClients.Ranges,
			Description: "Trusted clients: skip security features",
		}
	}

	out.RateLimits = z.RateLimits.Library()
	out.Records = z.RecordsLibrary(name)
	out.AlwaysUseHTTPS = z.AlwaysUseHTTPS
	out.HSTS = z.HSTS.Library()
	out.ManagedWAF = z.ManagedWAF.Library(name)

	return out
}

// legacyZoneEdge is the estate's origin-pull setting and SSL-mode ruleset,
// each zone's own provider "aop-provider-<slug>" and top-level resources.
func legacyZoneEdge(ctx *pulumi.Context, cfg *config.Config, toks map[string]string) error {
	for name := range cfg.Zones {
		z := cfg.Zones[name]
		origins := len(z.ActiveOrigins()) > 0
		if !origins && len(z.SSLModeRules) == 0 {
			continue
		}

		slug := tunnel.Slug(name)

		acct, err := account.New(ctx, "aop-provider-"+slug,
			account.Args{AccountID: cfg.Accounts[z.Account].AccountID}, pulumi.String(toks[z.Account]))
		if err != nil {
			return err
		}

		if origins {
			if _, err := cf.NewZoneSetting(ctx, "tls-client-auth-"+slug, &cf.ZoneSettingArgs{
				ZoneId: pulumi.String(z.ZoneID), SettingId: pulumi.String("tls_client_auth"), Value: pulumi.String("on"),
			}, acct.Use()); err != nil {
				return err
			}
		}

		if len(z.SSLModeRules) == 0 {
			continue
		}

		ruleList := cf.RulesetRuleArray{}

		hosts := make([]string, 0, len(z.SSLModeRules))
		for h := range z.SSLModeRules {
			hosts = append(hosts, h)
		}

		sort.Strings(hosts)

		for _, host := range hosts {
			mode := z.SSLModeRules[host]
			rule := &cf.RulesetRuleArgs{
				Action:           pulumi.String("set_config"),
				Expression:       pulumi.String(fmt.Sprintf("(http.host eq %q)", host)),
				Description:      pulumi.String(fmt.Sprintf("%s SSL %s", host, mode)),
				Enabled:          pulumi.Bool(true),
				ActionParameters: &cf.RulesetRuleActionParametersArgs{Ssl: pulumi.String(mode)},
			}
			if ref := z.SSLModeRuleRefs[host]; ref != "" {
				rule.Ref = pulumi.String(ref)
			}

			ruleList = append(ruleList, rule)
		}

		opts := []pulumi.ResourceOption{acct.Use()}
		if z.ConfigRulesImportID != "" {
			opts = append(opts, pulumi.Import(pulumi.ID("zones/"+z.ZoneID+"/"+z.ConfigRulesImportID)))
		}

		if _, err := cf.NewRuleset(ctx, "ssl-mode-"+slug, &cf.RulesetArgs{
			ZoneId: pulumi.String(z.ZoneID), Name: pulumi.String("default"), Kind: pulumi.String("zone"),
			Phase: pulumi.String("http_config_settings"), Rules: ruleList,
		}, opts...); err != nil {
			return err
		}
	}

	return nil
}

// legacyPublicCache appends the public-documents rule to the library's cache
// ruleset and narrows that ruleset's bypass, as the estate's transformation
// does.
func legacyPublicCache(slug string, rule rules.CacheRule) pulumi.ResourceTransformation {
	return func(ta *pulumi.ResourceTransformationArgs) *pulumi.ResourceTransformationResult {
		if ta.Type != "cloudflare:index/ruleset:Ruleset" || ta.Name != "cache-rules-"+slug {
			return nil
		}

		args, ok := ta.Props.(*cf.RulesetArgs)
		if !ok {
			return nil
		}

		existing, ok := args.Rules.(cf.RulesetRuleArray)
		if !ok {
			return nil
		}

		out := make(cf.RulesetRuleArray, 0, len(existing)+1)

		for _, r := range existing {
			out = append(out, legacyNarrow(r, rule.Expression))
		}

		out = append(out, &cf.RulesetRuleArgs{
			Action:      pulumi.String("set_cache_settings"),
			Expression:  pulumi.String(rule.Expression),
			Description: pulumi.String(rule.Description),
			Enabled:     pulumi.Bool(true),
			ActionParameters: &cf.RulesetRuleActionParametersArgs{
				Cache: pulumi.Bool(true),
				EdgeTtl: &cf.RulesetRuleActionParametersEdgeTtlArgs{
					Mode: pulumi.String("override_origin"), Default: pulumi.Int(rule.EdgeTTLSeconds),
				},
				BrowserTtl: &cf.RulesetRuleActionParametersBrowserTtlArgs{Mode: pulumi.String("respect_origin")},
			},
		})

		next := *args
		next.Rules = out

		return &pulumi.ResourceTransformationResult{Props: &next, Opts: ta.Opts}
	}
}

func legacyNarrow(r cf.RulesetRuleInput, expr string) cf.RulesetRuleInput {
	var args cf.RulesetRuleArgs

	switch v := r.(type) {
	case cf.RulesetRuleArgs:
		args = v
	case *cf.RulesetRuleArgs:
		args = *v
	default:
		return r
	}

	if d, ok := args.Description.(pulumi.String); !ok || string(d) != "Not a cacheable hostname" {
		return r
	}

	old, ok := args.Expression.(pulumi.String)
	if !ok {
		return r
	}

	args.Expression = pulumi.String(fmt.Sprintf("(%s) and not %s", string(old), expr))

	return args
}

func legacyOriginCNAMEs(tunnelName string, origins map[string]string) pulumi.ResourceTransformation {
	byRecord := map[string]string{}
	for host, origin := range origins {
		byRecord["cname-"+tunnelName+"-"+tunnel.Slug(host)] = origin
	}

	return func(ta *pulumi.ResourceTransformationArgs) *pulumi.ResourceTransformationResult {
		origin, ok := byRecord[ta.Name]
		if !ok || ta.Type != "cloudflare:index/dnsRecord:DnsRecord" {
			return nil
		}

		args, ok := ta.Props.(*cf.DnsRecordArgs)
		if !ok {
			return nil
		}

		args.Content = pulumi.String(origin)

		return &pulumi.ResourceTransformationResult{Props: args, Opts: ta.Opts}
	}
}
