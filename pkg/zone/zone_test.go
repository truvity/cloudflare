package zone

import (
	"sync"
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mocks records every registered resource so tests can assert on the exact
// child names, types and inputs — the names are a documented contract
// (consumers alias existing resources onto them).
type mocks struct {
	mu  sync.Mutex
	res map[string]resource.PropertyMap // "type/name" → inputs
}

func (m *mocks) NewResource(args pulumi.MockResourceArgs) (string, resource.PropertyMap, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.res[args.TypeToken+"/"+args.Name] = args.Inputs

	return args.Name + "-id", args.Inputs.Copy(), nil
}

func (m *mocks) Call(pulumi.MockCallArgs) (resource.PropertyMap, error) {
	return resource.PropertyMap{}, nil
}

func run(t *testing.T, args Args) *mocks {
	t.Helper()
	m := &mocks{res: map[string]resource.PropertyMap{}}
	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		_, err := New(ctx, "example", args)

		return err
	}, pulumi.WithMocks("proj", "stack", m))
	require.NoError(t, err)

	return m
}

const (
	settingType  = "cloudflare:index/zoneSetting:ZoneSetting"
	totalTLSType = "cloudflare:index/totalTls:TotalTls"
	rulesetType  = "cloudflare:index/ruleset:Ruleset"
)

// rules reads the cache ruleset's rules back as a slice of property maps,
// in the order they were registered — the order is part of what is being
// asserted.
func rules(t *testing.T, m *mocks) []resource.PropertyMap {
	t.Helper()
	got, ok := m.res[rulesetType+"/cache-rules-example"]
	require.True(t, ok, "the cache ruleset was not registered")

	var out []resource.PropertyMap
	for _, rule := range got["rules"].ArrayValue() {
		out = append(out, rule.ObjectValue())
	}

	return out
}

func TestChildNames(t *testing.T) {
	m := run(t, Args{
		ZoneID:        "zone-1",
		SSL:           "full",
		MinTLSVersion: "1.2",
		TotalTLS:      &TotalTLS{Enabled: true, CertificateAuthority: "google"},
		Cache:         &Cache{Hosts: []string{"app.example"}, RespectOriginBrowserTTL: true},
	})

	for _, want := range []string{
		settingType + "/setting-example-ssl",
		settingType + "/setting-example-min-tls-version",
		settingType + "/setting-example-browser-cache-ttl",
		totalTLSType + "/total-tls-example",
		rulesetType + "/cache-rules-example",
	} {
		assert.Contains(t, m.res, want, "child name is a contract consumers alias onto")
	}
}

func TestOnlyDeclaredSettingsAreManaged(t *testing.T) {
	m := run(t, Args{ZoneID: "zone-1", SSL: "strict"})

	assert.Contains(t, m.res, settingType+"/setting-example-ssl")
	assert.NotContains(t, m.res, settingType+"/setting-example-min-tls-version",
		"an unset field is a setting this estate does not manage")
	assert.NotContains(t, m.res, totalTLSType+"/total-tls-example")
	assert.NotContains(t, m.res, rulesetType+"/cache-rules-example",
		"a zone that declares no cache policy keeps the caching it has")
	assert.NotContains(t, m.res, settingType+"/setting-example-browser-cache-ttl")
}

func TestSettingInputs(t *testing.T) {
	m := run(t, Args{ZoneID: "zone-1", SSL: "full", MinTLSVersion: "1.3"})

	ssl := m.res[settingType+"/setting-example-ssl"]
	assert.Equal(t, "zone-1", ssl["zoneId"].StringValue())
	assert.Equal(t, "ssl", ssl["settingId"].StringValue())
	assert.Equal(t, "full", ssl["value"].StringValue())

	minTLS := m.res[settingType+"/setting-example-min-tls-version"]
	assert.Equal(t, "min_tls_version", minTLS["settingId"].StringValue())
	assert.Equal(t, "1.3", minTLS["value"].StringValue())
}

func TestTotalTLSInputs(t *testing.T) {
	m := run(t, Args{ZoneID: "zone-1", TotalTLS: &TotalTLS{Enabled: true, CertificateAuthority: "lets_encrypt"}})

	tls := m.res[totalTLSType+"/total-tls-example"]
	assert.Equal(t, "zone-1", tls["zoneId"].StringValue())
	assert.True(t, tls["enabled"].BoolValue())
	assert.Equal(t, "lets_encrypt", tls["certificateAuthority"].StringValue())
}

func TestTotalTLSDefaultsToCloudflaresAuthority(t *testing.T) {
	m := run(t, Args{ZoneID: "zone-1", TotalTLS: &TotalTLS{Enabled: true}})

	tls := m.res[totalTLSType+"/total-tls-example"]
	assert.False(t, tls.HasValue("certificateAuthority"),
		"an unset authority leaves Cloudflare's default rather than picking one")
}

func TestCacheRulesPartitionTheZone(t *testing.T) {
	m := run(t, Args{ZoneID: "zone-1", Cache: &Cache{Hosts: []string{"app.example", "docs.example"}}})

	set := m.res[rulesetType+"/cache-rules-example"]
	assert.Equal(t, "zone-1", set["zoneId"].StringValue())
	assert.Equal(t, "zone", set["kind"].StringValue())
	assert.Equal(t, "http_request_cache_settings", set["phase"].StringValue())

	got := rules(t, m)
	require.Len(t, got, 2)

	cacheable := `http.host in {"app.example" "docs.example"}`
	assert.Equal(t, cacheable, got[0]["expression"].StringValue())
	assert.Equal(t, "not ("+cacheable+")", got[1]["expression"].StringValue(),
		"the second expression is the negation of the first, so exactly one rule matches any request")
}

func TestCacheableHostLeavesTheTTLToTheOrigin(t *testing.T) {
	m := run(t, Args{ZoneID: "zone-1", Cache: &Cache{Hosts: []string{"app.example"}}})

	got := rules(t, m)
	require.Len(t, got, 2)

	assert.Equal(t, "set_cache_settings", got[0]["action"].StringValue())

	params := got[0]["actionParameters"].ObjectValue()
	assert.True(t, params["cache"].BoolValue())
	assert.Equal(t, "bypass_by_default", params["edgeTtl"].ObjectValue()["mode"].StringValue(),
		"the origin's Cache-Control decides, and a response without one is not cached")
	assert.Equal(t, "respect_origin", params["browserTtl"].ObjectValue()["mode"].StringValue())

	assert.False(t, got[1]["actionParameters"].ObjectValue()["cache"].BoolValue())
}

func TestCacheWildcardHost(t *testing.T) {
	m := run(t, Args{ZoneID: "zone-1", Cache: &Cache{Hosts: []string{"*.app.example", "docs.example"}}})

	got := rules(t, m)
	assert.Equal(t,
		`http.host in {"docs.example"} or ends_with(http.host, ".app.example")`,
		got[0]["expression"].StringValue(),
		"a set literal takes no wildcards, so a wildcard is a suffix test")
}

func TestCacheNoHostsCachesNothing(t *testing.T) {
	m := run(t, Args{ZoneID: "zone-1", Cache: &Cache{Hosts: nil}})

	got := rules(t, m)
	require.Len(t, got, 1, "with nothing cacheable the catch-all is the whole policy")
	assert.Equal(t, "true", got[0]["expression"].StringValue())
	assert.False(t, got[0]["actionParameters"].ObjectValue()["cache"].BoolValue())
}

func TestBrowserCacheTTLIsOptIn(t *testing.T) {
	m := run(t, Args{ZoneID: "zone-1", Cache: &Cache{Hosts: []string{"app.example"}}})
	assert.NotContains(t, m.res, settingType+"/setting-example-browser-cache-ttl",
		"the zone setting is a separate decision from the rules")

	m = run(t, Args{ZoneID: "zone-1", Cache: &Cache{Hosts: []string{"app.example"}, RespectOriginBrowserTTL: true}})
	ttl := m.res[settingType+"/setting-example-browser-cache-ttl"]
	assert.Equal(t, "browser_cache_ttl", ttl["settingId"].StringValue())
	assert.EqualValues(t, 0, ttl["value"].NumberValue(), "0 is Cloudflare's Respect Existing Headers")
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name string
		args Args
		want string
	}{
		{"no zone", Args{SSL: "full"}, "zoneId is required"},
		{"nothing to apply", Args{ZoneID: "z"}, "nothing to apply"},
		{"bad ssl", Args{ZoneID: "z", SSL: "sometimes"}, `ssl "sometimes" must be one of`},
		{"bad min tls", Args{ZoneID: "z", MinTLSVersion: "1.4"}, `minTlsVersion "1.4" must be one of`},
		{
			"bad authority",
			Args{ZoneID: "z", TotalTLS: &TotalTLS{Enabled: true, CertificateAuthority: "someone"}},
			`totalTls.certificateAuthority "someone" must be one of`,
		},
		{"ok", Args{ZoneID: "z", SSL: "strict"}, ""},
		{"empty host", Args{ZoneID: "z", Cache: &Cache{Hosts: []string{""}}}, "cache.hosts[0] is empty"},
		{
			"upper case host",
			Args{ZoneID: "z", Cache: &Cache{Hosts: []string{"App.example"}}},
			"must be lower case",
		},
		{
			"a URL, not a host",
			Args{ZoneID: "z", Cache: &Cache{Hosts: []string{"https://app.example/assets"}}},
			"must be a hostname, not a URL",
		},
		{
			"wildcard in the middle",
			Args{ZoneID: "z", Cache: &Cache{Hosts: []string{"app.*.example"}}},
			"a wildcard is one leading label",
		},
		{
			"bare wildcard",
			Args{ZoneID: "z", Cache: &Cache{Hosts: []string{"*."}}},
			"a wildcard is one leading label",
		},
		{
			"duplicate host",
			Args{ZoneID: "z", Cache: &Cache{Hosts: []string{"app.example", "app.example"}}},
			`"app.example" is listed twice`,
		},
		{"trusted clients ok", Args{ZoneID: "z", TrustedClients: validTrusted()}, ""},
		{"empty trusted clients manages nothing", Args{ZoneID: "z", TrustedClients: &TrustedClients{}}, "nothing to apply"},
		{"hosts without ranges", Args{ZoneID: "z", TrustedClients: &TrustedClients{Zone: "example.com", Hosts: []string{"a.example.com"}}}, "must both be non-empty"},
		{"no zone domain", Args{ZoneID: "z", TrustedClients: trusted(func(t *TrustedClients) { t.Zone = "" })}, "trustedClients.zone"},
		{"upper-case trusted host", Args{ZoneID: "z", TrustedClients: trusted(func(t *TrustedClients) { t.Hosts = []string{"A.example.com"} })}, "lower-case exact hostname"},
		{"wildcard trusted host", Args{ZoneID: "z", TrustedClients: trusted(func(t *TrustedClients) { t.Hosts = []string{"*.example.com"} })}, "lower-case exact hostname"},
		{"host outside zone", Args{ZoneID: "z", TrustedClients: trusted(func(t *TrustedClients) { t.Hosts = []string{"a.example.net"} })}, "inside example.com"},
		{"suffix lookalike", Args{ZoneID: "z", TrustedClients: trusted(func(t *TrustedClients) { t.Hosts = []string{"badexample.com"} })}, "inside example.com"},
		{"duplicate trusted host", Args{ZoneID: "z", TrustedClients: trusted(func(t *TrustedClients) { t.Hosts = []string{"a.example.com", "a.example.com"} })}, "listed twice"},
		{"not a CIDR", Args{ZoneID: "z", TrustedClients: trusted(func(t *TrustedClients) { t.Ranges = []string{"192.0.2.1"} })}, "CIDR block"},
		{"host bits set", Args{ZoneID: "z", TrustedClients: trusted(func(t *TrustedClients) { t.Ranges = []string{"192.0.2.1/24"} })}, "no host bits"},
		{"IPv4 too broad", Args{ZoneID: "z", TrustedClients: trusted(func(t *TrustedClients) { t.Ranges = []string{"0.0.0.0/7"} })}, "too broad"},
		{"IPv6 too broad", Args{ZoneID: "z", TrustedClients: trusted(func(t *TrustedClients) { t.Ranges = []string{"2000::/15"} })}, "too broad"},
		{"IPv4 /8 ok", Args{ZoneID: "z", TrustedClients: trusted(func(t *TrustedClients) { t.Ranges = []string{"10.0.0.0/8"} })}, ""},
		{"duplicate range", Args{ZoneID: "z", TrustedClients: trusted(func(t *TrustedClients) { t.Ranges = []string{"192.0.2.0/24", "192.0.2.0/24"} })}, "listed twice"},
		{"cache alone is enough to manage", Args{ZoneID: "z", Cache: &Cache{}}, ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.args.Validate()
			if c.want == "" {
				assert.NoError(t, err)

				return
			}

			require.Error(t, err)
			assert.Contains(t, err.Error(), c.want)
		})
	}
}

func validTrusted() *TrustedClients {
	return &TrustedClients{
		Zone:   "example.com",
		Hosts:  []string{"b.example.com", "a.example.com"},
		Ranges: []string{"198.51.100.0/24", "192.0.2.0/24", "2001:db8::/32"},
	}
}

func trusted(mutate func(*TrustedClients)) *TrustedClients {
	t := validTrusted()
	mutate(t)

	return t
}

const firewallName = rulesetType + "/firewall-custom-example"

func TestTrustedClientsIsOneSkipRule(t *testing.T) {
	m := run(t, Args{ZoneID: "zone-1", TrustedClients: validTrusted()})

	rs, ok := m.res[firewallName]
	require.True(t, ok, "the firewall ruleset was not registered")
	assert.Equal(t, "http_request_firewall_custom", rs["phase"].StringValue())
	assert.Equal(t, "zone", rs["kind"].StringValue())
	assert.Equal(t, "default", rs["name"].StringValue())

	rules := rs["rules"].ArrayValue()
	require.Len(t, rules, 1)

	rule := rules[0].ObjectValue()
	assert.Equal(t, "skip", rule["action"].StringValue())
	assert.Equal(t, "Trusted clients: skip security features", rule["description"].StringValue())
	assert.Equal(t,
		`(http.host in {"a.example.com" "b.example.com"}) and (ip.src in {192.0.2.0/24 198.51.100.0/24 2001:db8::/32})`,
		rule["expression"].StringValue())
	assert.True(t, rule["logging"].ObjectValue()["enabled"].BoolValue())

	params := rule["actionParameters"].ObjectValue()
	assert.Equal(t, "current", params["ruleset"].StringValue())

	var phases, products []string
	for _, v := range params["phases"].ArrayValue() {
		phases = append(phases, v.StringValue())
	}

	for _, v := range params["products"].ArrayValue() {
		products = append(products, v.StringValue())
	}

	assert.Equal(t, []string{"http_ratelimit", "http_request_firewall_managed", "http_request_sbfm"}, phases)
	assert.Equal(t, []string{"bic", "hot", "rateLimit", "securityLevel", "uaBlock", "waf", "zoneLockdown"}, products)
}

func TestTrustedClientsDescription(t *testing.T) {
	m := run(t, Args{ZoneID: "z", TrustedClients: trusted(func(c *TrustedClients) { c.Description = "Connector egress" })})
	rule := m.res[firewallName]["rules"].ArrayValue()[0].ObjectValue()
	assert.Equal(t, "Connector egress", rule["description"].StringValue())
}

func TestEmptyTrustedClientsRendersNoRuleset(t *testing.T) {
	m := run(t, Args{ZoneID: "z", SSL: "full", TrustedClients: &TrustedClients{}})
	assert.NotContains(t, m.res, firewallName)

	m = run(t, Args{ZoneID: "z", SSL: "full"})
	assert.NotContains(t, m.res, firewallName)
}

func TestTrustedClientsAndCacheUseSeparatePhases(t *testing.T) {
	m := run(t, Args{ZoneID: "z", Cache: &Cache{Hosts: []string{"app.example.com"}}, TrustedClients: validTrusted()})
	assert.Equal(t, "http_request_cache_settings", m.res[rulesetType+"/cache-rules-example"]["phase"].StringValue())
	assert.Equal(t, "http_request_firewall_custom", m.res[firewallName]["phase"].StringValue())
}
