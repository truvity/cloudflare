package zone

import (
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ptr[T any](v T) *T { return &v }

func TestAlwaysUseHTTPS(t *testing.T) {
	for _, c := range []struct {
		on   bool
		want string
	}{{true, "on"}, {false, "off"}} {
		m := run(t, Args{ZoneID: "zone-1", AlwaysUseHTTPS: ptr(c.on)})

		got := m.res[settingType+"/setting-example-always-use-https"]
		require.NotNil(t, got, "child name is a contract consumers alias onto")
		assert.Equal(t, "zone-1", got["zoneId"].StringValue())
		assert.Equal(t, "always_use_https", got["settingId"].StringValue())
		assert.Equal(t, c.want, got["value"].StringValue())
	}
}

func TestUnsetHardeningIsUnmanaged(t *testing.T) {
	m := run(t, Args{ZoneID: "zone-1", SSL: "strict"})

	assert.NotContains(t, m.res, settingType+"/setting-example-always-use-https")
	assert.NotContains(t, m.res, settingType+"/setting-example-security-header")
	assert.NotContains(t, m.res, rulesetType+"/firewall-managed-example",
		"a zone that declares no managed WAF keeps its managed phase as it is")
}

func TestHSTSValueUsesTheAPIsKeys(t *testing.T) {
	m := run(t, Args{ZoneID: "zone-1", AlwaysUseHTTPS: ptr(true), HSTS: &HSTS{Enabled: true, MaxAge: 300, IncludeSubdomains: true}})

	got := m.res[settingType+"/setting-example-security-header"]
	require.NotNil(t, got, "child name is a contract consumers alias onto")
	assert.Equal(t, "security_header", got["settingId"].StringValue())

	// snake_case, not the provider docs' camelCase (pulumi-cloudflare#1579).
	sts := got["value"].ObjectValue()["strict_transport_security"].ObjectValue()
	assert.Equal(t, resource.PropertyMap{
		"enabled":            resource.NewBoolProperty(true),
		"max_age":            resource.NewNumberProperty(300),
		"include_subdomains": resource.NewBoolProperty(true),
		"nosniff":            resource.NewBoolProperty(false),
		"preload":            resource.NewBoolProperty(false),
	}, sts)
}

func TestManagedWAFIsOneExecuteRule(t *testing.T) {
	m := run(t, Args{ZoneID: "zone-1", ManagedWAF: &ManagedWAF{
		Zone:  "example.com",
		Hosts: []string{"*.dev.example.com", "b.example.com", "a.example.com"},
	}})

	set := m.res[rulesetType+"/firewall-managed-example"]
	require.NotNil(t, set, "child name is a contract consumers alias onto")
	assert.Equal(t, "zone-1", set["zoneId"].StringValue())
	assert.Equal(t, "zone", set["kind"].StringValue())
	assert.Equal(t, "http_request_firewall_managed", set["phase"].StringValue())
	assert.Equal(t, "default", set["name"].StringValue())

	rules := set["rules"].ArrayValue()
	require.Len(t, rules, 1)

	rule := rules[0].ObjectValue()
	assert.Equal(t, "execute", rule["action"].StringValue())
	assert.True(t, rule["enabled"].BoolValue())
	assert.Equal(t, "Cloudflare Managed Ruleset", rule["description"].StringValue())
	assert.Equal(t, "efb7b8c949ac4650a09736fc376e9aee", rule["actionParameters"].ObjectValue()["id"].StringValue())
	assert.Equal(t, `http.host in {"a.example.com" "b.example.com"} or ends_with(http.host, ".dev.example.com")`,
		rule["expression"].StringValue(), "hosts are sorted: authoring order never changes the plan")
	assert.False(t, rule["actionParameters"].ObjectValue().HasValue("overrides"),
		"the ruleset's own default actions apply")
}

func TestManagedWAFWholeZone(t *testing.T) {
	m := run(t, Args{ZoneID: "zone-1", ManagedWAF: &ManagedWAF{WholeZone: true, Description: "Managed rules"}})

	rule := m.res[rulesetType+"/firewall-managed-example"]["rules"].ArrayValue()[0].ObjectValue()
	assert.Equal(t, "true", rule["expression"].StringValue())
	assert.Equal(t, "Managed rules", rule["description"].StringValue())
}

func TestHardeningValidation(t *testing.T) {
	cases := []struct {
		name string
		args Args
		want string
	}{
		{"https alone applies", Args{ZoneID: "z", AlwaysUseHTTPS: ptr(true)}, ""},
		{"https off is a decision", Args{ZoneID: "z", AlwaysUseHTTPS: ptr(false)}, ""},
		{"hsts alone applies", Args{ZoneID: "z", HSTS: &HSTS{}}, ""},
		{"hsts forget header", Args{ZoneID: "z", HSTS: &HSTS{Enabled: true}}, ""},
		{"hsts negative", Args{ZoneID: "z", HSTS: &HSTS{Enabled: true, MaxAge: -1}}, "hsts.maxAge"},
		{"hsts too long", Args{ZoneID: "z", HSTS: &HSTS{Enabled: true, MaxAge: 31536001}}, "hsts.maxAge"},
		{"hsts year", Args{ZoneID: "z", HSTS: &HSTS{Enabled: true, MaxAge: 31536000}}, ""},
		{
			"preload ok", Args{
				ZoneID: "z", AlwaysUseHTTPS: ptr(true),
				HSTS: &HSTS{Enabled: true, MaxAge: 31536000, IncludeSubdomains: true, Preload: true},
			}, "",
		},
		{
			"preload short", Args{
				ZoneID: "z", AlwaysUseHTTPS: ptr(true),
				HSTS: &HSTS{Enabled: true, MaxAge: 15552000, IncludeSubdomains: true, Preload: true},
			}, "hsts.preload",
		},
		{
			"preload no subdomains", Args{
				ZoneID: "z", AlwaysUseHTTPS: ptr(true),
				HSTS: &HSTS{Enabled: true, MaxAge: 31536000, Preload: true},
			}, "hsts.preload",
		},
		{
			"preload without https", Args{
				ZoneID: "z",
				HSTS:   &HSTS{Enabled: true, MaxAge: 31536000, IncludeSubdomains: true, Preload: true},
			}, "hsts.preload",
		},
		{"waf empty", Args{ZoneID: "z", ManagedWAF: &ManagedWAF{Zone: "example.com"}}, "empty host list"},
		{"waf whole zone", Args{ZoneID: "z", ManagedWAF: &ManagedWAF{WholeZone: true}}, ""},
		{
			"waf both", Args{ZoneID: "z", ManagedWAF: &ManagedWAF{WholeZone: true, Zone: "example.com", Hosts: []string{"a.example.com"}}},
			"exclusive",
		},
		{"waf no zone", Args{ZoneID: "z", ManagedWAF: &ManagedWAF{Hosts: []string{"a.example.com"}}}, "managedWaf.zone"},
		{"waf outside", Args{ZoneID: "z", ManagedWAF: &ManagedWAF{Zone: "example.com", Hosts: []string{"a.example.org"}}}, "inside example.com"},
		{"waf suffix trick", Args{ZoneID: "z", ManagedWAF: &ManagedWAF{Zone: "example.com", Hosts: []string{"badexample.com"}}}, "inside example.com"},
		{"waf upper", Args{ZoneID: "z", ManagedWAF: &ManagedWAF{Zone: "example.com", Hosts: []string{"A.example.com"}}}, "lower-case"},
		{"waf url", Args{ZoneID: "z", ManagedWAF: &ManagedWAF{Zone: "example.com", Hosts: []string{"https://a.example.com"}}}, "lower-case"},
		{"waf inner star", Args{ZoneID: "z", ManagedWAF: &ManagedWAF{Zone: "example.com", Hosts: []string{"a.*.example.com"}}}, "lower-case"},
		{"waf dup", Args{ZoneID: "z", ManagedWAF: &ManagedWAF{Zone: "example.com", Hosts: []string{"a.example.com", "a.example.com"}}}, "twice"},
		{"waf apex and wildcard", Args{ZoneID: "z", ManagedWAF: &ManagedWAF{Zone: "example.com", Hosts: []string{"example.com", "*.example.com"}}}, ""},
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
