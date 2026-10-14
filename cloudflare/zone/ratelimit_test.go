package zone

import (
	"strings"
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const rateLimitName = rulesetType + "/ratelimit-example"

func ingestRule() RateLimitRule {
	return RateLimitRule{
		Name: "ingest",
		Endpoints: []Endpoint{
			{Host: "app.example.com", Path: "/collect"},
			{Host: "alerts.example.com", Path: "/"},
			{Host: "otlp.example.com", PathPrefix: "/v1/"},
		},
		Period:            10,
		Requests:          20,
		MitigationTimeout: 10,
		Action:            "block",
	}
}

func proLimits(rules ...RateLimitRule) *RateLimits {
	return &RateLimits{Plan: PlanPro, Rules: rules}
}

func rateLimitRulesOf(t *testing.T, m *mocks) []resource.PropertyMap {
	t.Helper()
	set, ok := m.res[rateLimitName]
	require.True(t, ok, "the rate limit ruleset was not registered")

	var out []resource.PropertyMap
	for _, rule := range set["rules"].ArrayValue() {
		out = append(out, rule.ObjectValue())
	}

	return out
}

func TestRateLimitsAreOneEntryPointRuleset(t *testing.T) {
	m := run(t, Args{ZoneID: "zone-1", RateLimits: proLimits(ingestRule())})

	set := m.res[rateLimitName]
	assert.Equal(t, "zone-1", set["zoneId"].StringValue())
	assert.Equal(t, "zone", set["kind"].StringValue())
	assert.Equal(t, "http_ratelimit", set["phase"].StringValue())
	assert.Equal(t, "default", set["name"].StringValue())

	got := rateLimitRulesOf(t, m)
	require.Len(t, got, 1)
	assert.Equal(t, "block", got[0]["action"].StringValue())
	assert.Equal(t, "ingest", got[0]["description"].StringValue())
	assert.True(t, got[0]["enabled"].BoolValue())
	assert.Equal(t,
		`(http.host eq "app.example.com" and http.request.uri.path eq "/collect") or `+
			`(http.host eq "alerts.example.com" and http.request.uri.path eq "/") or `+
			`(http.host eq "otlp.example.com" and starts_with(http.request.uri.path, "/v1/"))`,
		got[0]["expression"].StringValue(),
		"endpoints are ORed into one expression, in declared order")

	rl := got[0]["ratelimit"].ObjectValue()
	var chars []string
	for _, c := range rl["characteristics"].ArrayValue() {
		chars = append(chars, c.StringValue())
	}

	assert.Equal(t, []string{"cf.colo.id", "ip.src"}, chars, "the data center id is always added, the address is the default key")
	assert.EqualValues(t, 10, rl["period"].NumberValue())
	assert.EqualValues(t, 20, rl["requestsPerPeriod"].NumberValue())
	assert.EqualValues(t, 10, rl["mitigationTimeout"].NumberValue())
	assert.False(t, rl.HasValue("countingExpression"), "unset: the counter counts what the rule matches")
}

func TestRateLimitsLeaveThePhaseAloneWhenNil(t *testing.T) {
	m := run(t, Args{ZoneID: "zone-1", SSL: "full"})
	assert.NotContains(t, m.res, rateLimitName)
}

func TestEmptyRateLimitsApplyAnEmptyRuleset(t *testing.T) {
	m := run(t, Args{ZoneID: "zone-1", RateLimits: proLimits()})
	assert.Empty(t, rateLimitRulesOf(t, m), "a declared block with no rules clears the phase")
}

func TestRateLimitsComposeWithOtherPhases(t *testing.T) {
	m := run(t, Args{
		ZoneID:         "zone-1",
		Cache:          &Cache{Hosts: []string{"app.example.com"}},
		TrustedClients: validTrusted(),
		RateLimits:     proLimits(ingestRule()),
	})

	for _, want := range []string{"cache-rules-example", "firewall-custom-example", "ratelimit-example"} {
		assert.Contains(t, m.res, rulesetType+"/"+want)
	}
}

func TestEndpointMethodsOnBusiness(t *testing.T) {
	r := ingestRule()
	r.Endpoints = []Endpoint{{Host: "app.example.com", Path: "/collect", Methods: []string{"POST", "PUT"}}}
	m := run(t, Args{ZoneID: "zone-1", RateLimits: &RateLimits{Plan: PlanBusiness, Rules: []RateLimitRule{r}}})

	assert.Equal(t,
		`(http.host eq "app.example.com" and http.request.uri.path eq "/collect" and http.request.method in {"POST" "PUT"})`,
		rateLimitRulesOf(t, m)[0]["expression"].StringValue())
}

func TestChallengeThrottlesWithZeroTimeout(t *testing.T) {
	r := ingestRule()
	r.Action = "managed_challenge"
	r.MitigationTimeout = 0
	m := run(t, Args{ZoneID: "zone-1", RateLimits: proLimits(r)})

	got := rateLimitRulesOf(t, m)[0]
	assert.Equal(t, "managed_challenge", got["action"].StringValue())
	assert.EqualValues(t, 0, got["ratelimit"].ObjectValue()["mitigationTimeout"].NumberValue())
}

func TestRawExpressionIsPassedThrough(t *testing.T) {
	r := ingestRule()
	r.Endpoints = nil
	r.Expression = `starts_with(http.request.uri.path, "/api/")`
	m := run(t, Args{ZoneID: "zone-1", RateLimits: proLimits(r)})

	assert.Equal(t, r.Expression, rateLimitRulesOf(t, m)[0]["expression"].StringValue())
}

func TestRateLimitsValidate(t *testing.T) {
	with := func(f func(r *RateLimitRule)) Args {
		r := ingestRule()
		f(&r)

		return Args{ZoneID: "z", RateLimits: proLimits(r)}
	}

	cases := []struct {
		name string
		args Args
		want string
	}{
		{"ok", Args{ZoneID: "z", RateLimits: proLimits(ingestRule())}, ""},
		{"empty block is a policy", Args{ZoneID: "z", RateLimits: proLimits()}, ""},
		{"plan required", Args{ZoneID: "z", RateLimits: &RateLimits{}}, `rateLimits.plan "" must be one of`},
		{"unknown plan", Args{ZoneID: "z", RateLimits: &RateLimits{Plan: "gold"}}, `plan "gold" must be one of`},
		{"too many rules on pro", Args{ZoneID: "z", RateLimits: proLimits(
			ingestRule(), func() RateLimitRule { r := ingestRule(); r.Name = "b"; return r }(),
			func() RateLimitRule { r := ingestRule(); r.Name = "c"; return r }())},
			"3 rules but the pro plan allows 2"},
		{"duplicate rule name", Args{ZoneID: "z", RateLimits: proLimits(ingestRule(), ingestRule())}, `name "ingest" is used twice`},
		{"no name", with(func(r *RateLimitRule) { r.Name = "" }), "name is required"},
		{"no match", with(func(r *RateLimitRule) { r.Endpoints = nil }), "endpoints or expression is required"},
		{"both matches", with(func(r *RateLimitRule) { r.Expression = "true" }), "alternatives"},
		{"method in raw expression on pro", with(func(r *RateLimitRule) {
			r.Endpoints = nil
			r.Expression = `http.request.method eq "POST"`
		}), "no request method field"},
		{"counting expression on pro", with(func(r *RateLimitRule) { r.CountingExpression = "true" }), "needs the business plan"},
		{"methods on pro", with(func(r *RateLimitRule) { r.Endpoints[0].Methods = []string{"POST"} }), "methods needs the business plan"},
		{
			"bad characteristic on pro",
			with(func(r *RateLimitRule) { r.Characteristics = []string{"http.host"} }),
			`characteristic "http.host" is not available on the pro plan`,
		},
		{"colo id is tolerated", with(func(r *RateLimitRule) { r.Characteristics = []string{"cf.colo.id", "ip.src"} }), ""},
		{"period 30 on pro", with(func(r *RateLimitRule) { r.Period = 30 }), "period 30 is not available on the pro plan"},
		{"period 120 on pro", with(func(r *RateLimitRule) { r.Period = 120 }), "period 120 is not available"},
		{"no requests", with(func(r *RateLimitRule) { r.Requests = 0 }), "requests must be at least 1"},
		{"unknown action", with(func(r *RateLimitRule) { r.Action = "allow" }), `action "allow" must be one of`},
		{"log is enterprise", with(func(r *RateLimitRule) { r.Action = "log" }), "Enterprise-only"},
		{"block timeout 0", with(func(r *RateLimitRule) { r.MitigationTimeout = 0 }), "mitigationTimeout 0 is not available"},
		{"block timeout a day on pro", with(func(r *RateLimitRule) { r.MitigationTimeout = 86400 }), "mitigationTimeout 86400 is not available on the pro plan"},
		{"challenge with timeout", with(func(r *RateLimitRule) { r.Action = "js_challenge" }), "must be 0 or omitted"},
		{"upper-case host", with(func(r *RateLimitRule) { r.Endpoints[0].Host = "App.example.com" }), "exact lower-case hostname"},
		{"wildcard host", with(func(r *RateLimitRule) { r.Endpoints[0].Host = "*.example.com" }), "exact lower-case hostname"},
		{"quote in host", with(func(r *RateLimitRule) { r.Endpoints[0].Host = `a".example.com` }), "exact lower-case hostname"},
		{"no host", with(func(r *RateLimitRule) { r.Endpoints[0].Host = "" }), "is empty"},
		{"path and prefix", with(func(r *RateLimitRule) { r.Endpoints[0].PathPrefix = "/x" }), "exactly one of path and pathPrefix"},
		{"neither path nor prefix", with(func(r *RateLimitRule) { r.Endpoints[0].Path = "" }), "exactly one of path and pathPrefix"},
		{"relative path", with(func(r *RateLimitRule) { r.Endpoints[0].Path = "collect" }), `must start with "/"`},
		{"query in path", with(func(r *RateLimitRule) { r.Endpoints[0].Path = "/collect?a=1" }), "no query string"},
		{"quote in path", with(func(r *RateLimitRule) { r.Endpoints[0].Path = `/a"b` }), "without a quote or backslash"},
		{"backslash in path", with(func(r *RateLimitRule) { r.Endpoints[0].Path = `/a\b` }), "without a quote or backslash"},
		{"non-ASCII path", with(func(r *RateLimitRule) { r.Endpoints[0].Path = "/café" }), "printable ASCII"},
		{"duplicate endpoint", with(func(r *RateLimitRule) { r.Endpoints = append(r.Endpoints, r.Endpoints[0]) }), "repeats an earlier endpoint"},
		{"long expression", with(func(r *RateLimitRule) {
			r.Endpoints = nil
			r.Expression = strings.Repeat("a", 4097)
		}), "longer than Cloudflare's 4096"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.args.Validate()
			if c.want == "" {
				require.NoError(t, err)

				return
			}

			require.Error(t, err)
			assert.Contains(t, err.Error(), c.want)
		})
	}
}

func TestBusinessPlanLimits(t *testing.T) {
	r := ingestRule()
	r.Period = 300
	r.MitigationTimeout = 86400
	r.CountingExpression = `http.response.code eq 403`
	r.Characteristics = []string{"cf.unique_visitor_id"}
	r.Endpoints[0].Methods = []string{"POST"}

	require.NoError(t, (&Args{ZoneID: "z", RateLimits: &RateLimits{Plan: PlanBusiness, Rules: []RateLimitRule{r}}}).Validate())

	r.Characteristics = []string{"ip.src", "cf.unique_visitor_id"}
	err := (&Args{ZoneID: "z", RateLimits: &RateLimits{Plan: PlanBusiness, Rules: []RateLimitRule{r}}}).Validate()
	require.ErrorContains(t, err, "cannot be used together")
}

func TestFreePlanHoldsOneRule(t *testing.T) {
	b := ingestRule()
	b.Name = "b"
	err := (&Args{ZoneID: "z", RateLimits: &RateLimits{Plan: PlanFree, Rules: []RateLimitRule{ingestRule(), b}}}).Validate()
	require.ErrorContains(t, err, "free plan allows 1")
}
