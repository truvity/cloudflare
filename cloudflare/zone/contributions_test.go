package zone

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cfrules "github.com/truvity/edge/v3/cloudflare/rules"
)

// render is every resource New registered, "type/name" to inputs, as JSON
// (encoding/json sorts the map keys, so the bytes are stable).
func render(t *testing.T, m *mocks) []byte {
	t.Helper()

	m.mu.Lock()
	defer m.mu.Unlock()

	out := make(map[string]any, len(m.res))
	for k, inputs := range m.res {
		out[k] = inputs.Mappable()
	}

	b, err := json.MarshalIndent(out, "", "  ")
	require.NoError(t, err)

	return append(b, '\n')
}

// assertGolden compares got with testdata/<name>; UPDATE_GOLDEN=1 rewrites it.
func assertGolden(t *testing.T, name string, got []byte) {
	t.Helper()

	path := filepath.Join("testdata", name)
	if os.Getenv("UPDATE_GOLDEN") != "" {
		require.NoError(t, os.MkdirAll("testdata", 0o755))
		require.NoError(t, os.WriteFile(path, got, 0o600))
	}

	want, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, string(want), string(got))
}

func contributedArgs(t *testing.T) Args {
	t.Helper()

	public, err := cfrules.PublicPathsCache("api.example.com", cfrules.PublicPathsArgs{})
	require.NoError(t, err)

	sslMode, err := cfrules.SSLMode("legacy.example.com", "full", "ssl-legacy-example-com")
	require.NoError(t, err)

	on := true

	return Args{
		ZoneID:                   "zone-1",
		Cache:                    &Cache{Hosts: []string{"app.example.com"}},
		TrustedClients:           &TrustedClients{Zone: "example.com", Hosts: []string{"api.example.com"}, Ranges: []string{"192.0.2.0/24"}},
		AuthenticatedOriginPulls: &on,
		Contributions:            []cfrules.Contribution{public.Contribution(), sslMode},
		ImportRulesets:           map[cfrules.Phase]string{cfrules.PhaseConfigSettings: "ruleset-id-1"},
		Compat:                   Compat{TopLevelAliases: true},
	}
}

// TestContributionsRender pins what a zone with contributions registers: the
// cache phase folds the public-paths claim into the bypass, the SSL-mode
// rule lands in the config phase under its ref, Authenticated Origin Pulls
// is a zone setting, and the ruleset is adopted by id.
func TestContributionsRender(t *testing.T) {
	assertGolden(t, "contributions.json", render(t, run(t, contributedArgs(t))))
}

func TestContributedCacheOrder(t *testing.T) {
	m := run(t, contributedArgs(t))

	got := rules(t, m)
	require.Len(t, got, 3)
	assert.Equal(t, "Cacheable hostname: the origin's Cache-Control decides", got[0]["description"].StringValue())
	assert.Equal(t, "Not a cacheable hostname", got[1]["description"].StringValue())
	assert.Contains(t, got[1]["expression"].StringValue(), ") and not (http.host eq \"api.example.com\"")
	assert.Equal(t, "public-paths-api.example.com", got[2]["ref"].StringValue())
}

func TestImportAdoptsTheExistingRuleset(t *testing.T) {
	m := run(t, contributedArgs(t))

	assert.Equal(t, map[string]string{rulesetType + "/ssl-mode-example": "zones/zone-1/ruleset-id-1"}, m.imported)
}

func TestAuthenticatedOriginPulls(t *testing.T) {
	off := false
	m := run(t, Args{ZoneID: "zone-1", AuthenticatedOriginPulls: &off})

	s := m.res[settingType+"/tls-client-auth-example"]
	assert.Equal(t, "tls_client_auth", s["settingId"].StringValue())
	assert.Equal(t, "off", s["value"].StringValue())
}

func TestImportMustNameAManagedPhase(t *testing.T) {
	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		_, err := New(ctx, "example", Args{
			ZoneID: "zone-1", SSL: "full",
			ImportRulesets: map[cfrules.Phase]string{cfrules.PhaseRateLimit: "id"},
		})

		return err
	}, pulumi.WithMocks("proj", "stack", &mocks{res: map[string]resource.PropertyMap{}}))
	require.Error(t, err)
}

func TestTopLevelAliasOnlyWhenAsked(t *testing.T) {
	base := []pulumi.ResourceOption{pulumi.Protect(true)}

	assert.Len(t, withTopLevelAlias(base, Compat{}), 1)
	assert.Len(t, withTopLevelAlias(base, Compat{TopLevelAliases: true}), 2)
	assert.Len(t, base, 1, "the shared option slice is not modified")
}

// OmitRefs registers a contributed rule the way an estate that predates refs
// did: enabled, and no ref input.
func TestOmitRefsLeavesTheRefOutOfTheInputs(t *testing.T) {
	args := contributedArgs(t)
	args.Compat.OmitRefs = []string{"public-paths-api.example.com"}

	got := rules(t, run(t, args))
	require.Len(t, got, 3)

	_, hasRef := got[2]["ref"]
	assert.False(t, hasRef, "the omitted ref is not an input")
	assert.True(t, got[2]["enabled"].BoolValue(), "and the rule is still enabled")
}

func TestOmitRefsRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*Args)
		want   string
	}{
		"no such rule": {func(a *Args) { a.Compat.OmitRefs = []string{"nothing"} }, `no contributed rule has ref "nothing"`},
		"a disabled rule": {func(a *Args) {
			a.Contributions[0].Rules[0].Disabled = true
			a.Compat.OmitRefs = []string{a.Contributions[0].Rules[0].Ref}
		}, "is disabled"},
	} {
		args := contributedArgs(t)
		tc.mutate(&args)

		err := pulumi.RunErr(func(ctx *pulumi.Context) error {
			_, err := New(ctx, "example", args)

			return err
		}, pulumi.WithMocks("proj", "stack", &mocks{res: map[string]resource.PropertyMap{}}))
		require.ErrorContains(t, err, tc.want, name)
	}
}
