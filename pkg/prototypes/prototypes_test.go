package prototypes

import (
	"strings"
	"sync"
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/cloudflare/v2/pkg/account"
	"github.com/truvity/cloudflare/v2/pkg/presettoken"
)

const (
	testAccount = "0123456789abcdef0123456789abcdef"
	testZone    = "fedcba9876543210fedcba9876543210"
	tokenType   = "cloudflare:index/accountToken:AccountToken"
	groupsToken = "cloudflare:index/getAccountApiTokenPermissionGroupsList:getAccountApiTokenPermissionGroupsList"
	testEnv     = "EXAMPLE_CLOUDFLARE_BREAKGLASS"
)

var testBreakGlass = presettoken.BreakGlass{
	Env: testEnv, Account: "example.1password.com", Vault: "vault", Item: "cf-root", Field: "token", ChildPrefix: "example-breakglass",
}

func testPresets() []Preset {
	return []Preset{
		{Name: "example-status", Policies: []account.ChildTokenPolicy{
			{PermissionGroups: []string{"DNS Write"}, Scope: account.ZoneScope{ZoneID: testZone}},
		}},
		{Name: "example-edge", Policies: []account.ChildTokenPolicy{
			{PermissionGroups: []string{"Cloudflare Tunnel Write"}, Scope: account.WholeAccountScope{}},
			{PermissionGroups: []string{"DNS Write", "Zone Settings Write"}, Scope: account.ZoneScope{ZoneID: testZone}},
		}},
	}
}

func testArgs() Args {
	return Args{AccountID: testAccount, Presets: testPresets(), NamePrefix: "example-prototype-", BreakGlass: testBreakGlass}
}

type mocks struct {
	mu      sync.Mutex
	res     map[string]resource.PropertyMap
	protect map[string]bool
	invokes int
}

func newMocks() *mocks {
	return &mocks{res: map[string]resource.PropertyMap{}, protect: map[string]bool{}}
}

func (m *mocks) NewResource(args pulumi.MockResourceArgs) (string, resource.PropertyMap, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := args.TypeToken + "/" + args.Name
	m.res[key] = args.Inputs
	m.protect[key] = args.RegisterRPC.GetProtect()

	return "id-" + args.Name, args.Inputs.Copy(), nil
}

func (m *mocks) Call(args pulumi.MockCallArgs) (resource.PropertyMap, error) {
	if args.Token != groupsToken {
		return resource.PropertyMap{}, nil
	}

	m.mu.Lock()
	m.invokes++
	m.mu.Unlock()

	name := args.Args["name"].StringValue()

	return resource.PropertyMap{"results": resource.NewArrayProperty([]resource.PropertyValue{
		resource.NewObjectProperty(resource.PropertyMap{
			"id": resource.NewStringProperty("pg:" + name), "name": resource.NewStringProperty(name),
			"scopes": resource.NewArrayProperty(nil),
		}),
	})}, nil
}

func rootEnv(t *testing.T) {
	t.Helper()
	t.Setenv(testEnv, "1")
	t.Setenv(RootEnv, "root-not-printed")

	for _, k := range conflictingEnv {
		t.Setenv(k, "")
	}
}

// Every preset becomes one DISABLED, PROTECTED account token on the default
// provider, with the policies' resource keys and the groups' resolved ids; the
// ids and statuses are exported.
func TestDeclaresDisabledProtectedPrototypes(t *testing.T) {
	rootEnv(t)

	m := newMocks()
	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		toks, err := Deploy(ctx, testArgs())
		if err != nil {
			return err
		}

		assert.Len(t, toks, 2)

		return nil
	}, pulumi.WithMocks("proj", "stack", m))
	require.NoError(t, err)

	edge := m.res[tokenType+"/prototype-example-edge"]
	require.NotNil(t, edge)
	assert.Equal(t, "disabled", edge["status"].StringValue())
	assert.Equal(t, "example-prototype-example-edge", edge["name"].StringValue())
	assert.Equal(t, testAccount, edge["accountId"].StringValue())
	assert.True(t, m.protect[tokenType+"/prototype-example-edge"], "a replaced prototype is a new id")
	assert.True(t, m.protect[tokenType+"/prototype-example-status"])

	policies := edge["policies"].ArrayValue()
	require.Len(t, policies, 2)

	whole := policies[0].ObjectValue()
	assert.Equal(t, "allow", whole["effect"].StringValue())
	assert.JSONEq(t, `{"com.cloudflare.api.account.`+testAccount+`":"*"}`, whole["resources"].StringValue())

	zone := policies[1].ObjectValue()
	assert.JSONEq(t, `{"com.cloudflare.api.account.zone.`+testZone+`":"*"}`, zone["resources"].StringValue())
	require.Len(t, zone["permissionGroups"].ArrayValue(), 2)
	assert.Equal(t, "pg:DNS Write", zone["permissionGroups"].ArrayValue()[0].ObjectValue()["id"].StringValue())

	for k := range m.res {
		assert.False(t, strings.Contains(k, "provider-"), "no explicit provider: the root would enter the state (%s)", k)
	}
}

// Without break-glass, or with a second credential, a stack config token or no
// root at all, nothing is declared.
func TestRefusesToRunWithoutTheRootFromTheEnvironment(t *testing.T) {
	for name, tc := range map[string]struct {
		setup func(t *testing.T)
		cfg   map[string]string
		want  string
	}{
		"no break-glass": {func(t *testing.T) { rootEnv(t); t.Setenv(testEnv, "") }, nil, "break-glass only"},
		"no root":        {func(t *testing.T) { rootEnv(t); t.Setenv(RootEnv, "") }, nil, RootEnv + " is not set"},
		"second credential": {func(t *testing.T) {
			rootEnv(t)
			t.Setenv("CLOUDFLARE_API_KEY", "k")
		}, nil, "CLOUDFLARE_API_KEY is set"},
		"token in config": {rootEnv, map[string]string{"cloudflare:apiToken": "t"}, "cloudflare:apiToken"},
	} {
		t.Run(name, func(t *testing.T) {
			tc.setup(t)

			m := newMocks()
			err := pulumi.RunErr(func(ctx *pulumi.Context) error {
				_, err := Deploy(ctx, testArgs())

				return err
			}, pulumi.WithMocks("proj", "stack", m), func(info *pulumi.RunInfo) { info.Config = tc.cfg })

			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
			assert.NotContains(t, err.Error(), "root-not-printed")
			assert.Empty(t, m.res, "nothing may be declared")
		})
	}
}

// Prototypes that exist in another stack are not declared before the move.
func TestMovedGate(t *testing.T) {
	rootEnv(t)

	args := testArgs()
	args.Moved = []string{"example-edge"}

	run := func(cfg map[string]string) (*mocks, error) {
		m := newMocks()
		err := pulumi.RunErr(func(ctx *pulumi.Context) error {
			_, err := Deploy(ctx, args)

			return err
		}, pulumi.WithMocks("proj", "stack", m), func(info *pulumi.RunInfo) { info.Config = cfg })

		return m, err
	}

	m, err := run(nil)
	require.ErrorContains(t, err, "before they are moved here")
	assert.Empty(t, m.res)

	_, err = run(map[string]string{"proj:stateMoved": "true"})
	require.NoError(t, err)
}

func TestArgsValidate(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*Args)
		want   string
	}{
		"bad account":    {func(a *Args) { a.AccountID = "x" }, "account id"},
		"no prefix":      {func(a *Args) { a.NamePrefix = "" }, "NamePrefix"},
		"no break-glass": {func(a *Args) { a.BreakGlass = presettoken.BreakGlass{} }, "BreakGlass.Env"},
		"no presets":     {func(a *Args) { a.Presets = nil }, "no presets"},
		"duplicate":      {func(a *Args) { a.Presets = append(a.Presets, a.Presets[0]) }, "twice"},
		"no name":        {func(a *Args) { a.Presets = []Preset{{Policies: a.Presets[0].Policies}} }, "no name"},
		"no policies":    {func(a *Args) { a.Presets = []Preset{{Name: "x"}} }, "policy"},
		"api tokens": {func(a *Args) {
			a.Presets = []Preset{{Name: "x", Policies: []account.ChildTokenPolicy{
				{PermissionGroups: []string{"Account API Tokens Write"}, Scope: account.WholeAccountScope{}},
			}}}
		}, "must never be granted"},
		"bad scope": {func(a *Args) {
			a.Presets = []Preset{{Name: "x", Policies: []account.ChildTokenPolicy{
				{PermissionGroups: []string{"DNS Write"}, Scope: account.ZoneScope{ZoneID: "z"}},
			}}}
		}, "zoneId"},
		"unknown moved": {func(a *Args) { a.Moved = []string{"nope"} }, "not in Presets"},
	} {
		t.Run(name, func(t *testing.T) {
			a := testArgs()
			tc.mutate(&a)

			err := a.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}

	require.NoError(t, testArgs().Validate())
}
