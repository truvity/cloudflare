package account

import (
	"sync"
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

const providerType = "pulumi:providers:cloudflare"

func TestProviderNameAndToken(t *testing.T) {
	m := &mocks{res: map[string]resource.PropertyMap{}}
	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		acct, err := New(ctx, "platform", Args{AccountID: "acct"}, pulumi.String("token-value"))
		if err != nil {
			return err
		}

		assert.Equal(t, "acct", acct.AccountID)
		assert.NotNil(t, acct.Use(), "Use binds a component to this account's provider")

		return nil
	}, pulumi.WithMocks("proj", "stack", m))
	require.NoError(t, err)

	inputs, ok := m.res[providerType+"/provider-platform"]
	require.True(t, ok, "child name is a contract consumers alias onto")

	token := inputs["apiToken"]
	require.True(t, token.IsSecret(), "the token must never reach plain state")
	assert.Equal(t, "token-value", token.SecretValue().Element.StringValue())
}

func TestBaseURLIsOnlySetWhenGiven(t *testing.T) {
	m := &mocks{res: map[string]resource.PropertyMap{}}
	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		_, err := New(ctx, "platform", Args{AccountID: "acct"}, pulumi.String("t"))

		return err
	}, pulumi.WithMocks("proj", "stack", m))
	require.NoError(t, err)

	assert.False(t, m.res[providerType+"/provider-platform"].HasValue("baseUrl"))
}

func TestTwoAccountsAreTwoProviders(t *testing.T) {
	m := &mocks{res: map[string]resource.PropertyMap{}}
	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		if _, err := New(ctx, "platform", Args{AccountID: "one"}, pulumi.String("t1")); err != nil {
			return err
		}
		_, err := New(ctx, "partner", Args{AccountID: "two"}, pulumi.String("t2"))

		return err
	}, pulumi.WithMocks("proj", "stack", m))
	require.NoError(t, err)

	assert.Contains(t, m.res, providerType+"/provider-platform")
	assert.Contains(t, m.res, providerType+"/provider-partner")
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name string
		args Args
		want string
	}{
		{"no account", Args{}, "accountId is required"},
		{"ok", Args{AccountID: "acct"}, ""},
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

func TestTokenIsRequired(t *testing.T) {
	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		_, err := New(ctx, "platform", Args{AccountID: "acct"}, nil)

		return err
	}, pulumi.WithMocks("proj", "stack", &mocks{res: map[string]resource.PropertyMap{}}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token is required")
}
