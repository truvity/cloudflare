package r2

import (
	"sync"
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/edge/v4/cloudflare/account"
)

const (
	accountTokenType = "cloudflare:index/accountToken:AccountToken"
	bucketType       = "cloudflare:index/r2Bucket:R2Bucket"
	lifecycleType    = "cloudflare:index/r2BucketLifecycle:R2BucketLifecycle"
)

// mocks records every registered resource so tests can assert on the exact
// child names, types and inputs: the names are a documented contract
// (consumers alias existing resources onto them).
type mocks struct {
	mu  sync.Mutex
	res map[string]resource.PropertyMap // "type/name" -> inputs
}

func newMocks() *mocks {
	return &mocks{res: map[string]resource.PropertyMap{}}
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

func baseConfig() Config {
	return Config{
		AccountID: "example-account-id",
		Bucket:    "example-bucket",
	}
}

// withAccountProvider builds a real (mocked) Cloudflare provider for
// accountID and returns the option that binds it — the same
// pulumi.Provider(...) account.Use() returns — so tests exercise the
// actual path a real caller takes (an explicit, named account), not an
// implicit default one.
func withAccountProvider(t *testing.T, ctx *pulumi.Context, accountID string) pulumi.ResourceOption {
	t.Helper()

	acct, err := account.New(ctx, "acct", account.Args{AccountID: accountID}, pulumi.String("token-"+accountID))
	require.NoError(t, err)

	return acct.Use()
}

func run(t *testing.T, cfg Config) (*mocks, *R2) {
	t.Helper()
	m := newMocks()

	var out *R2
	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		r, err := New(ctx, "cache", cfg, withAccountProvider(t, ctx, cfg.AccountID))
		if err != nil {
			return err
		}

		out = r

		return nil
	}, pulumi.WithMocks("proj", "stack", m))
	require.NoError(t, err)

	return m, out
}

func resolveString(t *testing.T, o pulumi.StringOutput) string {
	t.Helper()

	ch := make(chan string, 1)
	o.ApplyT(func(v string) string { ch <- v; return v })

	return <-ch
}

func TestChildNamesAreTheDocumentedContract(t *testing.T) {
	m, _ := run(t, baseConfig())

	assert.Contains(t, m.res, bucketType+"/bucket-cache")

	for k := range m.res {
		assert.NotContains(t, k, "r2BucketLifecycle", "no lifecycle unless Config.Lifecycle is set")
	}
}

func TestBucketArgs(t *testing.T) {
	m, r := run(t, baseConfig())

	b := m.res[bucketType+"/bucket-cache"]
	assert.Equal(t, "example-account-id", b["accountId"].StringValue())
	assert.Equal(t, "example-bucket", b["name"].StringValue())
	assert.False(t, b.HasValue("jurisdiction"), "unset by default")
	assert.Equal(t, "example-bucket", resolveString(t, r.BucketName))
}

func TestJurisdictionReachesTheBucket(t *testing.T) {
	cfg := baseConfig()
	cfg.Jurisdiction = "eu"
	m, _ := run(t, cfg)

	b := m.res[bucketType+"/bucket-cache"]
	assert.Equal(t, "eu", b["jurisdiction"].StringValue())
}

// The component mints no credentials: no account token, whatever the config.
func TestNoTokenIsRegistered(t *testing.T) {
	cfg := baseConfig()
	cfg.Lifecycle = &Lifecycle{ExpireAfterDays: 7}
	m, _ := run(t, cfg)

	for k := range m.res {
		assert.NotContains(t, k, accountTokenType)
	}
}

func TestLifecycleRule(t *testing.T) {
	cfg := baseConfig()
	cfg.Lifecycle = &Lifecycle{ExpireAfterDays: 7, Prefix: "tmp/"}
	m, _ := run(t, cfg)

	lc, ok := m.res[lifecycleType+"/lifecycle-cache"]
	require.True(t, ok)
	assert.Equal(t, "example-bucket", lc["bucketName"].StringValue())

	rules := lc["rules"].ArrayValue()
	require.Len(t, rules, 1)
	rule := rules[0].ObjectValue()
	assert.True(t, rule["enabled"].BoolValue())
	assert.Equal(t, "tmp/", rule["conditions"].ObjectValue()["prefix"].StringValue())

	transition := rule["deleteObjectsTransition"].ObjectValue()["condition"].ObjectValue()
	assert.Equal(t, float64(7*86400), transition["maxAge"].NumberValue())
	assert.Equal(t, "Age", transition["type"].StringValue())
}

func TestNoLifecycleWhenUnset(t *testing.T) {
	m, r := run(t, baseConfig())

	for k := range m.res {
		assert.NotContains(t, k, "r2BucketLifecycle")
	}
	assert.Nil(t, r.Lifecycle)
}

func TestValidate(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*Config)
		want string
	}{
		{"no account", func(c *Config) { c.AccountID = "" }, "accountId is required"},
		{"no bucket", func(c *Config) { c.Bucket = "" }, "bucket is required"},
		{"bucket too short", func(c *Config) { c.Bucket = "ab" }, "3-63 characters"},
		{"bucket too long", func(c *Config) { c.Bucket = stringsRepeat("a", 64) }, "3-63 characters"},
		{"bucket upper case", func(c *Config) { c.Bucket = "Example-Bucket" }, "lowercase letters"},
		{"bucket leading hyphen", func(c *Config) { c.Bucket = "-example" }, "may not start or end with a hyphen"},
		{"bucket trailing hyphen", func(c *Config) { c.Bucket = "example-" }, "may not start or end with a hyphen"},
		{"bucket bad character", func(c *Config) { c.Bucket = "example_bucket" }, "lowercase letters"},
		{"bad jurisdiction", func(c *Config) { c.Jurisdiction = "mars" }, "jurisdiction"},
		{"lifecycle zero days", func(c *Config) { c.Lifecycle = &Lifecycle{ExpireAfterDays: 0} }, "greater than zero"},
		{"lifecycle negative days", func(c *Config) { c.Lifecycle = &Lifecycle{ExpireAfterDays: -1} }, "greater than zero"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := baseConfig()
			tc.mut(&c)
			err := c.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestValidateAcceptsAWellFormedConfig(t *testing.T) {
	cfg := baseConfig()
	cfg.Jurisdiction = "eu"
	cfg.Lifecycle = &Lifecycle{ExpireAfterDays: 30}
	require.NoError(t, cfg.Validate())
}

func stringsRepeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}

	return string(out)
}
