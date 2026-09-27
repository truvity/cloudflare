package r2

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	pulumirpc "github.com/pulumi/pulumi/sdk/v3/proto/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/cloudflare/v2/pkg/account"
)

func assertionError(msg string) error { return errors.New(msg) }

const (
	accountTokenType     = "cloudflare:index/accountToken:AccountToken"
	bucketType           = "cloudflare:index/r2Bucket:R2Bucket"
	lifecycleType        = "cloudflare:index/r2BucketLifecycle:R2BucketLifecycle"
	permissionGroupToken = "cloudflare:index/getAccountApiTokenPermissionGroupsList:getAccountApiTokenPermissionGroupsList"
)

// mocks records every registered resource so tests can assert on the exact
// child names, types and inputs — the names are a documented contract
// (consumers alias existing resources onto them) — and answers the
// permission-group lookup invoke from a fixed name -> id table.
type mocks struct {
	mu      sync.Mutex
	res     map[string]resource.PropertyMap // "type/name" -> inputs
	regRPCs map[string]*pulumirpc.RegisterResourceRequest
	groups  map[string]string // permission group name -> id

	// lastPermissionGroupProvider records the provider ref the mock most
	// recently saw on the permission-group invoke — "" if none. Tests
	// assert on this to prove the invoke resolved the SAME provider its
	// sibling resources did, not the (possibly disabled) default one.
	lastPermissionGroupProvider string
}

func newMocks() *mocks {
	return &mocks{
		res:     map[string]resource.PropertyMap{},
		regRPCs: map[string]*pulumirpc.RegisterResourceRequest{},
		groups: map[string]string{
			"Workers R2 Storage Bucket Item Write": "group-write-id",
			"Workers R2 Storage Bucket Item Read":  "group-read-id",
			"Custom R2 Group":                      "group-custom-id",
		},
	}
}

func (m *mocks) NewResource(args pulumi.MockResourceArgs) (string, resource.PropertyMap, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := args.TypeToken + "/" + args.Name
	m.res[key] = args.Inputs
	m.regRPCs[key] = args.RegisterRPC

	out := args.Inputs.Copy()
	id := args.Name + "-id"

	if args.TypeToken == accountTokenType {
		id = "token-id-123"
		out["value"] = resource.NewStringProperty("tok-value-abc123")
	}

	return id, out, nil
}

func (m *mocks) Call(args pulumi.MockCallArgs) (resource.PropertyMap, error) {
	if args.Token != permissionGroupToken {
		return resource.PropertyMap{}, nil
	}

	m.mu.Lock()
	m.lastPermissionGroupProvider = args.Provider
	m.mu.Unlock()

	// The lookup MUST carry the caller's explicit Cloudflare provider —
	// gitops#1700 shipped this invoke with none at all, which fails
	// outright wherever the default provider is disabled (INF-r2-invoke).
	// A missing provider ref here must fail the test, not just log it, so
	// a future regression is caught the moment it is introduced rather
	// than at "kernel diff" time in a downstream repo.
	if args.Provider == "" {
		return resource.PropertyMap{}, assertionError("getAccountApiTokenPermissionGroupsList invoked with no explicit provider — thread the account's Cloudflare provider into this invoke, not just the bucket/token resources")
	}

	// The lookup MUST be account-scoped: assert the invoke always carries
	// an accountId, never just a bare name filter against the global list.
	if !args.Args.HasValue("accountId") || args.Args["accountId"].StringValue() == "" {
		return resource.PropertyMap{}, assertionError("getAccountApiTokenPermissionGroupsList invoked with no accountId")
	}

	encoded := args.Args["name"].StringValue()
	name := decodeSpaces(encoded)

	id, ok := m.groups[name]
	if !ok {
		return resource.PropertyMap{
			"results": resource.NewArrayProperty([]resource.PropertyValue{}),
		}, nil
	}

	return resource.PropertyMap{
		"results": resource.NewArrayProperty([]resource.PropertyValue{
			resource.NewObjectProperty(resource.PropertyMap{
				"id":     resource.NewStringProperty(id),
				"name":   resource.NewStringProperty(name),
				"scopes": resource.NewArrayProperty([]resource.PropertyValue{}),
			}),
		}),
	}, nil
}

// decodeSpaces reverses urlEncodeName for the mock's own bookkeeping.
func decodeSpaces(s string) string {
	out := make([]rune, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && s[i+1] == '2' && s[i+2] == '0' {
			out = append(out, ' ')
			i += 2

			continue
		}

		out = append(out, rune(s[i]))
	}

	return string(out)
}

func baseConfig() Config {
	return Config{
		AccountID: "example-account-id",
		Bucket:    "example-bucket",
		Token: TokenConfig{
			Enabled:    true,
			Permission: PermissionObjectReadWrite,
		},
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
	assert.Contains(t, m.res, accountTokenType+"/token-cache")

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

func TestJurisdictionSetsBucketAndResourceKey(t *testing.T) {
	cfg := baseConfig()
	cfg.Jurisdiction = "eu"
	m, _ := run(t, cfg)

	b := m.res[bucketType+"/bucket-cache"]
	assert.Equal(t, "eu", b["jurisdiction"].StringValue())

	tok := m.res[accountTokenType+"/token-cache"]
	policies := tok["policies"].ArrayValue()
	require.Len(t, policies, 1)

	var resources map[string]string
	require.NoError(t, json.Unmarshal([]byte(policies[0].ObjectValue()["resources"].StringValue()), &resources))
	assert.Equal(t, map[string]string{"com.cloudflare.edge.r2.bucket.example-account-id_eu_example-bucket": "*"}, resources)
}

func TestDefaultJurisdictionIsDefaultInResourceKey(t *testing.T) {
	m, _ := run(t, baseConfig())

	tok := m.res[accountTokenType+"/token-cache"]
	policies := tok["policies"].ArrayValue()

	var resources map[string]string
	require.NoError(t, json.Unmarshal([]byte(policies[0].ObjectValue()["resources"].StringValue()), &resources))
	assert.Equal(t, map[string]string{"com.cloudflare.edge.r2.bucket.example-account-id_default_example-bucket": "*"}, resources)
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

func TestTokenPolicyIsExactlyOneBucket(t *testing.T) {
	m, _ := run(t, baseConfig())

	tok := m.res[accountTokenType+"/token-cache"]
	policies := tok["policies"].ArrayValue()
	require.Len(t, policies, 1, "exactly one policy")

	policy := policies[0].ObjectValue()
	assert.Equal(t, "allow", policy["effect"].StringValue())

	groups := policy["permissionGroups"].ArrayValue()
	require.Len(t, groups, 1, "exactly one permission group")
	assert.Equal(t, "group-write-id", groups[0].ObjectValue()["id"].StringValue())

	var resources map[string]string
	require.NoError(t, json.Unmarshal([]byte(policy["resources"].StringValue()), &resources))
	require.Len(t, resources, 1, "scoped to exactly one bucket")
	assert.Equal(t, "*", resources["com.cloudflare.edge.r2.bucket.example-account-id_default_example-bucket"])
}

func TestTokenIsAccountOwned(t *testing.T) {
	m, r := run(t, baseConfig())

	tok := m.res[accountTokenType+"/token-cache"]
	require.True(t, tok.HasValue("accountId"), "an account-owned token must carry accountId, unlike a user token")
	assert.Equal(t, "example-account-id", tok["accountId"].StringValue())
	assert.Equal(t, "example-account-id", resolveString(t, r.Token.AccountId))

	// A user token (cloudflare:index/apiToken:ApiToken) must never appear:
	// the estate's provisioning token is scoped to create ACCOUNT-owned
	// tokens (Account API Tokens Write), not user ones.
	for k := range m.res {
		assert.NotContains(t, k, "apiToken:ApiToken")
	}
}

func TestPermissionGroupLookupByNamePicksReadOnly(t *testing.T) {
	cfg := baseConfig()
	cfg.Token.Permission = PermissionObjectReadOnly
	m, _ := run(t, cfg)

	tok := m.res[accountTokenType+"/token-cache"]
	groups := tok["policies"].ArrayValue()[0].ObjectValue()["permissionGroups"].ArrayValue()
	assert.Equal(t, "group-read-id", groups[0].ObjectValue()["id"].StringValue())
}

func TestPermissionGroupNameOverride(t *testing.T) {
	cfg := baseConfig()
	cfg.Token.PermissionGroupName = "Custom R2 Group"
	m, _ := run(t, cfg)

	tok := m.res[accountTokenType+"/token-cache"]
	groups := tok["policies"].ArrayValue()[0].ObjectValue()["permissionGroups"].ArrayValue()
	assert.Equal(t, "group-custom-id", groups[0].ObjectValue()["id"].StringValue())
}

func TestUnknownPermissionGroupNameFails(t *testing.T) {
	cfg := baseConfig()
	cfg.Token.PermissionGroupName = "Does Not Exist"
	m := newMocks()

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		_, err := New(ctx, "cache", cfg, withAccountProvider(t, ctx, cfg.AccountID))

		return err
	}, pulumi.WithMocks("proj", "stack", m))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestPermissionGroupLookupCarriesTheExplicitProvider is the regression
// test for gitops#1700 / INF-r2-invoke: New with an explicit provider in
// opts (the account.Use() every real caller passes) must thread that SAME
// provider into the permission-group invoke, not just into the bucket and
// token resources.
func TestPermissionGroupLookupCarriesTheExplicitProvider(t *testing.T) {
	m, _ := run(t, baseConfig())

	assert.NotEmpty(t, m.lastPermissionGroupProvider, "the invoke must carry the account's explicit provider")
}

// TestPermissionGroupLookupWithNoExplicitProviderFails is the mirror
// case: New called with NO provider in opts at all (the exact shape of
// gitops#1700's call site before the fix) must not silently succeed
// against a default provider — mocks.Call refuses an empty provider ref
// on this invoke, and that refusal must surface as New's own error.
func TestPermissionGroupLookupWithNoExplicitProviderFails(t *testing.T) {
	m := newMocks()

	err := pulumi.RunErr(func(ctx *pulumi.Context) error {
		_, err := New(ctx, "cache", baseConfig())

		return err
	}, pulumi.WithMocks("proj", "stack", m))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no explicit provider")
}

func TestSecretOutputsAreMarkedSecret(t *testing.T) {
	_, r := run(t, baseConfig())

	assert.True(t, pulumi.IsSecret(r.TokenValue), "TokenValue must be secret")
	assert.True(t, pulumi.IsSecret(r.S3SecretAccessKey), "S3SecretAccessKey must be secret")
	assert.False(t, pulumi.IsSecret(r.TokenID), "TokenID is not a secret")
	assert.False(t, pulumi.IsSecret(r.S3AccessKeyID), "S3AccessKeyID is not a secret")
}

func TestDerivedS3CredentialsMapping(t *testing.T) {
	_, r := run(t, baseConfig())

	tokenID := resolveString(t, r.TokenID)
	tokenValue := resolveString(t, r.TokenValue)
	accessKeyID := resolveString(t, r.S3AccessKeyID)
	secretKey := resolveString(t, r.S3SecretAccessKey)
	endpoint := resolveString(t, r.S3Endpoint)

	assert.Equal(t, "token-id-123", tokenID)
	assert.Equal(t, "tok-value-abc123", tokenValue)
	assert.Equal(t, tokenID, accessKeyID, "S3AccessKeyID = the token id")

	sum := sha256.Sum256([]byte(tokenValue))
	assert.Equal(t, hex.EncodeToString(sum[:]), secretKey, "S3SecretAccessKey = sha256(tokenValue)")

	assert.Equal(t, "https://example-account-id.r2.cloudflarestorage.com", endpoint)
}

func TestTokenDisabledCreatesNoTokenAndEmptyOutputs(t *testing.T) {
	cfg := baseConfig()
	cfg.Token = TokenConfig{Enabled: false}
	m, r := run(t, cfg)

	assert.NotContains(t, m.res, accountTokenType+"/token-cache")
	assert.Nil(t, r.Token)

	assert.Equal(t, "", resolveString(t, r.TokenID))
	assert.Equal(t, "", resolveString(t, r.TokenValue))
	assert.Equal(t, "", resolveString(t, r.S3AccessKeyID))
	assert.Equal(t, "", resolveString(t, r.S3SecretAccessKey))
}

func TestExpiresOnIsPassedThrough(t *testing.T) {
	cfg := baseConfig()
	cfg.Token.ExpiresOn = "2099-01-01T00:00:00Z"
	m, _ := run(t, cfg)

	tok := m.res[accountTokenType+"/token-cache"]
	assert.Equal(t, "2099-01-01T00:00:00Z", tok["expiresOn"].StringValue())
}

// Rotation forces a replacement, never an in-place rename: the token's
// Cloudflare-visible name embeds Rotation, and "name" is listed in
// ReplaceOnChanges on the token resource, so the property Rotation
// controls is exactly the one Pulumi is told never to update quietly.
func TestRotationChangesNameAndIsReplaceOnChange(t *testing.T) {
	cfg1 := baseConfig()
	cfg1.Token.Rotation = "2026-09-01"
	m1, _ := run(t, cfg1)

	cfg2 := baseConfig()
	cfg2.Token.Rotation = "2026-10-01"
	m2, _ := run(t, cfg2)

	name1 := m1.res[accountTokenType+"/token-cache"]["name"].StringValue()
	name2 := m2.res[accountTokenType+"/token-cache"]["name"].StringValue()
	assert.NotEqual(t, name1, name2, "changing Rotation must change the token's Name")
	assert.Contains(t, name1, "2026-09-01")
	assert.Contains(t, name2, "2026-10-01")

	rpc1 := m1.regRPCs[accountTokenType+"/token-cache"]
	require.NotNil(t, rpc1)
	assert.Contains(t, rpc1.GetReplaceOnChanges(), "name",
		"a Name change must be a REPLACE, not an update, or rotation would relabel the old token instead of minting a new one")

	rpc2 := m2.regRPCs[accountTokenType+"/token-cache"]
	require.NotNil(t, rpc2)
	assert.Contains(t, rpc2.GetReplaceOnChanges(), "name")
}

func TestNoRotationStillSetsReplaceOnChanges(t *testing.T) {
	m, _ := run(t, baseConfig())

	rpc := m.regRPCs[accountTokenType+"/token-cache"]
	require.NotNil(t, rpc)
	assert.Contains(t, rpc.GetReplaceOnChanges(), "name")
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
		{"bad permission", func(c *Config) { c.Token.Permission = "admin-read-write" }, "token.permission"},
		{"expiresOn not RFC3339", func(c *Config) { c.Token.ExpiresOn = "yesterday" }, "not RFC3339"},
		{"expiresOn in the past", func(c *Config) { c.Token.ExpiresOn = "2000-01-01T00:00:00Z" }, "must be in the future"},
		{"rotation bad characters", func(c *Config) { c.Token.Rotation = "not a valid name!" }, "token.rotation"},
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
	cfg.Token.ExpiresOn = "2099-01-01T00:00:00Z"
	cfg.Token.Rotation = "rev-1"
	require.NoError(t, cfg.Validate())
}

func TestValidateTokenDisabledSkipsTokenRules(t *testing.T) {
	cfg := baseConfig()
	cfg.Token = TokenConfig{Enabled: false, Permission: "nonsense"}
	require.NoError(t, cfg.Validate(), "an unused Permission is not validated when the token is disabled")
}

func stringsRepeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}

	return string(out)
}
