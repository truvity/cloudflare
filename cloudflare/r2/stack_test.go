package r2

import (
	"log/slog"
	"slices"
	"sync"
	"testing"

	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func stackArgs(b Declaration) StackArgs {
	return StackArgs{
		AccountName: "platform", AccountID: "acct-1", Token: "admin-token-value",
		Buckets: []Declaration{b}, Logger: slog.New(slog.DiscardHandler),
	}
}

func runStack(t *testing.T, args StackArgs) (*stackMocks, error) {
	t.Helper()

	m := &stackMocks{}
	err := pulumi.RunErr(func(ctx *pulumi.Context) error { return DeployStack(ctx, args) },
		pulumi.WithMocks("example", "buckets", m))

	return m, err
}

func TestDeployStackBucketWithLifecycle(t *testing.T) {
	m, err := runStack(t, stackArgs(Declaration{
		Name: "scratch", Enabled: true, Account: "platform", Bucket: "scratch-bucket",
		Lifecycle: &Lifecycle{ExpireAfterDays: 1},
	}))
	require.NoError(t, err)

	assert.Equal(t, []string{"r2-scratch"}, m.names("truvity:cloudflare:R2"))
	bucket := "cloudflare:index/r2Bucket:R2Bucket"
	assert.Equal(t, []string{"bucket-r2-scratch"}, m.names(bucket))
	assert.Equal(t, "scratch-bucket", m.input(bucket, "bucket-r2-scratch", "name"))
	assert.Equal(t, "acct-1", m.input(bucket, "bucket-r2-scratch", "accountId"))
	assert.Empty(t, m.input(bucket, "bucket-r2-scratch", "jurisdiction"))
	assert.Equal(t, []string{"lifecycle-r2-scratch"}, m.names("cloudflare:index/r2BucketLifecycle:R2BucketLifecycle"))
}

func TestDeployStackJurisdictionReachesTheBucket(t *testing.T) {
	m, err := runStack(t, stackArgs(Declaration{
		Name: "scratch", Enabled: true, Account: "platform", Bucket: "scratch-bucket", Jurisdiction: "eu",
	}))
	require.NoError(t, err)
	assert.Equal(t, "eu", m.input("cloudflare:index/r2Bucket:R2Bucket", "bucket-r2-scratch", "jurisdiction"))
}

func TestDeployStackDisabledBucketCreatesNothing(t *testing.T) {
	m, err := runStack(t, stackArgs(Declaration{Name: "scratch", Account: "platform", Bucket: "scratch-bucket"}))
	require.NoError(t, err)
	assert.Empty(t, m.names("truvity:cloudflare:R2"))
}

// The stack mints no tokens: its only provider is the admin child it was
// handed and it registers no account token of its own.
func TestDeployStackMintsNoTokens(t *testing.T) {
	m, err := runStack(t, stackArgs(Declaration{Name: "scratch", Enabled: true, Account: "platform", Bucket: "example-bucket"}))
	require.NoError(t, err)
	assert.Empty(t, m.names("cloudflare:index/accountToken:AccountToken"))
	assert.Equal(t, []string{"provider-r2"}, m.names("pulumi:providers:cloudflare"))
}

func TestDeployStackRefusesABucketOutsideTheAdminAccount(t *testing.T) {
	_, err := runStack(t, stackArgs(Declaration{Name: "scratch", Enabled: true, Account: "other", Bucket: "b"}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), `account "other" is not "platform"`)
}

type (
	stackRecorded struct {
		typ, name string
		inputs    resource.PropertyMap
	}

	stackMocks struct {
		mu        sync.Mutex
		resources []stackRecorded
	}
)

func (m *stackMocks) NewResource(args pulumi.MockResourceArgs) (string, resource.PropertyMap, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.resources = append(m.resources, stackRecorded{args.TypeToken, args.Name, args.Inputs})

	return args.Name + "-id", args.Inputs.Copy(), nil
}

func (m *stackMocks) Call(pulumi.MockCallArgs) (resource.PropertyMap, error) {
	return resource.PropertyMap{}, nil
}

func (m *stackMocks) names(typ string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	var out []string

	for _, r := range m.resources {
		if r.typ == typ {
			out = append(out, r.name)
		}
	}

	slices.Sort(out)

	return out
}

func (m *stackMocks) input(typ, name, key string) string {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, r := range m.resources {
		if r.typ == typ && r.name == name {
			val, ok := r.inputs[resource.PropertyKey(key)]
			if !ok || val.IsNull() {
				return ""
			}

			return val.StringValue()
		}
	}

	return ""
}
