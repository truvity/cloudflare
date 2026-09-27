package decide

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/cloudflare/v2/internal/config"
)

var testGrants = []config.Grant{
	{
		Group: "ci:cache:reader", Bucket: "example-bucket",
		Prefixes: []string{"go-build/", "bazel-remote/"}, Permission: config.PermissionReadOnly, TTLSeconds: 900,
	},
	{
		Group: "ci:cache:writer", Bucket: "example-bucket",
		Prefixes: []string{"go-build/", "bazel-remote/"}, Permission: config.PermissionReadWrite, TTLSeconds: 300,
	},
	{
		Group: "ci:artifacts:writer", Bucket: "artifacts-bucket",
		Permission: config.PermissionReadWrite, TTLSeconds: 600, // no prefix restriction
	},
}

func TestDecide(t *testing.T) {
	cases := []struct {
		name    string
		req     Request
		want    Decision
		wantErr string
	}{
		{
			name: "single matching group, no narrowing",
			req:  Request{Groups: []string{"ci:cache:reader"}},
			want: Decision{
				Bucket: "example-bucket", Prefixes: []string{"go-build/", "bazel-remote/"},
				Permission: config.PermissionReadOnly, TTLSeconds: 900,
			},
		},
		{
			name: "narrows to a subset of the grant's prefixes",
			req:  Request{Groups: []string{"ci:cache:writer"}, Prefixes: []string{"go-build/"}},
			want: Decision{
				Bucket: "example-bucket", Prefixes: []string{"go-build/"},
				Permission: config.PermissionReadWrite, TTLSeconds: 300,
			},
		},
		{
			name: "unrestricted grant with no prefixes at all",
			req:  Request{Groups: []string{"ci:artifacts:writer"}},
			want: Decision{
				Bucket: "artifacts-bucket", Permission: config.PermissionReadWrite, TTLSeconds: 600,
			},
		},
		{
			name: "several groups, only one has a grant",
			req:  Request{Groups: []string{"some-other-group", "ci:cache:reader"}},
			want: Decision{
				Bucket: "example-bucket", Prefixes: []string{"go-build/", "bazel-remote/"},
				Permission: config.PermissionReadOnly, TTLSeconds: 900,
			},
		},
		{
			name: "several groups match, explicit grant disambiguates",
			req: Request{
				Groups: []string{"ci:cache:reader", "ci:cache:writer"}, Grant: "ci:cache:writer",
			},
			want: Decision{
				Bucket: "example-bucket", Prefixes: []string{"go-build/", "bazel-remote/"},
				Permission: config.PermissionReadWrite, TTLSeconds: 300,
			},
		},
		{
			name:    "no group maps to a grant",
			req:     Request{Groups: []string{"unrelated-group"}},
			wantErr: "no group in the token maps to a grant",
		},
		{
			name:    "no groups at all",
			req:     Request{},
			wantErr: "no group in the token maps to a grant",
		},
		{
			name:    "several groups match, no grant named",
			req:     Request{Groups: []string{"ci:cache:reader", "ci:cache:writer"}},
			wantErr: "map to 2 grants",
		},
		{
			name:    "requested grant is not among the token's groups",
			req:     Request{Groups: []string{"ci:cache:reader"}, Grant: "ci:cache:writer"},
			wantErr: "not among the token's groups",
		},
		{
			name:    "requested grant refers to a group with no row at all",
			req:     Request{Groups: []string{"ci:cache:reader"}, Grant: "no-such-group"},
			wantErr: "not among the token's groups",
		},
		{
			name:    "requested prefix widens past the grant",
			req:     Request{Groups: []string{"ci:cache:reader"}, Prefixes: []string{"../etc/"}},
			wantErr: "may narrow, never widen",
		},
		{
			name:    "requested prefix is close but not an exact match",
			req:     Request{Groups: []string{"ci:cache:reader"}, Prefixes: []string{"go-build"}},
			wantErr: "may narrow, never widen",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Decide(tc.req, testGrants)

			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestDecideNeverWidensEvenWithGrantNamedExplicitly(t *testing.T) {
	// A single-candidate request naming its own grant explicitly behaves
	// the same as leaving Grant empty.
	got, err := Decide(Request{Groups: []string{"ci:cache:reader"}, Grant: "ci:cache:reader"}, testGrants)
	require.NoError(t, err)
	assert.Equal(t, config.PermissionReadOnly, got.Permission)
}

func TestMatchingGrantsPreservesConfigOrder(t *testing.T) {
	got := matchingGrants([]string{"ci:cache:writer", "ci:cache:reader"}, testGrants)
	require.Len(t, got, 2)
	assert.Equal(t, "ci:cache:reader", got[0].Group, "config order, not request order")
	assert.Equal(t, "ci:cache:writer", got[1].Group)
}
