package decide

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/cloudflare/v2/internal/config"
)

// testGrants follows the estate's own convention: one prefix per row per
// cache tool, so "ci:cache:writer" owns three rows in the same bucket
// that differ only by Prefixes. "ci:cache:admin" is a second group
// holding two rows that differ only by Permission, for the
// permission-disambiguation cases. "ci:artifacts:writer" has no prefix
// restriction at all (the whole bucket).
var testGrants = []config.Grant{
	{
		Group: "ci:cache:writer", Bucket: "example-bucket",
		Prefixes: []string{"go-build/"}, Permission: config.PermissionReadWrite, TTLSeconds: 300,
	},
	{
		Group: "ci:cache:writer", Bucket: "example-bucket",
		Prefixes: []string{"bazel-remote/"}, Permission: config.PermissionReadWrite, TTLSeconds: 300,
	},
	{
		Group: "ci:cache:writer", Bucket: "example-bucket",
		Prefixes: []string{"buildkit/"}, Permission: config.PermissionReadWrite, TTLSeconds: 300,
	},
	{
		Group: "ci:cache:reader", Bucket: "example-bucket",
		Prefixes: []string{"go-build/"}, Permission: config.PermissionReadOnly, TTLSeconds: 900,
	},
	{
		Group: "ci:cache:admin", Bucket: "example-bucket",
		Prefixes: []string{"go-build/"}, Permission: config.PermissionReadOnly, TTLSeconds: 120,
	},
	{
		Group: "ci:cache:admin", Bucket: "example-bucket",
		Prefixes: []string{"go-build/"}, Permission: config.PermissionReadWrite, TTLSeconds: 120,
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
			name: "single-row group, no narrowing",
			req:  Request{Groups: []string{"ci:cache:reader"}},
			want: Decision{
				Group: "ci:cache:reader", Bucket: "example-bucket", Prefixes: []string{"go-build/"},
				Permission: config.PermissionReadOnly, TTLSeconds: 900,
			},
		},
		{
			name: "unrestricted grant with no prefixes at all",
			req:  Request{Groups: []string{"ci:artifacts:writer"}},
			want: Decision{
				Group: "ci:artifacts:writer", Bucket: "artifacts-bucket", Permission: config.PermissionReadWrite, TTLSeconds: 600,
			},
		},
		{
			name: "multi-row group: the right row is chosen by prefix",
			req:  Request{Groups: []string{"ci:cache:writer"}, Prefixes: []string{"bazel-remote/"}},
			want: Decision{
				Group: "ci:cache:writer", Bucket: "example-bucket", Prefixes: []string{"bazel-remote/"},
				Permission: config.PermissionReadWrite, TTLSeconds: 300,
			},
		},
		{
			name: "several groups, only one is held",
			req:  Request{Groups: []string{"some-other-group", "ci:cache:reader"}},
			want: Decision{
				Group: "ci:cache:reader", Bucket: "example-bucket", Prefixes: []string{"go-build/"},
				Permission: config.PermissionReadOnly, TTLSeconds: 900,
			},
		},
		{
			name: "several groups reach different buckets, bucket disambiguates",
			req: Request{
				Groups: []string{"ci:cache:writer", "ci:artifacts:writer"}, Bucket: "artifacts-bucket",
			},
			want: Decision{
				Group: "ci:artifacts:writer", Bucket: "artifacts-bucket", Permission: config.PermissionReadWrite, TTLSeconds: 600,
			},
		},
		{
			name: "rows differing only in permission: resolved by an explicit permission",
			req: Request{
				Groups: []string{"ci:cache:admin"}, Prefixes: []string{"go-build/"}, Permission: config.PermissionReadWrite,
			},
			want: Decision{
				Group: "ci:cache:admin", Bucket: "example-bucket", Prefixes: []string{"go-build/"},
				Permission: config.PermissionReadWrite, TTLSeconds: 120,
			},
		},
		{
			name:    "a group not held by the token is refused",
			req:     Request{Groups: []string{"unrelated-group"}},
			wantErr: "no group in the token maps to a grant",
		},
		{
			name:    "no groups at all",
			req:     Request{},
			wantErr: "no group in the token maps to a grant",
		},
		{
			name:    "wrong bucket is refused",
			req:     Request{Groups: []string{"ci:cache:writer"}, Bucket: "no-such-bucket"},
			wantErr: "not reachable by the token's groups",
		},
		{
			name:    "no bucket named while the token's groups reach several",
			req:     Request{Groups: []string{"ci:cache:writer", "ci:artifacts:writer"}},
			wantErr: "reach 2 buckets",
		},
		{
			name:    "multi-row group, no prefix requested: ambiguous",
			req:     Request{Groups: []string{"ci:cache:writer"}},
			wantErr: "3 grant rows still match",
		},
		{
			name:    "rows differing only in permission, none requested: ambiguous",
			req:     Request{Groups: []string{"ci:cache:admin"}, Prefixes: []string{"go-build/"}},
			wantErr: "2 grant rows still match",
		},
		{
			name: "rows differing only in permission: the OTHER permission resolves to the other row",
			req: Request{
				Groups: []string{"ci:cache:admin"}, Prefixes: []string{"go-build/"}, Permission: config.PermissionReadOnly,
			},
			want: Decision{
				Group: "ci:cache:admin", Bucket: "example-bucket", Prefixes: []string{"go-build/"},
				Permission: config.PermissionReadOnly, TTLSeconds: 120,
			},
		},
		{
			name:    "requested prefix widens past every reachable row",
			req:     Request{Groups: []string{"ci:cache:writer"}, Prefixes: []string{"../etc/"}},
			wantErr: "may narrow, never widen",
		},
		{
			name:    "requested prefixes span more than one row",
			req:     Request{Groups: []string{"ci:cache:writer"}, Prefixes: []string{"go-build/", "bazel-remote/"}},
			wantErr: "not all in any single grant row",
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

func TestDecideRequestedPermissionMatchingNothingIsRefused(t *testing.T) {
	// ci:cache:reader's only row is object-read-only; asking explicitly
	// for object-read-write must not fall back to it silently.
	_, err := Decide(Request{
		Groups: []string{"ci:cache:reader"}, Permission: config.PermissionReadWrite,
	}, testGrants)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match any grant row")
}

func TestMatchingGrantsPreservesConfigOrder(t *testing.T) {
	got := matchingGrants([]string{"ci:cache:reader", "ci:artifacts:writer"}, testGrants)
	require.Len(t, got, 2)
	assert.Equal(t, "ci:cache:reader", got[0].Group, "config order, not request order")
	assert.Equal(t, "ci:artifacts:writer", got[1].Group)
}

func TestSpansRows(t *testing.T) {
	rows := []config.Grant{
		{Prefixes: []string{"a/"}},
		{Prefixes: []string{"b/"}},
	}

	assert.True(t, spansRows(rows, []string{"a/", "b/"}), "both prefixes exist, just not on the same row")
	assert.False(t, spansRows(rows, []string{"a/", "c/"}), "c/ is nowhere — that's widening, not spanning")
}
