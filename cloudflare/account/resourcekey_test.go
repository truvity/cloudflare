package account

import (
	"strings"
	"testing"
)

func TestResourceKey(t *testing.T) {
	const (
		acct = "0123456789abcdef0123456789abcdef"
		zone = "fedcba9876543210fedcba9876543210"
	)

	for _, tc := range []struct {
		name  string
		scope ChildTokenScope
		acct  string
		want  string
		err   string
	}{
		{"account", WholeAccountScope{}, acct, "com.cloudflare.api.account." + acct, ""},
		{"zone ignores the account", ZoneScope{ZoneID: zone}, "", "com.cloudflare.api.account.zone." + zone, ""},
		{"bucket default jurisdiction", R2BucketScope{Bucket: "logs-bucket"}, acct, "com.cloudflare.edge.r2.bucket." + acct + "_default_logs-bucket", ""},
		{"bucket eu", R2BucketScope{Bucket: "logs-bucket", Jurisdiction: "eu"}, acct, "com.cloudflare.edge.r2.bucket." + acct + "_eu_logs-bucket", ""},
		{"account without id", WholeAccountScope{}, "", "", "accountID is required"},
		{"bucket without id", R2BucketScope{Bucket: "logs-bucket"}, "", "", "accountID is required"},
		{"bad zone", ZoneScope{ZoneID: "nope"}, acct, "", "zoneId"},
		{"bad bucket", R2BucketScope{Bucket: "A"}, acct, "", "bucket"},
		{"nil", nil, acct, "", "unset"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResourceKey(tc.scope, tc.acct)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("got %v, want an error with %q", err, tc.err)
				}

				return
			}

			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}
