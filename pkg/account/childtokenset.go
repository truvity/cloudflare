package account

import (
	"fmt"
	"sort"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// NewChildTokenSet mints one child token per entry of cfgs and returns
// them keyed by the same name — the "one root token mints every
// least-privilege child a stack-per-token estate needs" pattern, made
// reusable instead of hand-written once per estate (see
// docs/layout.md#recommended-layout).
//
// It is a plain iteration convenience over NewChildToken, nothing more:
// for each key k (in the sorted order described below), it calls
//
//	NewChildToken(ctx, k, acct, cfgs[k], opts...)
//
// exactly as a caller would writing out one such call per child by hand.
// This is deliberate, and it is the whole reason NewChildTokenSet is safe
// to adopt onto an estate that already calls NewChildToken directly: name
// plays NO part in any minted resource's own Pulumi name — every
// resource's name, type and provider in Pulumi's state come entirely from
// cfgs' own keys and acct, precisely as they would from the equivalent
// hand-written calls. name exists only to prefix THIS function's own
// error messages, since a caller passing several sets (a root token
// feeding more than one family of children) may want to tell them apart
// in a failure. Migrating N hand-written NewChildToken calls onto one
// NewChildTokenSet call is therefore a ZERO-DIFF change in Pulumi's
// state, as long as cfgs' keys are exactly the names those calls already
// used — nothing is replaced, nothing is renamed, nothing new joins any
// URN.
//
// cfgs' keys are sorted (byte-wise, via sort.Strings) before minting, so
// two runs over the same map register resources in the same order —
// Pulumi's own dependency graph and any positional diagnostics see a
// stable sequence — regardless of Go's randomized map iteration. This
// is the same reason gitops's own cloudflare-root stack has always
// sorted its own zone and bucket names before looping over them (see
// pkg/r2 and this package's other callers); NewChildTokenSet only
// generalises that discipline into the library instead of asking every
// caller to remember it.
//
// A nil or empty cfgs mints nothing and returns an empty, non-nil map.
//
// Every ChildTokenConfig's own Validate (refusing "Account API Tokens"
// groups, an empty Policies list, an unrecognized Scope, and so on — see
// NewChildToken and docs/safety.md#pkgaccount) applies per entry,
// unchanged: NewChildTokenSet adds no validation and skips none. The
// first entry (in sorted order) that fails stops the whole set — nothing
// partially minted from one call is left registered when another entry
// in the same call fails validation, because Validate runs before
// NewChildToken registers anything for cfgs[k].
//
// NewChildTokenSet knows nothing about where the returned tokens are
// stored: exactly like NewChildToken, it returns each ChildToken's ID and
// secret Value and stops there. Delivering them to a consumer — a secret
// store, a chart, a Pulumi export — is the caller's job.
func NewChildTokenSet(
	ctx *pulumi.Context, name string, acct *Account, cfgs map[string]ChildTokenConfig, opts ...pulumi.ResourceOption,
) (map[string]*ChildToken, error) {
	out := make(map[string]*ChildToken, len(cfgs))

	keys := make([]string, 0, len(cfgs))
	for k := range cfgs {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	for _, k := range keys {
		child, err := NewChildToken(ctx, k, acct, cfgs[k], opts...)
		if err != nil {
			return nil, fmt.Errorf("account: child token set %q: child %q: %w", name, k, err)
		}

		out[k] = child
	}

	return out, nil
}

// EdgePolicies is the policy set for a "manage zones and run a tunnel"
// child: account-wide Cloudflare Tunnel management, plus DNS, SSL and
// Certificates, Zone Settings and Cache Settings on each zone in zoneIDs
// — the exact grant an estate's own edge stack (pkg/zone plus pkg/tunnel,
// scoped by account.Use()) needs to run as, and nothing more. See
// docs/layout.md#recommended-layout for where this fits.
//
// The permission-group names here are Cloudflare's own API names, which
// use "Write"/"Read" — confirmed live against the account's own
// getAccountApiTokenPermissionGroupsList, NOT the dashboard's "Edit"
// label for the same group (see NewChildToken's own by-name lookup,
// which resolves whichever name is passed here against that same list,
// so a caller who edits this list to add or drop a permission is checked
// exactly the same way).
func EdgePolicies(zoneIDs ...string) []ChildTokenPolicy {
	policies := make([]ChildTokenPolicy, 0, 1+len(zoneIDs))

	policies = append(policies, ChildTokenPolicy{
		PermissionGroups: []string{"Cloudflare Tunnel Write"},
		Scope:            WholeAccountScope{},
	})

	for _, zoneID := range zoneIDs {
		policies = append(policies, ChildTokenPolicy{
			PermissionGroups: []string{"DNS Write", "SSL and Certificates Write", "Zone Settings Write", "Cache Settings Write"},
			Scope:            ZoneScope{ZoneID: zoneID},
		})
	}

	return policies
}

// EdgePoliciesWithWAF is EdgePolicies plus the "Zone WAF Write" grant
// that pkg/zone's Args.TrustedClients needs to write its custom-firewall
// ruleset. It returns exactly what EdgePolicies(zoneIDs...) returns, then
// appends one more ZoneScope policy per entry of wafZoneIDs, in order,
// each granting only "Zone WAF Write" on that zone. wafZoneIDs is
// independent of zoneIDs (nothing is cross-checked), so list a zone in
// both when the same token also manages its DNS, settings and cache. An
// empty wafZoneIDs returns EdgePolicies(zoneIDs...) unchanged: the WAF
// grant is strictly opt-in, and EdgePolicies itself never includes it.
func EdgePoliciesWithWAF(wafZoneIDs []string, zoneIDs ...string) []ChildTokenPolicy {
	policies := EdgePolicies(zoneIDs...)

	for _, zoneID := range wafZoneIDs {
		policies = append(policies, ChildTokenPolicy{
			PermissionGroups: []string{"Zone WAF Write"},
			Scope:            ZoneScope{ZoneID: zoneID},
		})
	}

	return policies
}

// R2AdminPolicies is the policy set for an account-wide R2 administrator
// child: create, list and configure the lifecycle of every bucket on the
// account (Workers R2 Storage Write, WholeAccountScope). Pair it with
// pkg/r2's own New called with Config.Token.Enabled false — the bucket
// stack then runs on this child, and a bucket's own object-level
// credential comes from a separate R2BucketParentPolicies child instead
// of pkg/r2's deprecated Config.Token. See docs/layout.md#recommended-layout.
func R2AdminPolicies() []ChildTokenPolicy {
	return []ChildTokenPolicy{
		{PermissionGroups: []string{"Workers R2 Storage Write"}, Scope: WholeAccountScope{}},
	}
}

// R2BucketParentPolicies is the policy set for a bucket-scoped parent
// credential: object read and write on exactly one bucket (Workers R2
// Storage Bucket Item Write, R2BucketScope{Jurisdiction, Bucket}) — the
// same grant pkg/r2's own Config.Token mints inline when Enabled is true.
// Mint this from account.NewChildToken (or in a set, from
// NewChildTokenSet) instead of pkg/r2's Token once a bucket's consumer
// needs its own least-privilege credential kept apart from the bucket's
// own admin token; see pkg/r2's package doc and docs/layout.md#recommended-layout.
func R2BucketParentPolicies(jurisdiction, bucket string) []ChildTokenPolicy {
	return []ChildTokenPolicy{
		{
			PermissionGroups: []string{"Workers R2 Storage Bucket Item Write"},
			Scope:            R2BucketScope{Jurisdiction: jurisdiction, Bucket: bucket},
		},
	}
}
