// Package r2 provisions one R2 bucket, its optional expiry lifecycle, and
// an ACCOUNT-OWNED API token scoped to EXACTLY that bucket — plus the
// S3-compatible credential pair Cloudflare derives from that token, so a
// consumer does not have to re-implement the derivation itself.
//
// The token is account-owned (`cloudflare.AccountToken`,
// `/accounts/{account_id}/tokens`), not a user token
// (`cloudflare.ApiToken`, `/user/tokens`): an account-owned token is not
// tied to a person who might leave the estate, and it is what the
// provisioning token this package's own caller runs as is scoped to
// create — see "Provisioning permissions" below.
//
// The library's contract, shared by every public truvity module:
//
//   - Mechanism only. Nothing here knows an account id or a bucket name;
//     Config is a plain yaml-taggable struct a consumer unmarshals its own
//     config into.
//   - Credentials come in, secrets go out. The Cloudflare provider is the
//     caller's (pass it via pulumi.Provider, or account.Use() from this
//     module's account package). The parent token is created HERE — R2's
//     temporary-credential mechanisms need a parent token's id and value
//     to mint from — and its value, and everything derived from it, is
//     returned as a secret Output. Where it is stored (Pulumi config, a
//     Kubernetes Secret, OpenBAO) is the caller's decision; this package
//     creates no secret store entry.
//   - Refuse, never sanitize. A bucket name, permission or expiry outside
//     what Cloudflare accepts is refused by Validate before anything is
//     registered, not quietly corrected.
//
// # The token's scope
//
// The policy's Resources map names exactly one resource key, Cloudflare's
// own name for "this one bucket" —
// `com.cloudflare.edge.r2.bucket.<ACCOUNT_ID>_<JURISDICTION>_<BUCKET_NAME>`,
// jurisdiction "default" for a non-jurisdictional bucket — confirmed
// against https://developers.cloudflare.com/r2/api/tokens/#permissions
// (accessed 2026-09-27). A token this package creates can therefore never
// reach a second bucket, however Config changes.
//
// The permission group named in the policy is looked up BY NAME through
// the provider's ACCOUNT-scoped `getAccountApiTokenPermissionGroupsList`
// data source at apply time, never hard-coded as an id: ids are
// per-account, so a hard-coded one silently either grants nothing (wrong
// account) or the wrong grant. The two names this package knows, confirmed
// against https://developers.cloudflare.com/r2/api/tokens/#permissions
// (accessed 2026-09-27; R2 is listed as compatible with account-owned
// tokens on
// https://developers.cloudflare.com/fundamentals/api/get-started/account-owned-tokens/,
// same date): "Workers R2 Storage Bucket Item Write" (read, write and
// list on objects in the named bucket) for TokenConfig.Permission
// "object-read-write", and "Workers R2 Storage Bucket Item Read" (read
// and list) for "object-read-only". These are distinct from "Workers R2
// Storage Bucket Write"/"…Bucket Read", names that do not appear on that
// page as of the date above; TokenConfig.PermissionGroupName overrides
// the lookup if Cloudflare renames a group before this package catches
// up, or if a given account's list ever disagrees with the name above —
// New fails loudly with the name it looked up rather than silently
// falling back to something broader.
//
// Since v2.4.0, the mechanics of minting that token — resolving the
// permission group by name (with the account's explicit Cloudflare
// provider carried into the lookup invoke, never the default one), naming
// the bucket's resource key, and forcing a REPLACE on a Rotation change —
// live in `pkg/account`'s `NewChildToken`, generalised out of what this
// package originally did inline so any future caller can mint a
// similarly least-privilege token scoped to a zone or a whole account,
// not only to an R2 bucket. This package keeps only what is genuinely R2's
// own business: which permission group name a Permission level maps to,
// and the bucket resource key's shape (`account.R2BucketScope`, still the
// same key documented above). Nothing about Config, New's signature or
// R2's outputs changed for this package's own callers.
//
// # Provisioning permissions
//
// The Cloudflare API token this package's OWN caller (the Pulumi program)
// runs as needs, on the account being managed: "Account API Tokens Write"
// to create and manage the account-owned token, and "Workers R2 Storage
// Write" to create the bucket and its lifecycle and to read the account's
// own permission-group list — both the account's own
// getAccountApiTokenPermissionGroupsList names, confirmed live, never the
// dashboard's own (differently worded) labels for the same grants. Both
// are Accepted Permissions on the generated
// `cloudflare.AccountToken`/`cloudflare.R2Bucket` resources themselves
// (see their doc comments in this package's vendored `pulumi-cloudflare`
// SDK).
//
// # Deprecated: Config.Token
//
// Config.Token — a bucket-scoped parent token minted inline by this same
// component — is deprecated since v2.6.0. Mint it separately instead,
// with `account.NewChildToken` (one bucket) or `account.NewChildTokenSet`
// (several children, including this one, from one root token) and
// `account.R2BucketParentPolicies(cfg.Jurisdiction, cfg.Bucket)` — the
// same permission group and the same resource key Config.Token has always
// used — then call New with Token.Enabled false. See
// docs/layout.md#recommended-layout for why: a bucket's own admin token
// (`account.R2AdminPolicies`, account-wide) and a consumer's object-level
// token are two different blast radii and two different rotation
// schedules, and bundling the second into the component that creates the
// bucket makes that separation harder to see, not easier. Config.Token
// itself is unchanged and keeps working; removing it is a major version.
//
// # Rotation
//
// TokenConfig.Rotation is not a Cloudflare field. `account.NewChildToken`
// embeds it into the token's Cloudflare-visible Name (an actual, mutable
// field: account-owned tokens, like user tokens, support renaming without
// regenerating the token — Cloudflare's update endpoint for both changes
// name, policies, status and dates in place, never the secret value,
// which only a fresh create produces) and sets
// pulumi.ReplaceOnChanges("name") on the token resource, telling Pulumi to
// treat that change as a replacement rather than an update regardless of
// what the provider's own diff would otherwise do: the old token is
// deleted and a new one created, so its id and value are genuinely fresh.
// This holds independently of whichever way the generated `AccountToken`
// resource's own diff treats Name — the vendored SDK ships no
// ForceNew/replace metadata for either token resource to inspect, so
// neither package relies on it either way. Nothing else changes Name, so
// nothing else triggers a rotation by accident. A caller asks for a
// rotation declaratively by changing Rotation to any new value (a date, a
// counter, a reason) — the value itself has no meaning here beyond
// "different from before".
package r2

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/cloudflare/v2/pkg/account"
	"github.com/truvity/cloudflare/v2/pkg/cfnames"
)

// Permission levels TokenConfig.Permission accepts.
const (
	PermissionObjectReadWrite = "object-read-write"
	PermissionObjectReadOnly  = "object-read-only"
)

// defaultPermissionGroup maps a Permission to Cloudflare's own name for the
// permission group that grants it, scoped by the policy's Resources map to
// the one bucket this component owns. See the package doc for the
// citation and the caveat about near-identical names.
var defaultPermissionGroup = map[string]string{
	PermissionObjectReadWrite: "Workers R2 Storage Bucket Item Write",
	PermissionObjectReadOnly:  "Workers R2 Storage Bucket Item Read",
}

// r2Jurisdictions is this package's own display copy of cfnames.
// Jurisdictions, for Validate's error message only — the actual check
// calls account.ValidR2Jurisdiction (which itself delegates to
// pkg/cfnames), the single source of truth account.R2BucketScope also
// validates against, so a bucket this package accepts can never be
// refused again when its token's scope is built. The message skips ""
// and "default": an estate picking a jurisdiction is choosing one of the
// three real ones, and listing "none" next to them would read oddly.
var r2Jurisdictions = cfnames.Jurisdictions()[2:]

type (
	// Lifecycle expires objects after a fixed age. Every field is a
	// choice an estate makes explicitly; there is no lifecycle unless
	// Config.Lifecycle is set.
	Lifecycle struct {
		// ExpireAfterDays is the object age, in days, at which R2
		// deletes it. Required when Lifecycle is set; must be positive.
		ExpireAfterDays int `json:"expireAfterDays" yaml:"expireAfterDays"`
		// Prefix restricts the rule to objects whose key starts with
		// it. Empty applies to every object in the bucket.
		Prefix string `json:"prefix,omitempty" yaml:"prefix,omitempty"`
	}

	// TokenConfig is the parent API token this package creates, scoped to
	// exactly one bucket. Enabled is required to be explicit: a bucket
	// with no token block is a bucket this package does not hand out
	// credentials for at all.
	//
	// Deprecated: see Config.Token's own doc for the replacement
	// (account.NewChildToken/NewChildTokenSet plus
	// account.R2BucketParentPolicies) and why this stays rather than
	// being removed.
	TokenConfig struct {
		// Enabled turns the token on. False creates the bucket (and its
		// lifecycle, if set) and nothing else; every Token* and
		// S3* output resolves to an empty string.
		Enabled bool `json:"enabled" yaml:"enabled"`
		// Permission is PermissionObjectReadWrite or
		// PermissionObjectReadOnly. Required when Enabled.
		Permission string `json:"permission,omitempty" yaml:"permission,omitempty"`
		// ExpiresOn is an RFC3339 timestamp after which Cloudflare
		// refuses the token. Optional; for a scratch or test token that
		// should not outlive its errand. Must be in the future.
		ExpiresOn string `json:"expiresOn,omitempty" yaml:"expiresOn,omitempty"`
		// Rotation forces a fresh token — a new id and value — when
		// changed to any new value. See the package doc. Optional; empty
		// never rotates on its own.
		Rotation string `json:"rotation,omitempty" yaml:"rotation,omitempty"`
		// PermissionGroupName overrides the permission group name looked
		// up for Permission (see the package doc). Empty uses the
		// documented default for Permission.
		PermissionGroupName string `json:"permissionGroupName,omitempty" yaml:"permissionGroupName,omitempty"`
	}

	// Config is one bucket and its parent token.
	Config struct {
		// AccountID owning the bucket. Required — normally
		// account.Account.AccountID, with the provider bound via
		// account.Use() in opts.
		AccountID string `json:"accountId" yaml:"accountId"`
		// Bucket is the R2 bucket name. Required; must be a name
		// Cloudflare's own rules accept (see Validate).
		Bucket string `json:"bucket" yaml:"bucket"`
		// Jurisdiction is the bucket's data-residency jurisdiction:
		// "eu", "fedramp" or "us". Empty (or "default") is an ordinary,
		// non-jurisdictional bucket. It also selects the segment used
		// when scoping the token's policy to this bucket (see the
		// package doc), so the bucket and its token can never disagree
		// about which jurisdiction they mean.
		Jurisdiction string `json:"jurisdiction,omitempty" yaml:"jurisdiction,omitempty"`
		// Lifecycle expires objects after a fixed age. Nil creates none.
		Lifecycle *Lifecycle `json:"lifecycle,omitempty" yaml:"lifecycle,omitempty"`
		// Token is the parent API token scoped to this bucket.
		//
		// Deprecated: mint the bucket's parent token separately instead,
		// with account.NewChildToken (a single bucket) or
		// account.NewChildTokenSet (several children at once, including
		// this one) and account.R2BucketParentPolicies(cfg.Jurisdiction,
		// cfg.Bucket) — the exact same permission group and resource key
		// this field has always used — then call New with Token.Enabled
		// false. This keeps a bucket's admin credential (account.
		// R2AdminPolicies, scoped to the whole account) and its consumers'
		// object-level credentials on separate tokens with separate
		// rotation, the shape docs/layout.md#recommended-layout
		// describes, rather than bundling one bucket-scoped token into the
		// same component that creates the bucket. Left in place, not
		// removed: removing a field is a major version
		// (docs/reference.md#child-names-are-a-contract's own rule for
		// child names applies just as much to a Config field a caller's
		// YAML already sets), and Token keeps working exactly as before.
		Token TokenConfig `json:"token" yaml:"token"`
	}

	// R2 is the component: one bucket, its optional lifecycle, and its
	// optional parent token.
	R2 struct {
		pulumi.ResourceState

		Bucket    *cloudflare.R2Bucket
		Lifecycle *cloudflare.R2BucketLifecycle
		Token     *cloudflare.AccountToken

		// BucketName as created.
		BucketName pulumi.StringOutput `pulumi:"bucketName"`
		// TokenID is the parent token's id. Empty when Token.Enabled is
		// false.
		TokenID pulumi.StringOutput `pulumi:"tokenId"`
		// TokenValue is the parent token's secret value. Secret. Empty
		// when Token.Enabled is false.
		TokenValue pulumi.StringOutput `pulumi:"tokenValue"`
		// S3AccessKeyID equals TokenID: Cloudflare's R2-to-S3 credential
		// mapping uses the token id as the access key id
		// (https://developers.cloudflare.com/r2/api/s3/tokens/, accessed
		// 2026-09-27: "Access Key ID: The `id` of the API token."). The
		// same page describes account-owned tokens as a token type in its
		// own right ("Create Account API token") without restricting this
		// mapping to user tokens, and an account-owned token's id and
		// value are the same two fields (`AccountToken.ID()`,
		// `AccountToken.Value`) a user token has, so the mapping holds
		// unchanged.
		S3AccessKeyID pulumi.StringOutput `pulumi:"s3AccessKeyId"`
		// S3SecretAccessKey is the SHA-256 hash of TokenValue, hex
		// encoded — the same page: "Secret Access Key: The SHA-256 hash
		// of the API token `value`." Computed here so a caller never
		// re-implements the derivation. Secret. Empty when Token.Enabled
		// is false.
		S3SecretAccessKey pulumi.StringOutput `pulumi:"s3SecretAccessKey"`
		// S3Endpoint is this account's R2 S3-compatible endpoint.
		S3Endpoint pulumi.StringOutput `pulumi:"s3Endpoint"`
	}
)

func oneOf(value string, allowed []string) bool {
	for _, a := range allowed {
		if value == a {
			return true
		}
	}

	return false
}

// rotationValid restricts Rotation to a charset safe to embed in
// Cloudflare's token Name field without surprises.
func rotationValid(value string) bool {
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '-':
		default:
			return false
		}
	}

	return true
}

// Validate reports the first problem with cfg.
func (cfg *Config) Validate() error {
	if cfg.AccountID == "" {
		return fmt.Errorf("r2: accountId is required")
	}

	if cfg.Bucket == "" {
		return fmt.Errorf("r2: bucket is required")
	}

	// Delegated to account.ValidR2BucketName / account.ValidR2Jurisdiction
	// — the SAME functions account.R2BucketScope validates against when
	// this package builds its token's scope below, so a bucket accepted
	// here can never be refused again once Token.Enabled asks for a
	// child token scoped to it.
	if !account.ValidR2BucketName(cfg.Bucket) {
		return fmt.Errorf("r2 %q: bucket must be 3-63 characters of lowercase letters, digits and hyphens, and may not start or end with a hyphen", cfg.Bucket)
	}

	if !account.ValidR2Jurisdiction(cfg.Jurisdiction) {
		return fmt.Errorf("r2 %q: jurisdiction %q must be one of %v", cfg.Bucket, cfg.Jurisdiction, r2Jurisdictions)
	}

	if cfg.Lifecycle != nil && cfg.Lifecycle.ExpireAfterDays <= 0 {
		return fmt.Errorf("r2 %q: lifecycle.expireAfterDays must be greater than zero — omit lifecycle instead of declaring one that expires nothing", cfg.Bucket)
	}

	if cfg.Token.Enabled {
		if !oneOf(cfg.Token.Permission, []string{PermissionObjectReadWrite, PermissionObjectReadOnly}) {
			return fmt.Errorf("r2 %q: token.permission %q must be one of %q, %q", cfg.Bucket, cfg.Token.Permission, PermissionObjectReadWrite, PermissionObjectReadOnly)
		}

		if cfg.Token.ExpiresOn != "" {
			t, err := time.Parse(time.RFC3339, cfg.Token.ExpiresOn)
			if err != nil {
				return fmt.Errorf("r2 %q: token.expiresOn %q is not RFC3339: %w", cfg.Bucket, cfg.Token.ExpiresOn, err)
			}

			if !t.After(time.Now()) {
				return fmt.Errorf("r2 %q: token.expiresOn %q must be in the future", cfg.Bucket, cfg.Token.ExpiresOn)
			}
		}

		if !rotationValid(cfg.Token.Rotation) {
			return fmt.Errorf("r2 %q: token.rotation %q must contain only letters, digits, '.', '_' or '-'", cfg.Bucket, cfg.Token.Rotation)
		}
	}

	return nil
}

// permissionGroupName resolves the name to look up for cfg.Token: the
// override if given, else the documented default for Permission.
func permissionGroupName(tok TokenConfig) string {
	if tok.PermissionGroupName != "" {
		return tok.PermissionGroupName
	}

	return defaultPermissionGroup[tok.Permission]
}

// accountFromOptions rebuilds the account.Account this package's own New
// takes as an AccountID string plus opts (account.Use()) rather than as
// an *account.Account value directly: account.NewChildToken needs one, to
// resolve its permission-group lookup's explicit provider and to bind the
// same provider on the token resource it registers (an invoke does not
// inherit a parent's provider the way a child resource does — see
// account.InvokeOptionsFromResourceOptions's doc, which this replaces for
// this package's own use).
//
// A nil Provider (opts carried none) round-trips faithfully:
// account.NewChildToken then makes the SAME no-explicit-provider lookup
// this package has always made in that case, which TestPermissionGroup
// LookupWithNoExplicitProviderFails still catches.
func accountFromOptions(accountID string, opts ...pulumi.ResourceOption) (*account.Account, error) {
	ro, err := pulumi.NewResourceOptions(opts...)
	if err != nil {
		return nil, fmt.Errorf("resolving provider from resource options: %w", err)
	}

	provider, _ := ro.Provider.(*cloudflare.Provider)

	return &account.Account{AccountID: accountID, Provider: provider}, nil
}

// New provisions the bucket, its optional lifecycle, and its optional
// parent token. Children are named "bucket-<name>", "lifecycle-<name>" and
// "token-<name>" — a documented contract: consumers alias existing
// resources onto these names.
func New(ctx *pulumi.Context, name string, cfg Config, opts ...pulumi.ResourceOption) (*R2, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	comp := &R2{}
	if err := ctx.RegisterComponentResource("truvity:cloudflare:R2", name, comp, opts...); err != nil {
		return nil, err
	}

	child := []pulumi.ResourceOption{pulumi.Parent(comp)}

	bucketArgs := &cloudflare.R2BucketArgs{
		AccountId: pulumi.String(cfg.AccountID),
		Name:      pulumi.String(cfg.Bucket),
	}
	if cfg.Jurisdiction != "" && cfg.Jurisdiction != "default" {
		bucketArgs.Jurisdiction = pulumi.String(cfg.Jurisdiction)
	}

	bucket, err := cloudflare.NewR2Bucket(ctx, "bucket-"+name, bucketArgs, child...)
	if err != nil {
		return nil, fmt.Errorf("r2 %q: bucket: %w", cfg.Bucket, err)
	}

	comp.Bucket = bucket
	comp.BucketName = bucket.Name

	if cfg.Lifecycle != nil {
		lifecycle, err := cloudflare.NewR2BucketLifecycle(ctx, "lifecycle-"+name, &cloudflare.R2BucketLifecycleArgs{
			AccountId:  pulumi.String(cfg.AccountID),
			BucketName: bucket.Name,
			Rules: cloudflare.R2BucketLifecycleRuleArray{
				&cloudflare.R2BucketLifecycleRuleArgs{
					Id:      pulumi.String(fmt.Sprintf("expire-after-%dd", cfg.Lifecycle.ExpireAfterDays)),
					Enabled: pulumi.Bool(true),
					Conditions: &cloudflare.R2BucketLifecycleRuleConditionsArgs{
						Prefix: pulumi.String(cfg.Lifecycle.Prefix),
					},
					DeleteObjectsTransition: &cloudflare.R2BucketLifecycleRuleDeleteObjectsTransitionArgs{
						Condition: &cloudflare.R2BucketLifecycleRuleDeleteObjectsTransitionConditionArgs{
							// Age is in seconds; Config takes days.
							MaxAge: pulumi.Int(cfg.Lifecycle.ExpireAfterDays * 86400),
							Type:   pulumi.String("Age"),
						},
					},
				},
			},
		}, child...)
		if err != nil {
			return nil, fmt.Errorf("r2 %q: lifecycle: %w", cfg.Bucket, err)
		}

		comp.Lifecycle = lifecycle
	}

	if cfg.Token.Enabled {
		acct, err := accountFromOptions(cfg.AccountID, opts...)
		if err != nil {
			return nil, fmt.Errorf("r2 %q: token: %w", cfg.Bucket, err)
		}

		// The bucket's own token minting is account.NewChildToken's job
		// since v2.4.0 (see the package doc): permission-group-by-name
		// resolution, the resource-key shape and the Rotation-forces-
		// REPLACE mechanism all live there now, generalised out of what
		// this package used to do inline. What stays here is R2's own
		// business only — which permission group name a Permission level
		// maps to (permissionGroupName) and the bucket resource key's
		// shape (account.R2BucketScope, still the key documented above).
		ct, err := account.NewChildToken(ctx, "token-"+name, acct, account.ChildTokenConfig{
			Name:      "r2-" + cfg.Bucket,
			Rotation:  cfg.Token.Rotation,
			ExpiresOn: cfg.Token.ExpiresOn,
			Policies: []account.ChildTokenPolicy{
				{
					PermissionGroups: []string{permissionGroupName(cfg.Token)},
					Scope: account.R2BucketScope{
						Jurisdiction: cfg.Jurisdiction,
						Bucket:       cfg.Bucket,
					},
				},
			},
		}, child...)
		if err != nil {
			return nil, fmt.Errorf("r2 %q: token: %w", cfg.Bucket, err)
		}

		comp.Token = ct.Token
		comp.TokenID = ct.ID
		comp.TokenValue = ct.Value
		comp.S3AccessKeyID = comp.TokenID
		comp.S3SecretAccessKey = pulumi.ToSecret(ct.Token.Value.ApplyT(func(v string) string {
			sum := sha256.Sum256([]byte(v))

			return hex.EncodeToString(sum[:])
		}).(pulumi.StringOutput)).(pulumi.StringOutput)
	} else {
		comp.TokenID = pulumi.String("").ToStringOutput()
		comp.TokenValue = pulumi.ToSecret(pulumi.String("")).(pulumi.StringOutput)
		comp.S3AccessKeyID = comp.TokenID
		comp.S3SecretAccessKey = pulumi.ToSecret(pulumi.String("")).(pulumi.StringOutput)
	}

	comp.S3Endpoint = pulumi.String(fmt.Sprintf("https://%s.r2.cloudflarestorage.com", cfg.AccountID)).ToStringOutput()

	if err := ctx.RegisterResourceOutputs(comp, pulumi.Map{
		"bucketName":        comp.BucketName,
		"tokenId":           comp.TokenID,
		"tokenValue":        comp.TokenValue,
		"s3AccessKeyId":     comp.S3AccessKeyID,
		"s3SecretAccessKey": comp.S3SecretAccessKey,
		"s3Endpoint":        comp.S3Endpoint,
	}); err != nil {
		return nil, err
	}

	return comp, nil
}
