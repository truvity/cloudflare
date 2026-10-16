// Package r2 provisions one R2 bucket and its optional expiry lifecycle.
//
// It mints no credentials. A bucket's parent token (the one R2's
// temporary-credential mechanisms mint from, and whose id and SHA-256 hashed
// value are the S3 credential pair) is minted separately, with
// `account.NewChildToken` (one bucket) or `account.NewChildTokenSet` (several
// children from one root token) and `account.R2BucketParentPolicies(
// jurisdiction, bucket)`. That keeps a bucket's admin credential (account-wide)
// and its consumers' object-level credentials on separate tokens with separate
// rotation; see docs/cloudflare/layout.md#recommended-layout. Until v4.0.0 this
// package could mint that token inline (`Config.Token`); that path is removed.
//
// The library's contract, shared by every public truvity module:
//
//   - Mechanism only. Nothing here knows an account id or a bucket name;
//     Config is a plain yaml-taggable struct a consumer unmarshals its own
//     config into.
//   - Credentials come in. The Cloudflare provider is the caller's (pass it
//     via pulumi.Provider, or account.Use() from this module's account
//     package).
//   - Refuse, never sanitize. A bucket name, jurisdiction or expiry outside
//     what Cloudflare accepts is refused by Validate before anything is
//     registered, not quietly corrected.
//
// # Provisioning permissions
//
// The Cloudflare API token this package's OWN caller (the Pulumi program)
// runs as needs "Workers R2 Storage Write" on the account being managed, to
// create the bucket and its lifecycle (the account's own
// getAccountApiTokenPermissionGroupsList name, never the dashboard's label).
package r2

import (
	"fmt"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/edge/v4/cloudflare/account"
	"github.com/truvity/edge/v4/cloudflare/cfnames"
)

// r2Jurisdictions is this package's own display copy of cfnames.
// Jurisdictions, for Validate's error message only — the actual check
// calls account.ValidR2Jurisdiction (which itself delegates to
// cloudflare/cfnames), the single source of truth account.R2BucketScope also
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

	// Config is one bucket.
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
		// non-jurisdictional bucket.
		Jurisdiction string `json:"jurisdiction,omitempty" yaml:"jurisdiction,omitempty"`
		// Lifecycle expires objects after a fixed age. Nil creates none.
		Lifecycle *Lifecycle `json:"lifecycle,omitempty" yaml:"lifecycle,omitempty"`
	}

	// R2 is the component: one bucket and its optional lifecycle.
	R2 struct {
		pulumi.ResourceState

		Bucket    *cloudflare.R2Bucket
		Lifecycle *cloudflare.R2BucketLifecycle

		// BucketName as created.
		BucketName pulumi.StringOutput `pulumi:"bucketName"`
		// S3Endpoint is this account's R2 S3-compatible endpoint.
		S3Endpoint pulumi.StringOutput `pulumi:"s3Endpoint"`
	}
)

// Validate reports the first problem with cfg.
func (cfg *Config) Validate() error {
	if cfg.AccountID == "" {
		return fmt.Errorf("r2: accountId is required")
	}

	if cfg.Bucket == "" {
		return fmt.Errorf("r2: bucket is required")
	}

	// Delegated to account.ValidR2BucketName / account.ValidR2Jurisdiction,
	// the same functions account.R2BucketScope validates against, so a
	// bucket accepted here is one a separately minted token can be scoped
	// to.
	if !account.ValidR2BucketName(cfg.Bucket) {
		return fmt.Errorf("r2 %q: bucket must be 3-63 characters of lowercase letters, digits and hyphens, and may not start or end with a hyphen", cfg.Bucket)
	}

	if !account.ValidR2Jurisdiction(cfg.Jurisdiction) {
		return fmt.Errorf("r2 %q: jurisdiction %q must be one of %v", cfg.Bucket, cfg.Jurisdiction, r2Jurisdictions)
	}

	if cfg.Lifecycle != nil && cfg.Lifecycle.ExpireAfterDays <= 0 {
		return fmt.Errorf("r2 %q: lifecycle.expireAfterDays must be greater than zero — omit lifecycle instead of declaring one that expires nothing", cfg.Bucket)
	}

	return nil
}

// New provisions the bucket and its optional lifecycle. Children are named
// "bucket-<name>" and "lifecycle-<name>": a documented contract (consumers
// alias existing resources onto these names).
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

	comp.S3Endpoint = pulumi.String(fmt.Sprintf("https://%s.r2.cloudflarestorage.com", cfg.AccountID)).ToStringOutput()

	if err := ctx.RegisterResourceOutputs(comp, pulumi.Map{
		"bucketName": comp.BucketName,
		"s3Endpoint": comp.S3Endpoint,
	}); err != nil {
		return nil, err
	}

	return comp, nil
}
