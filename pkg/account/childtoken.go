package account

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// The two permission groups a child token this package mints must never
// carry: they are what lets a token itself create and manage other
// tokens, so granting one to a child token would let it mint its own
// siblings — or its own replacement after this program stops managing it.
// Only the root token this whole module's caller runs as should ever hold
// either. See docs/safety.md#child-tokens-never-hold-account-api-tokens.
const (
	permissionAccountAPITokensRead  = "Account API Tokens Read"
	permissionAccountAPITokensWrite = "Account API Tokens Write"
)

// zoneIDPattern is Cloudflare's own zone identifier shape: 32 lowercase
// hex characters. Confirmed against
// https://developers.cloudflare.com/api/resources/zones/ (accessed
// 2026-09-28): the `zone_id` path parameter is documented with
// `maxLength: 32`, and every example value on that page and its sibling
// endpoint pages ("506e3185e9c882d175a2d0cb0093d9f2", and so on) is a
// 32-character lowercase hex string — the same shape as an account id.
var zoneIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

func zoneIDValid(id string) bool {
	return zoneIDPattern.MatchString(id)
}

// r2Jurisdictions are the values R2BucketScope.Jurisdiction accepts,
// mirroring pkg/r2's own bucket jurisdictions (see pkg/r2's Config.
// Jurisdiction) so the two can never disagree about what a bucket's
// jurisdiction may be.
var r2Jurisdictions = []string{"", "default", "eu", "fedramp", "us"}

// ValidR2Jurisdiction reports whether jurisdiction is one R2BucketScope
// (and pkg/r2's own Config.Jurisdiction) accepts: "" or "default" for a
// non-jurisdictional bucket, or "eu", "fedramp", "us".
func ValidR2Jurisdiction(jurisdiction string) bool {
	return slices.Contains(r2Jurisdictions, jurisdiction)
}

// ValidR2BucketName reports whether name follows Cloudflare's R2 bucket
// naming rules: https://developers.cloudflare.com/r2/buckets/create-buckets/
// (accessed 2026-09-27) — "Bucket names can only contain lowercase letters
// (a-z), numbers (0-9), and hyphens (-)", "cannot begin or end with a
// hyphen", "3-63 characters in length". The single source of truth for
// this rule: pkg/r2's own Config.Bucket validation calls this too, so a
// bucket name and the R2BucketScope naming its own token's resource key
// can never disagree about what Cloudflare accepts.
func ValidR2BucketName(name string) bool {
	if len(name) < 3 || len(name) > 63 {
		return false
	}

	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-':
			if i == 0 || i == len(name)-1 {
				return false
			}
		default:
			return false
		}
	}

	return true
}

// rotationValid restricts ChildTokenConfig.Rotation to a charset safe to
// embed in Cloudflare's token Name field without surprises. Mirrors
// pkg/r2's own TokenConfig.Rotation rule (see r2's rotationValid) — the
// two are not the same function only because pkg/r2 imports this package,
// never the other way, so there is nowhere shared to hang one copy other
// than accepting this small, purely-syntactic duplication.
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

type (
	// ChildTokenScope names the ONE Cloudflare resource a ChildTokenPolicy's
	// permission groups apply to — Cloudflare's own "resource key" concept
	// (https://developers.cloudflare.com/fundamentals/api/how-to/create-via-api/,
	// accessed 2026-09-28). Its methods are unexported, so only a type
	// defined in this package can implement it: a caller cannot spell a
	// scope this package has not reviewed, and a nil Scope is the only way
	// ChildTokenConfig.Validate can see an "unknown" one.
	ChildTokenScope interface {
		// validate reports the first problem with the scope's own fields,
		// before an account id is known.
		validate() error
		// resourceKey returns the resource key naming this scope for
		// accountID, Cloudflare's own name for the resource a token
		// policy's Resources map grants against.
		resourceKey(accountID string) (string, error)
	}

	// WholeAccountScope scopes a policy's permission groups to the WHOLE
	// account: every zone and every account-level resource it owns. This
	// is the correct (and only) scope for a permission group the
	// permissions reference lists as account-scoped only (for example
	// "AI Gateway Read"/"Run"/"Edit" — see
	// https://developers.cloudflare.com/fundamentals/api/reference/permissions/,
	// accessed 2026-09-28), since such a group has no narrower resource
	// key to be scoped to at all.
	WholeAccountScope struct{}

	// ZoneScope scopes a policy's permission groups to exactly one zone.
	ZoneScope struct {
		// ZoneID the policy is scoped to. Required; Cloudflare's own zone
		// ids are 32-character lowercase hex strings (see zoneIDPattern).
		ZoneID string
	}

	// R2BucketScope scopes a policy's permission groups to exactly one R2
	// bucket — the same resource key pkg/r2 mints its own bucket token
	// with (see pkg/r2's package doc and docs/safety.md#pkgr2).
	R2BucketScope struct {
		// Jurisdiction segments the resource key exactly as it segments
		// the bucket itself; empty (or "default") is an ordinary,
		// non-jurisdictional bucket. See ValidR2Jurisdiction.
		Jurisdiction string
		// Bucket is the R2 bucket name. See ValidR2BucketName.
		Bucket string
	}

	// ChildTokenPolicy is one policy of a child token: the permission
	// groups it grants, over the one resource its Scope names. Cloudflare
	// evaluates every policy on a token with effect "allow" as pure
	// addition — the token can do the union of what its policies grant —
	// so there is no ordering between a ChildTokenConfig's Policies and no
	// way for one to narrow another; keep unrelated grants in unrelated
	// policies for clarity, not because it changes what the token can do.
	ChildTokenPolicy struct {
		// PermissionGroups this policy grants, each resolved BY NAME
		// against the account's own permission-group list at apply time
		// (see lookupPermissionGroupID) — never a hard-coded id, which is
		// per-account. Required, non-empty; neither
		// "Account API Tokens Read" nor "Account API Tokens Write" may
		// appear here (see the constants above).
		PermissionGroups []string
		// Scope is the one resource PermissionGroups applies to. Required.
		// One of WholeAccountScope{}, ZoneScope{...} or R2BucketScope{...}.
		Scope ChildTokenScope
	}

	// ChildTokenConfig is a child token this package mints under the
	// account's own root token — see New's own doc and
	// docs/safety.md#child-tokens-never-hold-account-api-tokens for what
	// "child" means here.
	ChildTokenConfig struct {
		// Name is the token's Cloudflare-visible Name. Required. When
		// Rotation is set, New embeds it into the Cloudflare-visible name
		// as "<Name>-<Rotation>" — see Rotation.
		Name string
		// Rotation forces a fresh token — a new id and value — when
		// changed to any new value; see New's doc and
		// docs/safety.md#rotation-is-a-replace-not-an-update (the same
		// mechanism pkg/r2's TokenConfig.Rotation already uses). Optional;
		// empty never rotates on its own.
		Rotation string
		// ExpiresOn is an RFC3339 timestamp after which Cloudflare refuses
		// the token. Optional; must be in the future when set.
		ExpiresOn string
		// Policies this token grants. Required, non-empty: a token with
		// no policy is a token that will be minted holding nothing,
		// which is never what a caller means to ask for.
		Policies []ChildTokenPolicy
	}

	// ChildToken is the account-owned Cloudflare API token New mints.
	//
	// It is deliberately NOT a Pulumi component resource: New registers
	// exactly one resource (the cloudflare.AccountToken below), and
	// wrapping a single resource in a component nobody else addresses
	// would only add a name to the resource graph — the same reasoning
	// Account itself documents for why it is not a component either. The
	// AccountToken is registered directly under whatever Parent (or none)
	// the caller's own opts give New, so a caller that already owns a
	// component (pkg/r2's R2, for instance) keeps that resource as ITS
	// OWN direct child — its type and name in Pulumi's state are exactly
	// what they would be had the caller registered the AccountToken
	// itself, which is what makes pkg/r2's refactor onto this function
	// invisible to an existing deployment: no new parent type joins the
	// URN, so nothing is replaced.
	ChildToken struct {
		// Token is the underlying resource, for a caller that needs more
		// than ID and Value (Status, IssuedOn, and so on).
		Token *cloudflare.AccountToken

		// ID is the child token's id.
		ID pulumi.StringOutput
		// Value is the child token's secret value. Secret.
		Value pulumi.StringOutput
	}
)

func (WholeAccountScope) validate() error { return nil }

// resourceKey: "com.cloudflare.api.account.<ACCOUNT_ID>", confirmed
// against
// https://developers.cloudflare.com/fundamentals/api/how-to/create-via-api/
// (accessed 2026-09-28), which shows this exact template scoping a policy
// to one whole account.
func (WholeAccountScope) resourceKey(accountID string) (string, error) {
	return fmt.Sprintf("com.cloudflare.api.account.%s", accountID), nil
}

func (s ZoneScope) validate() error {
	if !zoneIDValid(s.ZoneID) {
		return fmt.Errorf("zone scope: zoneId %q must be a 32-character lowercase hex string", s.ZoneID)
	}

	return nil
}

// resourceKey: "com.cloudflare.api.account.zone.<ZONE_ID>", confirmed
// against the same
// https://developers.cloudflare.com/fundamentals/api/how-to/create-via-api/
// page (accessed 2026-09-28), which shows this exact template scoping a
// policy to one zone. The account id plays no part in a zone's own
// resource key — a zone id is already globally unique — so it is accepted
// and ignored here, exactly as pkg/r2's own bucket resource key (which
// DOES need the account id, since a bucket name is only unique within its
// account) takes it.
func (s ZoneScope) resourceKey(string) (string, error) {
	return fmt.Sprintf("com.cloudflare.api.account.zone.%s", s.ZoneID), nil
}

func (s R2BucketScope) validate() error {
	if !ValidR2BucketName(s.Bucket) {
		return fmt.Errorf("r2 bucket scope: bucket %q must be 3-63 characters of lowercase letters, digits and hyphens, "+
			"and may not start or end with a hyphen", s.Bucket)
	}

	if !ValidR2Jurisdiction(s.Jurisdiction) {
		return fmt.Errorf("r2 bucket scope: jurisdiction %q must be one of %q", s.Jurisdiction, r2Jurisdictions[1:])
	}

	return nil
}

// resourceKey: "com.cloudflare.edge.r2.bucket.<ACCOUNT_ID>_<JURISDICTION>_<BUCKET_NAME>",
// jurisdiction "default" for a non-jurisdictional bucket — confirmed
// against https://developers.cloudflare.com/r2/api/tokens/#permissions
// (accessed 2026-09-27; see pkg/r2's own package doc, which cites the
// same page for the same key). This is pkg/r2's pre-existing resource
// key, generalised here so any caller — not just pkg/r2 — can scope a
// child token to one bucket.
func (s R2BucketScope) resourceKey(accountID string) (string, error) {
	jurisdiction := s.Jurisdiction
	if jurisdiction == "" {
		jurisdiction = "default"
	}

	return fmt.Sprintf("com.cloudflare.edge.r2.bucket.%s_%s_%s", accountID, jurisdiction, s.Bucket), nil
}

// Validate reports the first problem with cfg. New calls this before
// registering anything.
func (cfg *ChildTokenConfig) Validate() error {
	if cfg.Name == "" {
		return fmt.Errorf("account: child token: name is required")
	}

	if len(cfg.Policies) == 0 {
		return fmt.Errorf("account: child token: at least one policy is required — a token with no policy holds nothing")
	}

	for i, p := range cfg.Policies {
		if len(p.PermissionGroups) == 0 {
			return fmt.Errorf("account: child token: policy %d: at least one permission group is required", i)
		}

		for _, g := range p.PermissionGroups {
			if g == "" {
				return fmt.Errorf("account: child token: policy %d: a permission group name must not be empty", i)
			}

			if g == permissionAccountAPITokensRead || g == permissionAccountAPITokensWrite {
				return fmt.Errorf("account: child token: policy %d: permission group %q must never be granted to a child token — "+
					"only the root token that mints child tokens may hold it", i, g)
			}
		}

		if p.Scope == nil {
			return fmt.Errorf("account: child token: policy %d: scope is unset or unknown — pass account.WholeAccountScope{}, "+
				"account.ZoneScope{...} or account.R2BucketScope{...}", i)
		}

		if err := p.Scope.validate(); err != nil {
			return fmt.Errorf("account: child token: policy %d: %w", i, err)
		}
	}

	if cfg.ExpiresOn != "" {
		t, err := time.Parse(time.RFC3339, cfg.ExpiresOn)
		if err != nil {
			return fmt.Errorf("account: child token: expiresOn %q is not RFC3339: %w", cfg.ExpiresOn, err)
		}

		if !t.After(time.Now()) {
			return fmt.Errorf("account: child token: expiresOn %q must be in the future", cfg.ExpiresOn)
		}
	}

	if !rotationValid(cfg.Rotation) {
		return fmt.Errorf("account: child token: rotation %q must contain only letters, digits, '.', '_' or '-'", cfg.Rotation)
	}

	return nil
}

// lookupPermissionGroupID resolves groupName to its id for acct's account,
// via the provider's ACCOUNT-scoped getAccountApiTokenPermissionGroupsList
// data source — never a hard-coded id (per-account, so a hard-coded one
// would either grant nothing or the wrong thing under a different
// account) and never the global, non-account-scoped list (an
// account-owned token's own permission groups are looked up per account
// it belongs to).
//
// The Name filter is passed PLAIN, never pre-encoded: the generated SDK's
// doc comment ("the value must be URL-encoded") describes the raw
// Cloudflare REST parameter, but the provider builds and encodes the HTTP
// query itself from this Go-level string argument. A pre-encoded name
// (e.g. spaces as "%20") is therefore encoded a second time on the wire
// ("%20" becomes "%2520"), Cloudflare filters by that literal garbage
// string, and the lookup finds nothing even when the token has the
// permission — confirmed live against pkg/r2's own original copy of this
// function (fixed in cloudflare v2.3.1): a preview with the name
// pre-encoded sent
// `?name=Workers%2520R2%2520Storage%2520Bucket%2520Item%2520Write` and
// got a 403 back, not merely an empty result.
//
// Cloudflare's Name filter is not documented as an exact match, so the
// result is matched EXACTLY, client side, against every entry the list
// returns: zero exact matches or more than one is refused with a clear
// error rather than guessed at (e.g. by taking the first).
//
// invokeOpts carries the explicit Cloudflare provider New resolves from
// acct — an invoke does not inherit one from a parent component the way a
// child resource does, so without this the lookup falls back to the
// default Cloudflare provider regardless of what acct names, which fails
// outright wherever that default is disabled (see
// docs/safety.md#an-invoke-does-not-inherit-a-provider-the-way-a-resource-does).
func lookupPermissionGroupID(ctx *pulumi.Context, accountID, groupName string, invokeOpts ...pulumi.InvokeOption) (string, error) {
	res, err := cloudflare.LookupAccountApiTokenPermissionGroupsList(ctx, &cloudflare.LookupAccountApiTokenPermissionGroupsListArgs{
		AccountId: &accountID,
		Name:      &groupName,
	}, invokeOpts...)
	if err != nil {
		return "", fmt.Errorf("permission group %q: %w", groupName, err)
	}

	var matches []string
	for _, r := range res.Results {
		if r.Name == groupName {
			matches = append(matches, r.Id)
		}
	}

	switch len(matches) {
	case 0:
		return "", fmt.Errorf("permission group %q: not found via getAccountApiTokenPermissionGroupsList for account %q — "+
			"check the exact name Cloudflare uses today", groupName, accountID)
	case 1:
		return matches[0], nil
	default:
		return "", fmt.Errorf("permission group %q: %d exact matches via getAccountApiTokenPermissionGroupsList for account %q — "+
			"ambiguous, Cloudflare has more than one group of this exact name on this account", groupName, len(matches), accountID)
	}
}

// NewChildToken mints one account-owned Cloudflare API token
// (cloudflare.AccountToken, /accounts/{account_id}/tokens — not a user
// token, which is tied to a person who might leave) scoped to exactly
// cfg.Policies, under acct's account and provider. See ChildToken's own
// doc for why the result is a plain struct, not a component.
//
// name is the Pulumi resource name the underlying AccountToken is
// registered under — pass opts (Parent, in particular) the same way you
// would to any other resource this account's provider owns; acct.Use()
// needs no separate mention in opts, because NewChildToken binds acct's
// own provider explicitly on both the resource and the permission-group
// lookup invoke (see lookupPermissionGroupID's doc for why the invoke
// needs its own, explicit copy).
//
// A change to cfg.Rotation is a REPLACE, never an in-place rename: see
// docs/safety.md#rotation-is-a-replace-not-an-update. Nothing else in
// ChildTokenConfig triggers one.
func NewChildToken(ctx *pulumi.Context, name string, acct *Account, cfg ChildTokenConfig, opts ...pulumi.ResourceOption) (*ChildToken, error) {
	if acct == nil {
		return nil, fmt.Errorf("account: child token %q: acct is required", name)
	}

	if acct.AccountID == "" {
		return nil, fmt.Errorf("account: child token %q: acct.AccountID is required", name)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("account: child token %q: %w", name, err)
	}

	// An invoke does not inherit a provider from a parent resource the
	// way a child resource does (see lookupPermissionGroupID's doc), so
	// it is bound explicitly here from acct rather than left to whatever
	// opts happens to carry. A nil acct.Provider (acct built with none)
	// makes this an empty slice, which is the SAME "no explicit
	// provider" invoke pkg/r2 has always made when its own caller passed
	// none — still refused by a Cloudflare account whose default
	// provider is disabled, exactly as it always was.
	var invokeOpts []pulumi.InvokeOption
	if acct.Provider != nil {
		invokeOpts = []pulumi.InvokeOption{pulumi.Provider(acct.Provider)}
	}

	policies := make(cloudflare.AccountTokenPolicyArray, 0, len(cfg.Policies))

	for i, p := range cfg.Policies {
		groups := make(cloudflare.AccountTokenPolicyPermissionGroupArray, 0, len(p.PermissionGroups))

		for _, groupName := range p.PermissionGroups {
			id, err := lookupPermissionGroupID(ctx, acct.AccountID, groupName, invokeOpts...)
			if err != nil {
				return nil, fmt.Errorf("account: child token %q: policy %d: %w", name, i, err)
			}

			groups = append(groups, &cloudflare.AccountTokenPolicyPermissionGroupArgs{Id: pulumi.String(id)})
		}

		key, err := p.Scope.resourceKey(acct.AccountID)
		if err != nil {
			return nil, fmt.Errorf("account: child token %q: policy %d: %w", name, i, err)
		}

		resources, err := json.Marshal(map[string]string{key: "*"})
		if err != nil {
			return nil, fmt.Errorf("account: child token %q: policy %d: %w", name, i, err)
		}

		policies = append(policies, &cloudflare.AccountTokenPolicyArgs{
			Effect:           pulumi.String("allow"),
			PermissionGroups: groups,
			Resources:        pulumi.String(string(resources)),
		})
	}

	// The rotation marker lives in the Cloudflare-visible Name so that
	// ReplaceOnChanges("name") below has something real to react to —
	// see docs/safety.md#rotation-is-a-replace-not-an-update.
	tokenName := cfg.Name
	if cfg.Rotation != "" {
		tokenName = tokenName + "-" + cfg.Rotation
	}

	tokenArgs := &cloudflare.AccountTokenArgs{
		AccountId: pulumi.String(acct.AccountID),
		Name:      pulumi.String(tokenName),
		Policies:  policies,
	}
	if cfg.ExpiresOn != "" {
		tokenArgs.ExpiresOn = pulumi.String(cfg.ExpiresOn)
	}

	resourceOpts := append([]pulumi.ResourceOption{}, opts...)
	if acct.Provider != nil {
		// acct is the authority on which provider this token belongs to,
		// so it is bound explicitly rather than left to Parent-based
		// inheritance alone — the same resource, same provider, whether
		// or not the caller's own opts already carry one (harmless
		// either way: acct.Provider is that caller's own provider too,
		// whenever the caller follows the documented acct.Use() pattern).
		resourceOpts = append(resourceOpts, pulumi.Provider(acct.Provider))
	}

	// A Name change is otherwise an in-place UPDATE (Cloudflare's
	// account-token update endpoint changes name/policies/status/dates
	// without touching id or value): force a REPLACE instead, so a
	// Rotation change actually mints a new id and value rather than
	// relabeling the old ones. See
	// docs/safety.md#rotation-is-a-replace-not-an-update.
	resourceOpts = append(resourceOpts, pulumi.ReplaceOnChanges([]string{"name"}))

	token, err := cloudflare.NewAccountToken(ctx, name, tokenArgs, resourceOpts...)
	if err != nil {
		return nil, fmt.Errorf("account: child token %q: %w", name, err)
	}

	return &ChildToken{
		Token: token,
		ID:    token.ID().ToStringOutput(),
		Value: pulumi.ToSecret(token.Value).(pulumi.StringOutput),
	}, nil
}
