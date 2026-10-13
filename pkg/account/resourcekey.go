package account

import (
	"fmt"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// ResourceKey returns Cloudflare's resource key for scope in accountID: the
// name a token policy's Resources map grants against, the same key
// NewChildToken writes. It is for callers that build a policy outside Pulumi
// (a disabled prototype token, or a token minted through the API) and must
// spell exactly the key a child token would carry, instead of keeping a copy
// of the key templates.
//
// accountID is required for WholeAccountScope and R2BucketScope; a zone's key
// does not use it. A nil scope, or one this package does not define, is an
// error.
func ResourceKey(scope ChildTokenScope, accountID string) (string, error) {
	if scope == nil {
		return "", fmt.Errorf("account: resource key: scope is unset")
	}

	if err := scope.validate(); err != nil {
		return "", fmt.Errorf("account: resource key: %w", err)
	}

	if _, whole := scope.(WholeAccountScope); whole || isR2Bucket(scope) {
		if accountID == "" {
			return "", fmt.Errorf("account: resource key: accountID is required for this scope")
		}
	}

	return scope.resourceKey(accountID)
}

func isR2Bucket(scope ChildTokenScope) bool {
	_, ok := scope.(R2BucketScope)

	return ok
}

// LookupPermissionGroupID resolves a permission group of accountID by its
// exact display name ("DNS Write") to the id a policy needs, through the
// provider's account-scoped list. Zero or several exact matches are errors.
// It is the lookup NewChildToken uses, for callers that declare a token
// resource of their own (see pkg/prototypes); pass the explicit provider of
// the account as an invoke option, if there is one.
func LookupPermissionGroupID(ctx *pulumi.Context, accountID, name string, opts ...pulumi.InvokeOption) (string, error) {
	return lookupPermissionGroupID(ctx, accountID, name, opts...)
}
