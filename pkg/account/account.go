// Package account binds one Cloudflare API token to one account, so an
// estate whose zones live in several accounts writes the account as data
// rather than as code.
//
// A Cloudflare token is account-scoped and a tunnel cannot cross accounts,
// so "which account" is a property of every resource, not a global. This
// package makes it one: a caller builds an Account per row of its own
// registry and passes acct.Use() to each component it creates there.
//
// The library's contract, shared by every public truvity module:
//
//   - Mechanism only. Nothing here knows an account id, a token value or a
//     zone; Args is a plain yaml-taggable struct a consumer unmarshals its
//     own config into, and the token arrives as an Input.
//   - Credentials come in, secrets go out. The token is a caller INPUT —
//     read from wherever the caller keeps secrets — and is marked secret
//     here so it never lands in plain state.
//   - No implicit scope. An Account configures a provider and nothing
//     else; it reads no zones, creates no records and changes no settings.
package account

import (
	"fmt"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// Args identifies one Cloudflare account.
type Args struct {
	// AccountID the token is scoped to. Required.
	AccountID string `json:"accountId" yaml:"accountId"`
	// BaseURL overrides the API endpoint. Empty means Cloudflare's own;
	// set it only for a proxy or a test double.
	BaseURL string `json:"baseUrl,omitempty" yaml:"baseUrl,omitempty"`
}

// Validate reports the first problem with args.
func (a *Args) Validate() error {
	if a.AccountID == "" {
		return fmt.Errorf("account: accountId is required")
	}

	return nil
}

// Account is a configured provider plus the account id its resources
// belong to. It is not a component: a provider has no children, and
// wrapping one would only add a name nobody refers to.
type Account struct {
	// AccountID as supplied, for resources that take it as an argument.
	AccountID string
	// Provider scoped to this account's token.
	Provider *cloudflare.Provider
}

// New configures a provider for one account. The child provider is named
// "provider-<name>", a documented contract: consumers alias existing
// resources onto these names.
func New(ctx *pulumi.Context, name string, args Args, token pulumi.StringInput, opts ...pulumi.ResourceOption) (*Account, error) {
	if err := args.Validate(); err != nil {
		return nil, err
	}

	if token == nil {
		return nil, fmt.Errorf("account %q: token is required — it is a caller input, never derived here", name)
	}

	pArgs := &cloudflare.ProviderArgs{
		ApiToken: pulumi.ToSecret(token).(pulumi.StringOutput),
	}
	if args.BaseURL != "" {
		pArgs.BaseUrl = pulumi.String(args.BaseURL)
	}

	provider, err := cloudflare.NewProvider(ctx, "provider-"+name, pArgs, opts...)
	if err != nil {
		return nil, fmt.Errorf("account %q: %w", name, err)
	}

	return &Account{AccountID: args.AccountID, Provider: provider}, nil
}

// Use is the resource option that binds a component to this account. It
// exists so a caller never has to remember which of several providers a
// given zone or tunnel belongs to:
//
//	tun, err := tunnel.New(ctx, name, args, secret, acct.Use())
func (a *Account) Use() pulumi.ResourceOption {
	return pulumi.Provider(a.Provider)
}
