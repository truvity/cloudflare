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
//
// NewChildToken, in childtoken.go, mints a least-privilege, account-owned
// Cloudflare API token scoped to exactly one resource — a zone, the whole
// account, or (the scope pkg/r2 uses) one R2 bucket — under the root,
// account-owned token this whole module's caller runs as. See its own doc
// and docs/safety.md#child-tokens-never-hold-account-api-tokens.
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

// Invoke is Use's invoke-side counterpart: the option that binds a plain
// data-source lookup (a ctx.Invoke, or a generated Lookup*/Get* call) to
// this account's provider.
//
// A component RESOURCE inherits its parent's provider automatically —
// that is what makes Use() enough for everything this module registers
// as a resource. A plain invoke does not: with no explicit provider (and
// no parent already carrying one), it falls back to the default
// Cloudflare provider, which an estate that disables that default (as
// gitops does, so every Cloudflare call is accountable to a named
// account) cannot satisfy — the failure this method exists to prevent.
// Pass it explicitly to any Lookup*/Get* call this module or a caller
// makes directly:
//
//	res, err := cloudflare.LookupSomething(ctx, args, acct.Invoke())
func (a *Account) Invoke() pulumi.InvokeOption {
	return pulumi.Provider(a.Provider)
}

// InvokeOptionsFromResourceOptions extracts the explicit Cloudflare
// provider passed via opts — pulumi.Provider(...), or Account.Use() —
// and returns it as an InvokeOption slice, empty (never nil-containing)
// if opts carried none.
//
// A package whose New builds both resources and a plain data-source
// lookup from the same opts (pkg/r2's permission-group lookup, pkg/
// tunnel's token lookup) cannot rely on resource-to-parent provider
// inheritance for the lookup the way it can for a child resource — see
// Invoke's doc. Splice this into the Lookup/Get call instead, so it
// resolves the SAME provider the component's own resources do:
//
//	invokeOpts, err := account.InvokeOptionsFromResourceOptions(opts...)
//	...
//	res, err := cloudflare.LookupSomething(ctx, args, invokeOpts...)
//
// Nil opts, or opts with no explicit provider, resolve to an empty
// slice: the lookup then falls back to the default provider, exactly as
// the resources built from the same opts would.
func InvokeOptionsFromResourceOptions(opts ...pulumi.ResourceOption) ([]pulumi.InvokeOption, error) {
	ro, err := pulumi.NewResourceOptions(opts...)
	if err != nil {
		return nil, fmt.Errorf("resolving provider from resource options: %w", err)
	}

	if ro.Provider == nil {
		return nil, nil
	}

	return []pulumi.InvokeOption{pulumi.Provider(ro.Provider)}, nil
}
