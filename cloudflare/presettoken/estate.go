package presettoken

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"
)

// EstateBreakGlass is what an estate decides about its break-glass, apart from
// the item that holds an account's root (which is the account's).
type EstateBreakGlass struct {
	// Env switches every credential to the root when "1"; see
	// [BreakGlass.Env] for the name it must have.
	Env string
	// ItemEnv names the 1Password item of the root for one command: it
	// overrides the account's item, and is the only way to name one the
	// registry does not have yet. Optional.
	ItemEnv string
	// Account, Vault and Field are the 1Password account, vault and field of
	// the roots; the item is the account's.
	Account, Vault, Field string
	// ChildPrefix starts the name of every break-glass child.
	ChildPrefix string
	// ItemHint is where the estate writes an account's item, for the
	// refusal when break-glass is on and no item is known. It may hold one
	// %s, the account name ("accounts.%s.root_item in the registry").
	ItemHint string
}

// Estate is every fact of [Config] that is one estate's and the same for all of
// its accounts: build a Config per account with [Estate.Config].
type Estate struct {
	// SluisctlMin, BinaryPrefixes, Lifetime, GrantHint and Runbook are the
	// fields of Config of the same name.
	SluisctlMin    string
	BinaryPrefixes []string
	Lifetime       time.Duration
	GrantHint      string
	Runbook        string
	BreakGlass     EstateBreakGlass
}

// Config is the configuration of one account: the estate's, the issuer, and a
// complete break-glass block whenever the account's root item is known (item,
// or the variable [EstateBreakGlass.ItemEnv] over it), so a prototypes stack
// (which needs it) and a provider can share it. When no item is known,
// break-glass off is the zero block (the credential comes from sluis), and
// break-glass on is an error that names what to set. getenv reads the
// environment (os.Getenv in production).
func (e Estate) Config(accountName, item, issuer string, getenv func(string) string) (Config, error) {
	out := Config{
		Issuer:         issuer,
		SluisctlMin:    e.SluisctlMin,
		BinaryPrefixes: slices.Clone(e.BinaryPrefixes),
		Lifetime:       e.Lifetime,
		GrantHint:      e.GrantHint,
		Runbook:        e.Runbook,
	}

	bg := e.BreakGlass

	if bg.ItemEnv != "" {
		if v := getenv(bg.ItemEnv); v != "" {
			item = v
		}
	}

	switch {
	case item != "":
		out.BreakGlass = BreakGlass{
			Env: bg.Env, Account: bg.Account, Vault: bg.Vault,
			Item: item, Field: bg.Field, ChildPrefix: bg.ChildPrefix,
		}
	case bg.Env != "" && getenv(bg.Env) == "1":
		set := bg.ItemEnv + "=<item> for this command"
		if bg.ItemEnv == "" {
			set = "the item"
		}

		if bg.ItemHint != "" {
			set += ", or " + fmt.Sprintf(bg.ItemHint, accountName)
		}

		return Config{}, fmt.Errorf("break-glass for account %q: the 1Password item of its root token is not named: set %s", accountName, set)
	}

	return out, nil
}

// Credential is the credential of one preset's request: from sluis, or from
// break-glass with the request's own policies. The item and issuer are the
// account's (accountName names it in a refusal). A preset that hands out an API token must come back with one.
func (e Estate) Credential(ctx context.Context, src Source, accountName string, req Request, item, issuer string,
	getenv func(string) string) (Credential, error) {
	conf, err := e.Config(accountName, item, issuer, getenv)
	if err != nil {
		return Credential{}, err
	}

	cred, err := src.Token(ctx, conf, req)
	if err != nil {
		return Credential{}, fmt.Errorf("cloudflare preset %s: %w", req.Preset, err)
	}

	if !req.R2 && cred.Token == "" {
		return Credential{}, errors.New("cloudflare preset " + req.Preset + ": no token came back")
	}

	return cred, nil
}
