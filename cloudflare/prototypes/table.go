package prototypes

import (
	"fmt"

	cf "github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/edge/v4/cloudflare/presets"
	"github.com/truvity/edge/v4/cloudflare/presettoken"
)

// Table is a prototypes stack over the table of cloudflare/presets: the stack
// of ONE account declares the prototype of each of that account's presets.
type Table struct {
	// Account is the account the stack serves (its name in the table).
	Account string
	// Presets is the whole table; only Account's are declared.
	Presets []presets.Preset
	// Estate, Item and Getenv give the break-glass block ([presettoken.Estate.Config]):
	// Item is the account's 1Password item of its root, and may be empty when
	// the estate's item variable names it for one command.
	Estate presettoken.Estate
	Item   string
	Getenv func(string) string
	// NamePrefix, Moved, MovedKey and Options are [Args]'.
	NamePrefix string
	Moved      []string
	MovedKey   string
	Options    func(preset string) []pulumi.ResourceOption
}

// FromPresets converts the presets of one account to the stack's declaration,
// in table order. It fails when the account has none: a stack with nothing to
// declare is a mistake in the table, not an empty stack.
func FromPresets(table []presets.Preset, accountName string) (accountID string, out []Preset, err error) {
	for i := range table {
		p := &table[i]
		if p.Account != accountName {
			continue
		}

		accountID = p.AccountID
		out = append(out, Preset{Name: p.Name, Policies: p.Policies})
	}

	if len(out) == 0 {
		return "", nil, fmt.Errorf("the table has no preset of account %s", accountName)
	}

	return accountID, out, nil
}

// DeployTable is the entry point of an account's prototypes stack: it checks
// that the estate names the 1Password item of the account's root (this stack
// runs as the root, which is break-glass only) before anything, then declares
// the account's presets through [Deploy]. Resource names, token names and
// policy order are those of [Deploy]: "prototype-<preset>", NamePrefix+preset,
// and the preset's own order.
func DeployTable(ctx *pulumi.Context, t Table) (map[string]*cf.AccountToken, error) {
	getenv := t.Getenv
	if getenv == nil {
		return nil, fmt.Errorf("%s: Getenv is required (os.Getenv in production)", ctx.Stack())
	}

	conf, err := t.Estate.Config(t.Account, t.Item, "", getenv)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ctx.Stack(), err)
	}

	if conf.BreakGlass.Env == "" {
		set := "the item"
		if t.Estate.BreakGlass.ItemEnv != "" {
			set = t.Estate.BreakGlass.ItemEnv + "=<item> for this command"
		}

		if h := t.Estate.BreakGlass.ItemHint; h != "" {
			set += ", or " + fmt.Sprintf(h, t.Account)
		}

		return nil, fmt.Errorf("%s: this stack runs as the account root, which is break-glass only, and the 1Password item of the %s root "+
			"is not named: set %s", ctx.Stack(), t.Account, set)
	}

	accountID, ps, err := FromPresets(t.Presets, t.Account)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ctx.Stack(), err)
	}

	return Deploy(ctx, Args{
		AccountID: accountID, Presets: ps, NamePrefix: t.NamePrefix, BreakGlass: conf.BreakGlass,
		Moved: t.Moved, MovedKey: t.MovedKey, Options: t.Options,
	})
}
