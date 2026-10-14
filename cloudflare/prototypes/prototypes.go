// Package prototypes declares the DISABLED prototype tokens a sluis Cloudflare
// preset is cloned from: one account token per preset, whose policies are the
// preset's rights. sluis reads a prototype at every mint, refuses it unless
// it is disabled and grants nothing on its refusal list, and clones it into
// an account token that expires. cloudflare/presettoken is the other half: the
// client that asks sluis for the clone.
//
// THE ONLY STACK THAT RUNS AS THE ACCOUNT ROOT, and only in break-glass:
// creating, changing or disabling an account token needs Account API Tokens
// Write, which no preset may carry. It changes when a preset's rights change,
// which is rare and deliberate.
//
// THE ROOT NEVER ENTERS THE STATE. Every resource here uses the DEFAULT
// Cloudflare provider, and the root reaches that provider only through the
// environment of the `pulumi` process (CLOUDFLARE_API_TOKEN, set for that one
// command by a wrapper that reads it from the vault). An explicit provider
// records its apiToken as a (secret) input in the state and in every
// checkpoint of its history; the default provider's inputs are the stack's
// `cloudflare:*` config, and the provider reads CLOUDFLARE_API_TOKEN itself at
// Configure. So [Deploy] refuses to run with a credential or an endpoint in the
// provider's config (`cloudflare:apiToken`, `apiKey`, `apiUserServiceKey`,
// `baseUrl`), with a second credential or an endpoint override in the
// environment, and outside break-glass, and it never reads the token's value: it only checks
// that one is there. A stack that runs this must allow the default provider
// (a stack that lists cloudflare in disable-default-providers cannot).
//
// DISABLED AT CREATION IS IGNORED BY CLOUDFLARE: a token created with status
// disabled comes back active. Apply again with --refresh (the refresh sees it
// and the update disables it) and check every prototype's status (the
// StatusOutputPrefix outputs show Pulumi's view; ask Cloudflare for the
// truth) before an id goes into the sluis
// configuration. sluis refuses an active prototype at every mint besides.
//
// Each prototype is protected: its id is in the sluis configuration, and a
// replaced prototype is a new id every mint of the preset then fails on.
package prototypes

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"

	cf "github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/edge/v3/cloudflare/account"
	"github.com/truvity/edge/v3/cloudflare/presettoken"
)

const (
	// Status is the only status a prototype may have.
	Status = "disabled"

	// RootEnv carries the root to the default provider (and nothing else).
	RootEnv = "CLOUDFLARE_API_TOKEN"

	// ResourcePrefix starts every prototype's Pulumi name: "prototype-<preset>".
	// The name is an id in the state: it is not a parameter.
	ResourcePrefix = "prototype-"

	// IDsOutput is the stack output mapping preset to prototype token id.
	IDsOutput = "sluisPrototypeIds"
	// StatusOutputPrefix starts the per-preset output of a prototype's
	// status: "sluisPrototypeStatus_<preset>".
	StatusOutputPrefix = "sluisPrototypeStatus_"

	// DefaultMovedKey is the stack config key (in the project's namespace)
	// that says Args.Moved were moved here.
	DefaultMovedKey = "stateMoved"
)

// conflictingEnv would make the default provider authenticate otherwise.
// An endpoint override is one: the root would be sent where the environment
// says.
var conflictingEnv = []string{
	"CLOUDFLARE_API_KEY", "CLOUDFLARE_EMAIL", "CLOUDFLARE_API_USER_SERVICE_KEY",
	"CLOUDFLARE_BASE_URL", "CLOUDFLARE_API_BASE_URL",
}

// rootConfig are the stack config keys that would put a credential in the
// state through the default provider's inputs.
// (or the root's destination, `baseUrl`) in the state.
var rootConfig = []string{"cloudflare:apiToken", "cloudflare:apiKey", "cloudflare:apiUserServiceKey", "cloudflare:baseUrl"}

// Preset is one sluis preset and its prototype.
type Preset struct {
	// Name is the sluis preset name: the Pulumi name is "prototype-<Name>"
	// and the token's name Args.NamePrefix + Name.
	Name string
	// Policies are what every token minted from the preset may do. None may
	// carry Account API Tokens (account.ChildTokenConfig.Validate refuses it,
	// as sluis does).
	Policies []account.ChildTokenPolicy
}

// Args is the stack's declaration.
type Args struct {
	// AccountID is the Cloudflare account the prototypes live in.
	AccountID string
	// Presets are the prototypes to declare, by unique name.
	Presets []Preset
	// NamePrefix starts every token's name in Cloudflare, e.g.
	// "<estate>-prototype-". Required: the name is how a person finds the
	// token in the dashboard.
	NamePrefix string
	// BreakGlass is the estate's break-glass configuration: Env says the
	// stack runs as the root. Required, with Env set.
	BreakGlass presettoken.BreakGlass
	// Moved are prototypes that already exist elsewhere (another stack's
	// state) and are moved here with `pulumi state move`. The gate is
	// CONDITIONAL: it applies only while Moved is non-empty, so an estate with
	// nothing to move (a fresh account) lists none and has no gate at all; an
	// estate that does list some must keep the list until the move is done and
	// the config key is set. While any is listed, Deploy refuses to declare anything until the stack config
	// "<project>:<MovedKey>" is "true": a preview before the move would
	// CREATE second copies with new ids. Empty on a fresh account.
	Moved []string
	// MovedKey replaces DefaultMovedKey.
	MovedKey string
	// Options returns extra resource options for one preset's token, appended
	// after the protection every prototype has: an Alias to keep the URN of a
	// prototype that was declared under another name or parent, an
	// IgnoreChanges. Optional.
	Options func(preset string) []pulumi.ResourceOption
}

// Validate reports the first problem with the declaration, without a Pulumi
// context.
func (a Args) Validate() error {
	if !presettoken.ValidAccountID(a.AccountID) {
		return fmt.Errorf("prototypes: account id %q is not a 32-character lowercase hex string", a.AccountID)
	}

	if a.NamePrefix == "" {
		return errors.New("prototypes: NamePrefix is required")
	}

	if a.BreakGlass.Env == "" {
		return errors.New("prototypes: BreakGlass.Env is required: the stack runs as the account root, which is break-glass only")
	}

	if err := a.BreakGlass.Validate(); err != nil {
		return fmt.Errorf("prototypes: %w", err)
	}

	if len(a.Presets) == 0 {
		return errors.New("prototypes: no presets")
	}

	seen := map[string]bool{}

	for _, p := range a.Presets {
		if !presettoken.ValidPresetName(p.Name) {
			return fmt.Errorf("prototypes: preset name %q must be lowercase letters, digits and hyphens, 1-63 characters, starting with a letter or digit", p.Name)
		}

		if seen[p.Name] {
			return fmt.Errorf("prototypes: preset %q is declared twice", p.Name)
		}

		seen[p.Name] = true

		cfg := account.ChildTokenConfig{Name: p.Name, Policies: p.Policies}
		if err := cfg.Validate(); err != nil {
			return fmt.Errorf("prototypes: preset %q: %w", p.Name, err)
		}

		for i, pol := range p.Policies {
			if _, err := account.ResourceKey(pol.Scope, a.AccountID); err != nil {
				return fmt.Errorf("prototypes: preset %q: policy %d: %w", p.Name, i, err)
			}
		}
	}

	for _, m := range a.Moved {
		if !seen[m] {
			return fmt.Errorf("prototypes: moved preset %q is not in Presets", m)
		}
	}

	return nil
}

// Deploy declares the stack: one disabled, protected account token per
// preset, in sorted order, and exports their ids and statuses. It returns the
// tokens by preset name.
func Deploy(ctx *pulumi.Context, args Args) (map[string]*cf.AccountToken, error) {
	if err := args.Validate(); err != nil {
		return nil, err
	}

	if len(args.Moved) > 0 {
		key := args.MovedKey
		if key == "" {
			key = DefaultMovedKey
		}

		if v, _ := ctx.GetConfig(ctx.Project() + ":" + key); v != "true" {
			return nil, fmt.Errorf("prototypes: refusing to declare %v before they are moved here: "+
				"run `pulumi state move`, then `pulumi config set %s true --stack %s` (on a fresh account, set it with nothing to move)",
				args.Moved, key, ctx.Stack())
		}
	}

	if err := requireRoot(ctx, args.BreakGlass); err != nil {
		return nil, err
	}

	presets := slices.Clone(args.Presets)
	slices.SortFunc(presets, func(a, b Preset) int { return cmp.Compare(a.Name, b.Name) })

	tokens := make(map[string]*cf.AccountToken, len(presets))
	ids := pulumi.StringMap{}

	for _, p := range presets {
		tok, err := declare(ctx, args, p)
		if err != nil {
			return nil, err
		}

		tokens[p.Name] = tok
		ids[p.Name] = tok.ID().ToStringOutput()
		ctx.Export(StatusOutputPrefix+p.Name, tok.Status)
	}

	ctx.Export(IDsOutput, ids)

	return tokens, nil
}

func declare(ctx *pulumi.Context, args Args, p Preset) (*cf.AccountToken, error) {
	policies := make(cf.AccountTokenPolicyArray, 0, len(p.Policies))

	for i, pol := range p.Policies {
		groups := make(cf.AccountTokenPolicyPermissionGroupArray, 0, len(pol.PermissionGroups))

		for _, name := range pol.PermissionGroups {
			id, err := account.LookupPermissionGroupID(ctx, args.AccountID, name)
			if err != nil {
				return nil, fmt.Errorf("prototype %s: policy %d: %w", p.Name, i, err)
			}

			groups = append(groups, &cf.AccountTokenPolicyPermissionGroupArgs{Id: pulumi.String(id)})
		}

		key, err := account.ResourceKey(pol.Scope, args.AccountID)
		if err != nil {
			return nil, fmt.Errorf("prototype %s: policy %d: %w", p.Name, i, err)
		}

		resources, err := json.Marshal(map[string]string{key: "*"})
		if err != nil {
			return nil, err
		}

		policies = append(policies, &cf.AccountTokenPolicyArgs{
			Effect:           pulumi.String("allow"),
			PermissionGroups: groups,
			Resources:        pulumi.String(resources),
		})
	}

	opts := []pulumi.ResourceOption{pulumi.Protect(true)}
	if args.Options != nil {
		opts = append(opts, args.Options(p.Name)...)
	}

	tok, err := cf.NewAccountToken(ctx, ResourcePrefix+p.Name, &cf.AccountTokenArgs{
		AccountId: pulumi.String(args.AccountID),
		Name:      pulumi.String(args.NamePrefix + p.Name),
		Status:    pulumi.String(Status),
		Policies:  policies,
	}, opts...)
	if err != nil {
		return nil, fmt.Errorf("prototype %s: %w", p.Name, err)
	}

	return tok, nil
}

// requireRoot refuses to run unless break-glass is on and the root reaches the
// default provider through the environment only.
func requireRoot(ctx *pulumi.Context, bg presettoken.BreakGlass) error {
	if !bg.Enabled() {
		return fmt.Errorf("prototypes run as the account root, which is break-glass only: "+
			"use the estate's break-glass wrapper (it sets %s=1 and %s for that command)", bg.Env, RootEnv)
	}

	return checkRootEnvironment(bg, os.Getenv, func(key string) (string, bool) { return ctx.GetConfig(key) })
}

// checkRootEnvironment is requireRoot less the context, for tests.
func checkRootEnvironment(bg presettoken.BreakGlass, env func(string) string, config func(string) (string, bool)) error {
	if env(RootEnv) == "" {
		return fmt.Errorf("prototypes: %s is not set: run through the estate's break-glass wrapper (%s)", RootEnv, bg.Env)
	}

	for _, name := range conflictingEnv {
		if env(name) != "" {
			return fmt.Errorf("prototypes: %s is set; unset it (the root is the one credential here)", name)
		}
	}

	for _, key := range rootConfig {
		if v, ok := config(key); ok && v != "" {
			return fmt.Errorf("prototypes: the stack config sets %s, which the state would keep: `pulumi config rm %s`", key, key)
		}
	}

	return nil
}
