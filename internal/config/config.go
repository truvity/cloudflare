// Package config is the R2 credential broker's own configuration schema:
// the OIDC issuer it trusts, the account it mints into, and the group →
// grant map that decides what a caller may ask for.
//
// The library's contract, shared by every public truvity module:
//
//   - Mechanism only. Nothing here names a real issuer, account or
//     bucket; every field is a caller input with no default that would
//     leak one, and an estate supplies its own values from its own
//     (private) configuration.
//   - Group-only. A grant maps a group name to a bucket, a prefix list
//     and a permission — nothing else. There is deliberately no field
//     for a repository, a ref or an event name: that decision already
//     belongs to whatever OIDC issuer minted the token's groups claim,
//     and a claim-matching field here would let this broker start
//     deciding the same question a second, disagreeing way.
//   - Refuse rather than guess. Loading is strict (an unknown key fails
//     the load, it is not silently ignored) and Validate rejects
//     anything a broker could not safely act on: an empty group, an
//     unrecognized permission, a non-positive TTL, or two rows identical
//     in every field a request could disambiguate by (group, bucket,
//     prefixes, permission) that still disagree on how long a credential
//     from them should live.
package config

import (
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"unicode"

	"go.yaml.in/yaml/v3"
)

// Permission is the scope Cloudflare's temporary-credentials API grants a
// minted credential. Only the two non-admin values are accepted here: the
// broker mints credentials for a group a token carries, and an estate that
// wants to hand out admin-level R2 access should do so as a deliberate,
// separate decision rather than a value this config schema makes
// reachable by accident.
type Permission string

// The permissions this broker will ever mint. Cloudflare's API also
// accepts "admin-read-only" and "admin-read-write"
// (developers.cloudflare.com/r2/api/s3/temporary-credentials/); neither is
// valid in a grant row, on purpose.
const (
	PermissionReadOnly  Permission = "object-read-only"
	PermissionReadWrite Permission = "object-read-write"
)

// Valid reports whether p is one of the two permissions this broker mints.
func (p Permission) Valid() bool {
	switch p {
	case PermissionReadOnly, PermissionReadWrite:
		return true
	default:
		return false
	}
}

// MintMode selects how the broker builds a temporary credential.
type MintMode string

const (
	// MintModeLocal signs the credential itself (no Cloudflare API call);
	// the default. See internal/mint.
	MintModeLocal MintMode = "local"
	// MintModeAPI calls Cloudflare's temporary-credentials REST endpoint
	// for every mint. Used as LocalMinter's fallback, or set here to make
	// API mode the default for this installation.
	MintModeAPI MintMode = "api"
)

type (
	// Account identifies the Cloudflare account the broker mints into,
	// and where its parent API token's value comes from.
	Account struct {
		// ID is the Cloudflare account id. Exactly one of ID and IDFile
		// is required.
		ID string `yaml:"id,omitempty"`
		// IDFile is a path to a file holding the account id, resolved
		// into ID at Load time (see (*Config).resolveAccountFiles). Not
		// sensitive — see ID — but some estates keep it in the same
		// Secret as ParentTokenID/the parent token's value, one mount
		// instead of several; this field is how that Secret's key
		// reaches this config. Exactly one of ID and IDFile is required.
		IDFile string `yaml:"idFile,omitempty"`
		// ParentTokenID is the parent API token's OWN id — "Access Key
		// ID: the id of the API token"
		// (developers.cloudflare.com/r2/api/s3/tokens/). Exactly one of
		// ParentTokenID and ParentTokenIDFile is required. Unlike the
		// token's value, this is not sensitive (Cloudflare shows it in
		// the dashboard next to the token's name), so it is a plain
		// config field rather than a file/env indirection — but see
		// ParentTokenIDFile for the case where an estate still wants it
		// to come from the same Secret as ID or the token's value.
		ParentTokenID string `yaml:"parentTokenId,omitempty"`
		// ParentTokenIDFile is a path to a file holding ParentTokenID,
		// resolved the same way as IDFile. Exactly one of ParentTokenID
		// and ParentTokenIDFile is required.
		ParentTokenIDFile string `yaml:"parentTokenIdFile,omitempty"`
		// ParentTokenFile is a path to a file holding the parent token's
		// value. Exactly one of ParentTokenFile and ParentTokenEnv is
		// required — there is deliberately no field for the value
		// itself, so a token can never be pasted into this config.
		ParentTokenFile string `yaml:"parentTokenFile,omitempty"`
		// ParentTokenEnv is the name of an environment variable holding
		// the parent token's value. See ParentTokenFile.
		ParentTokenEnv string `yaml:"parentTokenEnv,omitempty"`
	}

	// Minting selects the broker's minting mode.
	Minting struct {
		// Mode is "local" (default) or "api". Empty means MintModeLocal.
		Mode MintMode `yaml:"mode,omitempty"`
	}

	// Grant maps one group to what a token carrying it may mint. A group
	// with several buckets is several rows.
	Grant struct {
		// Group is the exact value the broker looks for in the token's
		// groups claim. Required.
		Group string `yaml:"group"`
		// Bucket is the one bucket this grant scopes to — the
		// temporary-credentials API takes exactly one bucket per
		// credential. Required.
		Bucket string `yaml:"bucket"`
		// Prefixes this grant allows, passed to Cloudflare as the
		// request's own `prefixes` list. A request may narrow to a
		// subset of these; it may never widen past them. Empty means no
		// prefix restriction (the whole bucket, within Permission).
		Prefixes []string `yaml:"prefixes,omitempty"`
		// Permission minted for this grant. Required; must be one of
		// the two values Permission.Valid accepts.
		Permission Permission `yaml:"permission"`
		// TTLSeconds is how long a credential minted under this grant
		// lives. Required, must be > 0. Cloudflare's own docs give no
		// documented minimum, maximum or default
		// (developers.cloudflare.com/r2/api/s3/temporary-credentials/:
		// "Set ttlSeconds to the shortest value that fits your use
		// case"), so this schema enforces only "positive" until a real
		// upper bound is confirmed.
		TTLSeconds int `yaml:"ttlSeconds"`
	}

	// Config is the broker's whole configuration file.
	Config struct {
		// Issuer is the OIDC issuer URL the broker trusts. Required, no
		// default — a default here would be a particular this
		// repository cannot carry (see hack/leak-canary.sh).
		Issuer string `yaml:"issuer"`
		// Audience is the value the broker requires in a token's aud
		// claim. Required.
		Audience string `yaml:"audience"`
		// GroupsClaim names the claim carrying the token's group list.
		// Required.
		GroupsClaim string `yaml:"groupsClaim"`
		// Account the broker mints into.
		Account Account `yaml:"account"`
		// Minting mode. Zero value defaults to local at Load time.
		Minting Minting `yaml:"minting,omitempty"`
		// Grants this broker will act on. Empty renders a broker that
		// verifies tokens and refuses every request — a safe default,
		// not a load error.
		Grants []Grant `yaml:"grants,omitempty"`
	}
)

// Load decodes and validates a config from r. Loading is strict: a field
// this schema does not know about fails the load rather than being
// silently ignored, so a typo in a grant row is a load-time error, not a
// grant nobody notices is missing.
func Load(r io.Reader) (*Config, error) {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)

	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}

	if cfg.Minting.Mode == "" {
		cfg.Minting.Mode = MintModeLocal
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	if err := cfg.resolveAccountFiles(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// resolveAccountFiles fills Account.ID and Account.ParentTokenID from
// their *File counterparts when those are set. Validate has already
// confirmed exactly one source exists for each field before this runs
// (Load calls it first), so this only has to read whichever one is
// present — a caller that builds a Config some other way and wants the
// same resolution should call Validate then this, in that order, too.
func (c *Config) resolveAccountFiles() error {
	if c.Account.IDFile != "" {
		v, err := readTrimmedFile(c.Account.IDFile)
		if err != nil {
			return fmt.Errorf("config: account.idFile: %w", err)
		}

		c.Account.ID = v
	}

	if c.Account.ParentTokenIDFile != "" {
		v, err := readTrimmedFile(c.Account.ParentTokenIDFile)
		if err != nil {
			return fmt.Errorf("config: account.parentTokenIdFile: %w", err)
		}

		c.Account.ParentTokenID = v
	}

	return nil
}

// readTrimmedFile reads path and strips exactly one trailing newline
// ("\n", or "\r\n"): a value written by a tool that appends one trailing
// newline to whatever it mounts (a Secret's own default behavior for a
// literal value, an editor that adds one on save) would otherwise carry
// one character too many. Any OTHER whitespace — leading, embedded, or a
// second trailing newline — is refused rather than silently stripped: an
// account id or a token id is never legitimately padded, and guessing at
// what to trim would hide a mis-mounted file instead of failing on it.
func readTrimmedFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", path, err)
	}

	s := strings.TrimSuffix(string(data), "\n")
	s = strings.TrimSuffix(s, "\r")

	if s == "" {
		return "", fmt.Errorf("%s is empty", path)
	}

	if strings.IndexFunc(s, unicode.IsSpace) >= 0 {
		return "", fmt.Errorf("%s contains whitespace other than a single trailing newline", path)
	}

	return s, nil
}

// Validate reports the first problem with cfg. Load calls it; a caller
// that builds a Config some other way (a test, a chart's rendered values)
// should call it too before trusting the result.
func (c *Config) Validate() error {
	if c.Issuer == "" {
		return fmt.Errorf("config: issuer is required")
	}

	if c.Audience == "" {
		return fmt.Errorf("config: audience is required")
	}

	if c.GroupsClaim == "" {
		return fmt.Errorf("config: groupsClaim is required")
	}

	hasID := c.Account.ID != ""
	hasIDFile := c.Account.IDFile != ""

	if hasID == hasIDFile {
		// Both false, or both true — either way there is not exactly
		// one source.
		return fmt.Errorf("config: account needs exactly one of id or idFile")
	}

	hasParentTokenID := c.Account.ParentTokenID != ""
	hasParentTokenIDFile := c.Account.ParentTokenIDFile != ""

	if hasParentTokenID == hasParentTokenIDFile {
		return fmt.Errorf("config: account needs exactly one of parentTokenId or parentTokenIdFile")
	}

	hasFile := c.Account.ParentTokenFile != ""
	hasEnv := c.Account.ParentTokenEnv != ""

	if hasFile == hasEnv {
		// Both false, or both true — either way there is not exactly
		// one source.
		return fmt.Errorf("config: account needs exactly one of parentTokenFile or parentTokenEnv (never an inline value)")
	}

	switch c.Minting.Mode {
	case MintModeLocal, MintModeAPI:
	default:
		return fmt.Errorf("config: minting.mode %q is neither %q nor %q", c.Minting.Mode, MintModeLocal, MintModeAPI)
	}

	return c.validateGrants()
}

// validateGrants checks each row on its own, then checks for rows that
// disagree about the SAME thing.
//
// The estate's own convention is one prefix per row per cache tool, so
// one group commonly owns several rows in the same bucket that differ
// only by Prefixes (internal/decide resolves which one a request means
// by what it asks for) — that is normal, not a conflict, and two rows
// may also legitimately share group, bucket AND prefixes while differing
// only in Permission (a reader row and a writer row for the same scope;
// a request disambiguates with an explicit permission, per
// internal/decide). What IS a conflict is two rows identical in every
// field decide can be asked to disambiguate by (group, bucket, prefixes,
// permission) that still disagree on ttlSeconds: nothing in a request
// can choose between them, so whichever the config happens to list first
// would win silently.
func (c *Config) validateGrants() error {
	seen := make(map[string]Grant, len(c.Grants))

	for i, g := range c.Grants {
		if g.Group == "" {
			return fmt.Errorf("config: grants[%d]: group is required", i)
		}

		if g.Bucket == "" {
			return fmt.Errorf("config: grants[%d] (group %q): bucket is required", i, g.Group)
		}

		if !g.Permission.Valid() {
			return fmt.Errorf("config: grants[%d] (group %q): permission %q is neither %q nor %q",
				i, g.Group, g.Permission, PermissionReadOnly, PermissionReadWrite)
		}

		if g.TTLSeconds <= 0 {
			return fmt.Errorf("config: grants[%d] (group %q): ttlSeconds must be > 0, got %d", i, g.Group, g.TTLSeconds)
		}

		key := grantIdentity(g)

		prev, ok := seen[key]
		if !ok {
			seen[key] = g

			continue
		}

		if prev.TTLSeconds != g.TTLSeconds {
			return fmt.Errorf(
				"config: group %q, bucket %q with this prefix list and permission appear in more than one grant row with different ttlSeconds — "+
					"one row would win and this file does not say which", g.Group, g.Bucket)
		}
	}

	return nil
}

// grantIdentity is everything internal/decide can be asked to
// disambiguate a row by: group, bucket, its prefix SET (order does not
// matter — decide matches by containment, not position) and permission.
// Two rows sharing this identity are either exact duplicates (redundant,
// not an error) or disagree on ttlSeconds (a real conflict — see
// validateGrants).
func grantIdentity(g Grant) string {
	prefixes := slices.Clone(g.Prefixes)
	slices.Sort(prefixes)

	return g.Group + "\x00" + g.Bucket + "\x00" + strings.Join(prefixes, "\x00") + "\x00" + string(g.Permission)
}
