// Package presettoken is where a Pulumi stack gets a Cloudflare credential
// from a sluis preset: on demand, at preview and apply time, for ONE preset,
// short-lived, and held in memory only.
//
//	sluisctl cloudflare token <preset> --format json --lifetime 1h --no-cache --issuer <url>
//	sluisctl cloudflare r2    <preset>               --lifetime 1h --no-cache --issuer <url>
//
// The caller is whoever runs the stack: `sluisctl login` on a laptop, the
// job's own OIDC identity in a pipeline. sluis clones the preset's DISABLED
// prototype token (declared by pkg/prototypes) into an account token that
// expires, refuses a caller its policy does not grant, and audits the mint.
// Nothing here holds a standing Cloudflare credential: there is none to hold.
//
// The package knows no estate. Every fact that differs between estates is a
// field of [Config] (the issuer, the sluisctl version floor, the binary paths
// sluisctl may come from, the break-glass item) or of [Request] (the preset,
// the account, the policies); there is no default that names one.
//
// HARDENING, all of it on by construction:
//
//   - sluisctl must resolve (symlinks followed) under one of
//     Config.BinaryPrefixes, and be at least Config.SluisctlMin, checked once
//     per binary;
//   - the child's environment drops every inherited SLUISCTL_* and OP_*
//     variable (OP_SESSION_* excepted: it is how `op signin` hands op its
//     session), every proxy variable and every CA override, so nothing
//     inherited decides where a credential travels or whom it trusts. The
//     issuer therefore travels as an explicit --issuer argument, never as
//     SLUISCTL_ISSUER;
//   - sluisctl runs with its credential cache off (the flag and
//     SLUISCTL_CLOUDFLARE_NO_CACHE=1), its stdout is read into memory, and an
//     error carries an exit code and a capped stderr, never a value;
//   - every CLI call has a timeout, and a stderr is cut at 512 bytes;
//   - an answer that claims to outlive the lifetime asked for, or to expire
//     within Config.MinRemaining, is refused;
//   - a new API token is verified against Cloudflare (as that token, to
//     api.cloudflare.com only, over the system roots, with no proxy and no
//     redirect) before it is handed out, because a just-minted token is not
//     always accepted at once; an R2 pair has no verify endpoint and is left
//     to settle.
//
// BREAK-GLASS. With the environment variable Config.BreakGlass.Env set to "1",
// and only then, the credential comes from the account's root instead: the
// root is read from 1Password into memory and used to mint a child with the
// preset's own policies (Request.Policies), an hour at most, through
// Cloudflare's API. It is for a sluis outage and for the bootstrap of the
// prototypes themselves. Every use says so, loudly, on stderr, with the
// minted token's id; the child is left to expire. The root is never printed,
// logged or written to disk, and a value that would need trimming is refused.
package presettoken

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/truvity/cloudflare/v2/pkg/account"
)

const (
	// DefaultLifetime is what a credential is asked for when Config.Lifetime
	// is zero.
	DefaultLifetime = time.Hour
	// DefaultMinRemaining is the shortest remaining life a credential may
	// have when Config.MinRemaining is zero.
	DefaultMinRemaining = 15 * time.Minute

	// noCacheEnv is sluisctl's switch for not caching a minted credential on
	// disk, set as well as the flag.
	noCacheEnv = "SLUISCTL_CLOUDFLARE_NO_CACHE"
)

// The CLIs, and how long each may take: sluisctl talks to sluis; op may wait
// for a person at a biometric prompt.
const (
	sluisctlTimeout = 2 * time.Minute
	opTimeout       = 5 * time.Minute
	versionTimeout  = 30 * time.Second
	// stderrCap bounds what of a CLI's stderr an error carries.
	stderrCap = 512
	// expirySlack is how much past the lifetime an answer's expiry may lie.
	expirySlack = 2 * time.Minute
)

// Config is everything an estate decides. The zero value is not usable:
// SluisctlMin and BinaryPrefixes are required.
type Config struct {
	// Issuer is the sluis issuer URL, passed to sluisctl as --issuer. Empty
	// leaves sluisctl to its own configured issuer (which the cleaned
	// environment cannot influence). When set it must be an https URL.
	Issuer string
	// SluisctlMin is the oldest sluisctl accepted, "MAJOR.MINOR.PATCH". A
	// release with --no-cache and --issuer on the cloudflare commands is
	// needed.
	SluisctlMin string
	// BinaryPrefixes are the path prefixes sluisctl may resolve under, after
	// symlinks: for a nix or devbox profile, "/nix/store/". At least one.
	// Other CLIs (op) are used from anywhere but named on stderr when they
	// are not under a prefix.
	BinaryPrefixes []string
	// Lifetime is asked of sluis and given to a break-glass child. Zero means
	// DefaultLifetime.
	Lifetime time.Duration
	// MinRemaining is the shortest remaining life accepted. Zero means
	// DefaultMinRemaining.
	MinRemaining time.Duration
	// BreakGlass is where the root is kept. The zero value disables
	// break-glass: the credential then always comes from sluis.
	BreakGlass BreakGlass
	// GrantHint is appended to the "sluis does not grant this preset to you"
	// error: the estate's policy group, a runbook. Optional.
	GrantHint string
	// Runbook names the estate's runbook in the break-glass refusal.
	// Optional.
	Runbook string
}

// BreakGlass says where the account root is kept and how a break-glass use is
// switched on and named. All fields are required once Env is set.
type BreakGlass struct {
	// Env is the environment variable that, set to "1", switches every
	// credential to the root.
	Env string
	// Account is the 1Password account (sign-in address or id), always passed
	// to `op read --account`, so the read never lands in another one.
	Account string
	// Vault, Item and Field spell the reference op://<Vault>/<Item>/<Field>.
	Vault, Item, Field string
	// ChildPrefix starts the name of every child minted: "<ChildPrefix>-
	// <preset>-<UTC time>", so a break-glass token is recognisable in the
	// dashboard.
	ChildPrefix string
}

// Enabled reports whether break-glass is configured and switched on.
func (b BreakGlass) Enabled() bool {
	return b.Env != "" && os.Getenv(b.Env) == "1"
}

// Ref is the 1Password secret reference of the root.
func (b BreakGlass) Ref() string {
	return "op://" + b.Vault + "/" + b.Item + "/" + b.Field
}

func (b BreakGlass) configured() bool { return b != BreakGlass{} }

func (b BreakGlass) validate() error {
	if !b.configured() {
		return nil
	}

	for name, v := range map[string]string{
		"Env": b.Env, "Account": b.Account, "Vault": b.Vault, "Item": b.Item, "Field": b.Field, "ChildPrefix": b.ChildPrefix,
	} {
		if v == "" {
			return fmt.Errorf("break-glass: %s is required once any field is set", name)
		}

		if strings.ContainsFunc(v, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
			return fmt.Errorf("break-glass: %s holds whitespace or a control character", name)
		}
	}

	for name, v := range map[string]string{"Vault": b.Vault, "Item": b.Item, "Field": b.Field} {
		if strings.Contains(v, "/") {
			return fmt.Errorf("break-glass: %s must not contain a slash", name)
		}
	}

	return nil
}

func (c Config) lifetime() time.Duration {
	if c.Lifetime > 0 {
		return c.Lifetime
	}

	return DefaultLifetime
}

func (c Config) minRemaining() time.Duration {
	if c.MinRemaining > 0 {
		return c.MinRemaining
	}

	return DefaultMinRemaining
}

// Validate reports the first problem with the configuration. Token calls it.
func (c Config) Validate() error {
	if _, ok := parseVersion(c.SluisctlMin); !ok {
		return fmt.Errorf("presettoken: SluisctlMin %q is not a MAJOR.MINOR.PATCH release", c.SluisctlMin)
	}

	if len(c.BinaryPrefixes) == 0 {
		return errors.New("presettoken: BinaryPrefixes is required: sluisctl must come from a pinned place")
	}

	for _, p := range c.BinaryPrefixes {
		if !filepath.IsAbs(p) {
			return fmt.Errorf("presettoken: binary prefix %q is not an absolute path", p)
		}
	}

	if c.Issuer != "" {
		u, err := url.Parse(c.Issuer)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("presettoken: issuer %q must be a plain https URL", c.Issuer)
		}

		if strings.HasPrefix(c.Issuer, "-") {
			return fmt.Errorf("presettoken: issuer %q looks like a flag", c.Issuer)
		}
	}

	if c.Lifetime < 0 || c.MinRemaining < 0 || c.minRemaining() >= c.lifetime() {
		return fmt.Errorf("presettoken: MinRemaining %s must be under Lifetime %s", c.minRemaining(), c.lifetime())
	}

	return c.BreakGlass.validate()
}

// Request is one provider's credential: the preset, and what break-glass
// needs to mint the same thing without sluis.
type Request struct {
	// Preset is the sluis preset name.
	Preset string
	// R2 is an R2 preset: the credential is an S3 pair, not an API token.
	R2 bool
	// AccountID is the Cloudflare account: break-glass mints in it, and a new
	// API token is verified in it before use.
	AccountID string
	// Policies are the preset prototype's policies (break-glass only).
	Policies []account.ChildTokenPolicy
}

// Credential is what a provider is built from: Token for an API-token preset;
// AccessKeyID and SecretAccessKey for an R2 one.
type Credential struct {
	Token           string
	AccessKeyID     string
	SecretAccessKey string
	ExpiresOn       time.Time
}

// Runner runs a CLI with an environment and stdin, and returns stdout,
// stderr and its exit code (-1 when it did not run).
type Runner func(ctx context.Context, env []string, stdin []byte, name string, args ...string) (stdout, stderr []byte, code int, err error)

// Source gets credentials. The zero value execs sluisctl and op and talks to
// Cloudflare; tests replace the seams.
type Source struct {
	// Run replaces the CLIs.
	Run Runner
	// LookPath replaces exec.LookPath plus filepath.EvalSymlinks.
	LookPath func(name string) (string, error)
	// Now replaces time.Now.
	Now func() time.Time
	// Stderr replaces os.Stderr, for notices and the break-glass banner.
	Stderr *os.File
}

// Token is the one way a stack gets a Cloudflare credential, with the zero
// Source.
func Token(ctx context.Context, cfg Config, req Request) (Credential, error) {
	return Source{}.Token(ctx, cfg, req)
}

func (s Source) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}

	return time.Now()
}

func (s Source) run() Runner {
	if s.Run != nil {
		return s.Run
	}

	return execRun
}

func (s Source) stderr() *os.File {
	if s.Stderr != nil {
		return s.Stderr
	}

	return os.Stderr
}

func (s Source) notice(format string, args ...any) {
	_, _ = fmt.Fprintf(s.stderr(), "presettoken: "+format+"\n", args...)
}

// Token returns a verified credential for the preset of req, from sluis or, in
// break-glass, from the root.
func (s Source) Token(ctx context.Context, cfg Config, req Request) (Credential, error) {
	if err := cfg.Validate(); err != nil {
		return Credential{}, err
	}

	if strings.TrimSpace(req.Preset) == "" {
		return Credential{}, errors.New("cloudflare provider token: no preset")
	}

	var (
		cred Credential
		err  error
	)

	if cfg.BreakGlass.Enabled() {
		cred, err = s.breakGlass(ctx, cfg, req)
	} else {
		cred, err = s.fromSluis(ctx, cfg, req)
	}

	if err != nil {
		return Credential{}, err
	}

	if cred.ExpiresOn.After(s.now().Add(cfg.lifetime() + expirySlack)) {
		return Credential{}, fmt.Errorf("cloudflare preset %s: the credential claims to live until %s, longer than the %s asked for: refusing",
			req.Preset, cred.ExpiresOn.UTC().Format(time.RFC3339), cfg.lifetime())
	}

	if left := cred.ExpiresOn.Sub(s.now()); left < cfg.minRemaining() {
		return Credential{}, fmt.Errorf("cloudflare preset %s: the credential expires in %s, under %s: run again%s",
			req.Preset, left.Round(time.Second), cfg.minRemaining(), useBreakGlass(cfg))
	}

	if req.R2 && (cred.AccessKeyID == "" || cred.SecretAccessKey == "") || !req.R2 && cred.Token == "" {
		return Credential{}, fmt.Errorf("cloudflare preset %s: the credential is not the kind the preset hands out", req.Preset)
	}

	if err := s.settle(ctx, req, cred); err != nil {
		return Credential{}, err
	}

	return cred, nil
}

func useBreakGlass(cfg Config) string {
	if cfg.BreakGlass.Env == "" {
		return ""
	}

	return fmt.Sprintf(", or use break-glass (%s=1)", cfg.BreakGlass.Env)
}

// resolve finds a CLI once and refuses one that is not where the estate puts
// it: sluisctl must resolve under a Config.BinaryPrefixes entry, which pins its
// version; op (1Password's CLI, usually not in the profile) is named loudly
// instead.
func (s Source) resolve(cfg Config, name string) (string, error) {
	look := s.LookPath
	if look == nil {
		look = func(n string) (string, error) {
			p, err := exec.LookPath(n)
			if err != nil {
				return "", err
			}

			return filepath.EvalSymlinks(p)
		}
	}

	path, err := look(name)
	if err != nil {
		return "", fmt.Errorf("%s is not on PATH (run inside the pinned toolchain): %w", name, err)
	}

	pinned := slices.ContainsFunc(cfg.BinaryPrefixes, func(p string) bool { return strings.HasPrefix(path, p) })

	switch {
	case name == "sluisctl" && !pinned:
		return "", fmt.Errorf("sluisctl resolves to %s, outside %v: run inside the pinned toolchain", path, cfg.BinaryPrefixes)
	case !pinned:
		s.notice("using %s at %s (not under %v)", name, path, cfg.BinaryPrefixes)
	}

	return path, nil
}

var (
	versionMu sync.Mutex
	versionOK = map[string]bool{}
)

// requireSluisctl refuses a sluisctl older than cfg.SluisctlMin, once per
// binary and floor.
func (s Source) requireSluisctl(ctx context.Context, cfg Config, path string) error {
	key := path + "@" + cfg.SluisctlMin

	versionMu.Lock()
	defer versionMu.Unlock()

	if versionOK[key] {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, versionTimeout)
	defer cancel()

	stdout, _, _, err := s.run()(ctx, cleanEnv(), nil, path, "version", "--json")
	if err != nil {
		return fmt.Errorf("sluisctl version: %w", err)
	}

	var v struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(stdout, &v); err != nil || !versionAtLeast(v.Version, cfg.SluisctlMin) {
		return fmt.Errorf("sluisctl %q is older than %s: update the pinned toolchain", v.Version, cfg.SluisctlMin)
	}

	versionOK[key] = true

	return nil
}

// capStderr is the head of a CLI's stderr, for an error.
func capStderr(b []byte) string {
	b = bytes.TrimSpace(b)
	if len(b) > stderrCap {
		return string(b[:stderrCap]) + "..."
	}

	return string(b)
}

// strippedEnv are inherited variables no CLI run here sees: a proxy decides
// the path a credential travels, a CA override whom it trusts.
var strippedEnv = []string{
	"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
	"SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE",
}

// cleanEnv is the process environment less strippedEnv and every inherited
// SLUISCTL_* and OP_* variable, plus extra. OP_SESSION_* is kept: it is how
// `op signin` without the desktop app hands op its session. What goes is what
// could point op elsewhere (OP_CONNECT_*, OP_SERVICE_ACCOUNT_TOKEN,
// OP_ACCOUNT) or change sluisctl's behaviour unseen (SLUISCTL_ISSUER, the
// config path).
func cleanEnv(extra ...string) []string {
	return append(slices.DeleteFunc(os.Environ(), func(kv string) bool {
		name, _, _ := strings.Cut(kv, "=")
		upper := strings.ToUpper(name)

		return slices.Contains(strippedEnv, upper) || strings.HasPrefix(upper, "SLUISCTL_") ||
			(strings.HasPrefix(upper, "OP_") && !strings.HasPrefix(upper, "OP_SESSION_"))
	}), extra...)
}

func execRun(ctx context.Context, env []string, stdin []byte, name string, args ...string) ([]byte, []byte, int, error) {
	var stdout, stderr bytes.Buffer

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = env
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}

	err := cmd.Run()

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return stdout.Bytes(), stderr.Bytes(), exitErr.ExitCode(), err
	}

	if err != nil {
		return nil, stderr.Bytes(), -1, err
	}

	return stdout.Bytes(), stderr.Bytes(), 0, nil
}

// sluisctl's exit codes.
const (
	exitUsage       = 2
	exitNotSignedIn = 3
	exitNotGranted  = 4
	exitUnreachable = 5
)

// sluisArgs is the command line: flags follow the preset, as sluisctl reads
// them.
func sluisArgs(cfg Config, req Request) []string {
	args := []string{"cloudflare", "token", req.Preset, "--format", "json"}
	if req.R2 {
		args = []string{"cloudflare", "r2", req.Preset}
	}

	args = append(args, "--lifetime", cfg.lifetime().String(), "--no-cache")

	if cfg.Issuer != "" {
		args = append(args, "--issuer", cfg.Issuer)
	}

	return args
}

// fromSluis execs sluisctl for the preset and reads its answer into memory.
func (s Source) fromSluis(ctx context.Context, cfg Config, req Request) (Credential, error) {
	kind := "token"
	if req.R2 {
		kind = "r2"
	}

	path, err := s.resolve(cfg, "sluisctl")
	if err != nil {
		return Credential{}, fmt.Errorf("cloudflare preset %s: %w", req.Preset, err)
	}

	if err := s.requireSluisctl(ctx, cfg, path); err != nil {
		return Credential{}, fmt.Errorf("cloudflare preset %s: %w", req.Preset, err)
	}

	ctx, cancel := context.WithTimeout(ctx, sluisctlTimeout)
	defer cancel()

	stdout, stderr, code, err := s.run()(ctx, cleanEnv(noCacheEnv+"=1"), nil, path, sluisArgs(cfg, req)...)
	if err != nil {
		why, known := "", true

		switch code {
		case exitNotSignedIn:
			why = "not signed in to sluis: run `sluisctl login`"
			if cfg.Issuer != "" {
				why += " --issuer " + cfg.Issuer
			}
		case exitNotGranted:
			why = "sluis does not grant this preset to you"
			if cfg.GrantHint != "" {
				why += ": " + cfg.GrantHint
			}
		case exitUnreachable:
			why = "sluis is unreachable: retry" + useBreakGlass(cfg)
		case exitUsage:
			why = fmt.Sprintf("sluisctl refused the command line (sluisctl %s or later is needed for --no-cache and --issuer)", cfg.SluisctlMin)
		case -1:
			why = "sluisctl did not run or timed out"
		default:
			known = false
		}

		detail := ""
		if known {
			detail = "\n" + capStderr(stderr)
		}

		return Credential{}, fmt.Errorf("cloudflare preset %s: sluisctl cloudflare %s: %s: %w%s",
			req.Preset, kind, why, err, detail)
	}

	return parseSluisAnswer(req, stdout)
}

func parseSluisAnswer(req Request, stdout []byte) (Credential, error) {
	if req.R2 {
		// An AWS credential_process answer.
		var a struct {
			Version         int    `json:"Version"`
			AccessKeyID     string `json:"AccessKeyId"`
			SecretAccessKey string `json:"SecretAccessKey"`
			Expiration      string `json:"Expiration"`
		}
		if err := json.Unmarshal(stdout, &a); err != nil || a.Version != 1 {
			return Credential{}, fmt.Errorf("cloudflare preset %s: sluisctl's answer is not a credential_process document", req.Preset)
		}

		exp, err := time.Parse(time.RFC3339, a.Expiration)
		if err != nil {
			return Credential{}, fmt.Errorf("cloudflare preset %s: Expiration is not RFC 3339", req.Preset)
		}

		return Credential{AccessKeyID: a.AccessKeyID, SecretAccessKey: a.SecretAccessKey, ExpiresOn: exp}, nil
	}

	var a struct {
		Token     string `json:"token"`
		ExpiresOn string `json:"expires_on"`
	}
	if err := json.Unmarshal(stdout, &a); err != nil {
		return Credential{}, fmt.Errorf("cloudflare preset %s: sluisctl's answer is not JSON", req.Preset)
	}

	exp, err := time.Parse(time.RFC3339, a.ExpiresOn)
	if err != nil {
		return Credential{}, fmt.Errorf("cloudflare preset %s: expires_on is not RFC 3339", req.Preset)
	}

	return Credential{Token: a.Token, ExpiresOn: exp}, nil
}
