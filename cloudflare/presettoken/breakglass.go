package presettoken

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/truvity/edge/v3/cloudflare/account"
)

// cloudflareAPI is the only API break-glass talks to; tests point it at a
// local server.
var cloudflareAPI = "https://api.cloudflare.com/client/v4"

// newCFClient is an HTTP client for Cloudflare's API and nothing else: the
// host is fixed, no proxy is honoured, and the roots are the system's own
// pool, refused when SSL_CERT_FILE or SSL_CERT_DIR would have changed it.
// Break-glass sends the root through it; settle sends each new token.
func newCFClient(accountID, token string) (*cfClient, error) {
	u, err := url.Parse(cloudflareAPI)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{Proxy: nil, ForceAttemptHTTP2: true}

	if u.Scheme == "https" {
		if u.Host != "api.cloudflare.com" {
			return nil, fmt.Errorf("refusing to send a Cloudflare token to %s", u.Host)
		}

		for _, env := range []string{"SSL_CERT_FILE", "SSL_CERT_DIR"} {
			if os.Getenv(env) != "" {
				return nil, fmt.Errorf("%s is set: it would change whom a Cloudflare token is sent to; unset it", env)
			}
		}

		roots, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("system roots: %w", err)
		}

		transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12, ServerName: "api.cloudflare.com"}
	}

	return &cfClient{api: cloudflareAPI, host: u.Host, account: accountID, token: token,
		http: &http.Client{Timeout: 30 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("refusing a redirect with a Cloudflare token")
		}}}, nil
}

// RootToken reads the account's root token from 1Password into memory, for
// break-glass only: it refuses unless the break-glass variable is "1". The
// value is never printed; a trailing newline or any whitespace is refused,
// not trimmed.
func (s Source) RootToken(ctx context.Context, cfg Config) (string, error) {
	if err := cfg.Validate(); err != nil {
		return "", err
	}

	bg := cfg.BreakGlass
	if !bg.Enabled() {
		return "", fmt.Errorf("the Cloudflare root is break-glass only: configure it and set %s=1%s", bg.Env, runbookHint(cfg))
	}

	s.banner(bg, "reading the Cloudflare ROOT from 1Password (%s)", bg.Ref())

	path, err := s.resolve(cfg, "op")
	if err != nil {
		return "", fmt.Errorf("cloudflare break-glass: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	stdout, stderr, code, err := s.run()(ctx, cleanEnv(), nil, path, "read", "--account", bg.Account, "--no-newline", bg.Ref())
	if err != nil {
		why, detail := "op read failed", "\n"+capStderr(stderr)
		if code == -1 {
			why, detail = "op (1Password's CLI) did not run, or timed out", ""
		}

		return "", fmt.Errorf("cloudflare break-glass: %s (op signin --account %s?): %w%s", why, bg.Account, err, detail)
	}

	token := string(stdout)
	if token == "" {
		return "", fmt.Errorf("cloudflare break-glass: %s is empty", bg.Ref())
	}

	if strings.IndexFunc(token, unicode.IsSpace) != -1 {
		return "", fmt.Errorf("cloudflare break-glass: %s holds whitespace: refusing, not trimming", bg.Ref())
	}

	return token, nil
}

func runbookHint(cfg Config) string {
	if cfg.Runbook == "" {
		return ""
	}

	return " (" + cfg.Runbook + ")"
}

func (s Source) banner(bg BreakGlass, format string, args ...any) {
	_, _ = fmt.Fprintf(s.stderr(), "\n!!! CLOUDFLARE BREAK-GLASS (%s=1): "+format+" !!!\n\n", append([]any{bg.Env}, args...)...)
}

// breakGlass mints, with the root, a child of the preset's own policies that
// expires within the lifetime, and hands it back as the preset would. The child is
// left to expire; its id is in the banner for an early revoke.
func (s Source) breakGlass(ctx context.Context, cfg Config, req Request) (Credential, error) {
	if req.AccountID == "" || len(req.Policies) == 0 {
		return Credential{}, fmt.Errorf("cloudflare break-glass %s: no account or policies to mint with", req.Preset)
	}

	child := account.ChildTokenConfig{Name: cfg.BreakGlass.ChildPrefix + "-" + req.Preset, Policies: req.Policies}
	if err := child.Validate(); err != nil {
		return Credential{}, fmt.Errorf("cloudflare break-glass %s: %w", req.Preset, err)
	}

	root, err := s.RootToken(ctx, cfg)
	if err != nil {
		return Credential{}, err
	}

	c, err := newCFClient(req.AccountID, root)
	if err != nil {
		return Credential{}, fmt.Errorf("cloudflare break-glass %s: %w", req.Preset, err)
	}

	policies := make([]map[string]any, 0, len(req.Policies))

	for i, p := range req.Policies {
		groups := make([]map[string]string, 0, len(p.PermissionGroups))

		for _, name := range p.PermissionGroups {
			id, err := c.permissionGroupID(ctx, name)
			if err != nil {
				return Credential{}, fmt.Errorf("cloudflare break-glass %s: policy %d: %w", req.Preset, i, err)
			}

			groups = append(groups, map[string]string{"id": id})
		}

		key, err := account.ResourceKey(p.Scope, req.AccountID)
		if err != nil {
			return Credential{}, fmt.Errorf("cloudflare break-glass %s: policy %d: %w", req.Preset, i, err)
		}

		policies = append(policies, map[string]any{
			"effect": "allow", "permission_groups": groups, "resources": map[string]string{key: "*"},
		})
	}

	expires := s.now().Add(min(cfg.lifetime(), MaxLifetime)).UTC().Truncate(time.Second)
	name := fmt.Sprintf("%s-%s-%s", cfg.BreakGlass.ChildPrefix, req.Preset, s.now().UTC().Format("20060102T150405Z"))

	id, value, err := c.createToken(ctx, name, policies, expires)
	if err != nil {
		return Credential{}, fmt.Errorf("cloudflare break-glass %s: %w", req.Preset, err)
	}

	s.banner(cfg.BreakGlass, "minted %s (token id %s) for preset %s with the ROOT; it expires at %s", name, id, req.Preset, expires.Format(time.RFC3339))

	if req.R2 {
		sum := sha256.Sum256([]byte(value))

		return Credential{AccessKeyID: id, SecretAccessKey: hex.EncodeToString(sum[:]), ExpiresOn: expires}, nil
	}

	return Credential{Token: value, ExpiresOn: expires}, nil
}

// cfClient is the calls made to Cloudflare: break-glass's two, as the root,
// and the verify of a new token, as that token.
type cfClient struct {
	api, host, account, token string
	http                      *http.Client
}

func (c *cfClient) do(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader

	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}

		rd = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.api+path, rd)
	if err != nil {
		return err
	}

	if req.URL.Host != c.host {
		return fmt.Errorf("refusing to send a Cloudflare token to %s", req.URL.Host)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}

	var env struct {
		Success bool `json:"success"`
		Errors  []struct {
			Message string `json:"message"`
		} `json:"errors"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("%s %s: %s, not a Cloudflare answer", method, path, resp.Status)
	}

	if !env.Success {
		msgs := make([]string, 0, len(env.Errors))
		for _, e := range env.Errors {
			msgs = append(msgs, e.Message)
		}

		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, strings.Join(msgs, "; "))
	}

	return json.Unmarshal(env.Result, out)
}

// permissionGroupID resolves a permission group by its exact name.
func (c *cfClient) permissionGroupID(ctx context.Context, name string) (string, error) {
	var groups []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}

	path := "/accounts/" + url.PathEscape(c.account) + "/tokens/permission_groups?name=" + url.QueryEscape(name)
	if err := c.do(ctx, http.MethodGet, path, nil, &groups); err != nil {
		return "", err
	}

	var ids []string

	for _, g := range groups {
		if g.Name == name {
			ids = append(ids, g.ID)
		}
	}

	if len(ids) != 1 {
		return "", fmt.Errorf("permission group %q: %d exact matches", name, len(ids))
	}

	return ids[0], nil
}

// createToken creates an account token and returns its id and value.
func (c *cfClient) createToken(ctx context.Context, name string, policies []map[string]any, expires time.Time) (string, string, error) {
	var created struct {
		ID    string `json:"id"`
		Value string `json:"value"`
	}

	if err := c.do(ctx, http.MethodPost, "/accounts/"+url.PathEscape(c.account)+"/tokens", map[string]any{
		"name": name, "policies": policies, "expires_on": expires.Format(time.RFC3339),
	}, &created); err != nil {
		return "", "", err
	}

	if created.ID == "" || created.Value == "" {
		return "", "", errors.New("cloudflare created a token with no id or value")
	}

	return created.ID, created.Value, nil
}
