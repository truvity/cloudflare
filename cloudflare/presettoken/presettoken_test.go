package presettoken

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/truvity/edge/v3/cloudflare/account"
)

const (
	testAccount       = "0123456789abcdef0123456789abcdef"
	testIssuer        = "https://access.example.test"
	testMin           = "1.76.8"
	testBreakGlassEnv = "EXAMPLE_CLOUDFLARE_BREAKGLASS"
)

// testCfg is a made-up estate: nothing in the package defaults to one.
func testCfg() Config {
	return Config{
		Issuer:         testIssuer,
		SluisctlMin:    testMin,
		BinaryPrefixes: []string{binDir},
		GrantHint:      "policy group example:deploy",
		BreakGlass: BreakGlass{
			Env: testBreakGlassEnv, Account: "example.1password.com", Vault: "vault", Item: "cf-root", Field: "token",
			ChildPrefix: "example-breakglass",
		},
	}
}

var now = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)

type call struct {
	name string
	args []string
	env  []string
}

// fakeCLI answers sluisctl and op as they would, and records every call.
type fakeCLI struct {
	mu    sync.Mutex
	calls []call

	sluisOut  string
	sluisCode int
	opOut     string
	version   string
}

func (f *fakeCLI) run(_ context.Context, env []string, _ []byte, name string, args ...string) ([]byte, []byte, int, error) {
	name = filepath.Base(name)

	f.mu.Lock()
	f.calls = append(f.calls, call{name, args, env})
	f.mu.Unlock()

	switch name {
	case "sluisctl":
		if len(args) > 0 && args[0] == "version" {
			v := f.version
			if v == "" {
				v = testMin
			}

			return []byte(`{"version":"` + v + `"}`), nil, 0, nil
		}

		if f.sluisCode != 0 {
			return nil, []byte("sluisctl: refused"), f.sluisCode, errors.New("exit status")
		}

		return []byte(f.sluisOut), nil, 0, nil
	case "op":
		return []byte(f.opOut), nil, 0, nil
	}

	return nil, nil, -1, errors.New("no such command")
}

// source is a Source over the fake CLIs and the fixed clock.
func (f *fakeCLI) source(look func(string) (string, error)) Source {
	return Source{Run: f.run, LookPath: look, Now: func() time.Time { return now }}
}

var edgeReq = Request{Preset: "example-edge", AccountID: testAccount}

func (f *fakeCLI) named(name string) []call {
	f.mu.Lock()
	defer f.mu.Unlock()

	var out []call

	for _, c := range f.calls {
		if c.name == name {
			out = append(out, c)
		}
	}

	return out
}

func tokenJSON(token string, expires time.Time) string {
	b, _ := json.Marshal(map[string]string{"token": token, "expires_on": expires.Format(time.RFC3339)})

	return string(b)
}

// Without the flag the token comes from sluis, on demand, for the preset, with
// a one-hour lifetime and the cache off; 1Password is never touched.
func TestProviderTokenFromSluis(t *testing.T) {
	t.Setenv(testBreakGlassEnv, "")
	t.Setenv("HTTPS_PROXY", "http://proxy.example:3128")

	f := &fakeCLI{sluisOut: tokenJSON("edge-value", now.Add(time.Hour))}
	s := Source{Run: f.run, LookPath: nixPath, Now: func() time.Time { return now }}

	cred, err := s.Token(context.Background(), testCfg(), edgeReq)
	if err != nil {
		t.Fatal(err)
	}

	if cred.Token != "edge-value" {
		t.Fatalf("token %q", cred.Token)
	}

	calls := mints(f.named("sluisctl"))
	if len(calls) != 1 {
		t.Fatalf("sluisctl minted %d times", len(calls))
	}

	want := []string{"cloudflare", "token", "example-edge", "--format", "json", "--lifetime", "1h0m0s", "--no-cache", "--issuer", testIssuer}
	if !slices.Equal(calls[0].args, want) {
		t.Errorf("args %v, want %v", calls[0].args, want)
	}

	if !slices.Contains(calls[0].env, "SLUISCTL_CLOUDFLARE_NO_CACHE=1") {
		t.Error("the cache is not switched off in the environment")
	}

	if slices.ContainsFunc(calls[0].env, func(kv string) bool { return strings.HasPrefix(kv, "HTTPS_PROXY=") }) {
		t.Error("a proxy reaches sluisctl")
	}

	if len(f.named("op")) != 0 {
		t.Fatal("1Password was read without the break-glass flag")
	}
}

func TestProviderTokenR2FromSluis(t *testing.T) {
	t.Setenv(testBreakGlassEnv, "")

	out, _ := json.Marshal(map[string]any{"Version": 1, "AccessKeyId": "id1", "SecretAccessKey": "s1", "Expiration": now.Add(time.Hour).Format(time.RFC3339)})
	f := &fakeCLI{sluisOut: string(out)}
	s := Source{Run: f.run, LookPath: nixPath, Now: func() time.Time { return now }}

	cred, err := s.Token(context.Background(), testCfg(), Request{Preset: "example-bucket-writer", R2: true})
	if err != nil {
		t.Fatal(err)
	}

	if cred.AccessKeyID != "id1" || cred.SecretAccessKey != "s1" {
		t.Fatalf("cred %+v", cred)
	}

	want := []string{"cloudflare", "r2", "example-bucket-writer", "--lifetime", "1h0m0s", "--no-cache", "--issuer", testIssuer}
	if got := mints(f.named("sluisctl"))[0].args; !slices.Equal(got, want) {
		t.Errorf("args %v, want %v", got, want)
	}
}

// A credential about to expire, and each sluisctl refusal, fail with what to do;
// no error carries the value.
func TestProviderTokenRefusals(t *testing.T) {
	t.Setenv(testBreakGlassEnv, "")

	for _, tc := range []struct {
		name string
		f    *fakeCLI
		want string
	}{
		{"expires in 10m", &fakeCLI{sluisOut: tokenJSON("secret-value", now.Add(10*time.Minute))}, "run again, or use break-glass"},
		{"not signed in", &fakeCLI{sluisCode: exitNotSignedIn}, "sluisctl login"},
		{"not granted", &fakeCLI{sluisCode: exitNotGranted}, "policy group example:deploy"},
		{"unreachable", &fakeCLI{sluisCode: exitUnreachable}, testBreakGlassEnv},
		{"old sluisctl", &fakeCLI{sluisCode: exitUsage}, testMin},
		{"empty token", &fakeCLI{sluisOut: tokenJSON("", now.Add(time.Hour))}, "not the kind"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := Source{Run: tc.f.run, LookPath: nixPath, Now: func() time.Time { return now }}

			_, err := s.Token(context.Background(), testCfg(), edgeReq)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}

			if strings.Contains(err.Error(), "secret-value") {
				t.Fatal("the error carries the value")
			}
		})
	}
}

// fakeCloudflare is the API calls break-glass makes, and the verify of the
// child.
type fakeCloudflare struct {
	mu      sync.Mutex
	auth    []string
	created []map[string]any
}

func (f *fakeCloudflare) handler(t *testing.T) http.Handler {
	t.Helper()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.auth = append(f.auth, r.Header.Get("Authorization"))
		f.mu.Unlock()

		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/accounts/"+testAccount+"/tokens/verify"):
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]string{"id": "child-id", "status": "active"}})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/accounts/"+testAccount+"/tokens/permission_groups"):
			name := r.URL.Query().Get("name")
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": []map[string]string{{"id": "pg:" + name, "name": name}}})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/accounts/"+testAccount+"/tokens"):
			body, _ := io.ReadAll(r.Body)

			var m map[string]any
			_ = json.Unmarshal(body, &m)

			f.mu.Lock()
			f.created = append(f.created, m)
			f.mu.Unlock()

			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]string{"id": "child-id", "value": "child-value"}})
		default:
			http.Error(w, "unexpected", http.StatusNotFound)
		}
	})
}

// With the flag the root comes from 1Password and a child of the preset's own
// policies is minted for at most an hour; sluis is never asked, and the
// banner says break-glass.
func TestProviderTokenBreakGlass(t *testing.T) {
	t.Setenv(testBreakGlassEnv, "1")

	cf := &fakeCloudflare{}
	srv := httptest.NewServer(cf.handler(t))
	t.Cleanup(srv.Close)

	banner, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}

	f := &fakeCLI{opOut: "root-value"}
	useAPI(t, srv.URL)

	s := Source{Run: f.run, LookPath: nixPath, Now: func() time.Time { return now }, Stderr: banner}

	req := Request{Preset: "example-bucket-writer", R2: true, AccountID: testAccount, Policies: []account.ChildTokenPolicy{
		{PermissionGroups: []string{"Workers R2 Storage Bucket Item Write"}, Scope: account.R2BucketScope{Bucket: "example-bucket"}},
	}}

	cred, err := s.Token(context.Background(), testCfg(), req)
	if err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256([]byte("child-value"))
	if cred.AccessKeyID != "child-id" || cred.SecretAccessKey != hex.EncodeToString(sum[:]) {
		t.Fatalf("cred %+v", cred)
	}

	if !cred.ExpiresOn.Equal(now.Add(time.Hour)) {
		t.Errorf("expires %s", cred.ExpiresOn)
	}

	if len(f.named("sluisctl")) != 0 {
		t.Fatal("sluis was asked in break-glass")
	}

	ops := f.named("op")
	if len(ops) != 1 || !slices.Equal(ops[0].args, []string{"read", "--account", "example.1password.com", "--no-newline", "op://vault/cf-root/token"}) {
		t.Fatalf("op calls %v", ops)
	}

	for _, a := range cf.auth {
		if a != "Bearer root-value" {
			t.Fatalf("a call went with %q", a)
		}
	}

	if len(cf.created) != 1 {
		t.Fatalf("%d tokens created", len(cf.created))
	}

	c := cf.created[0]
	if exp, _ := time.Parse(time.RFC3339, c["expires_on"].(string)); exp.Sub(now) > time.Hour {
		t.Errorf("expires_on %v", c["expires_on"])
	}

	pol := c["policies"].([]any)[0].(map[string]any)
	if res := pol["resources"].(map[string]any); res["com.cloudflare.edge.r2.bucket."+testAccount+"_default_example-bucket"] != "*" {
		t.Errorf("resources %v", res)
	}

	if g := pol["permission_groups"].([]any)[0].(map[string]any)["id"]; g != "pg:Workers R2 Storage Bucket Item Write" {
		t.Errorf("group %v", g)
	}

	_, _ = banner.Seek(0, 0)

	out, _ := io.ReadAll(banner)
	text := string(out)
	if !strings.Contains(text, "BREAK-GLASS") || !strings.Contains(text, "child-id") ||
		strings.Contains(text, "child-value") || strings.Contains(text, "root-value") {
		t.Fatalf("banner %q", out)
	}
}

// The root is break-glass only, and a value that would need trimming is
// refused.
func TestRootToken(t *testing.T) {
	t.Setenv(testBreakGlassEnv, "")

	f := &fakeCLI{opOut: "root-value"}
	if _, err := (Source{Run: f.run, LookPath: nixPath}).RootToken(context.Background(), testCfg()); err == nil || len(f.named("op")) != 0 {
		t.Fatalf("read the root without the flag: %v", err)
	}

	t.Setenv(testBreakGlassEnv, "1")

	devnull, _ := os.Open(os.DevNull)
	f = &fakeCLI{opOut: "root-value\n"}

	if _, err := (Source{Run: f.run, LookPath: nixPath, Stderr: devnull}).RootToken(context.Background(), testCfg()); err == nil ||
		!strings.Contains(err.Error(), "whitespace") {
		t.Fatalf("got %v", err)
	}
}

// Break-glass refuses a policy holding Account API Tokens, as the library does.
func TestBreakGlassRefusesAPITokens(t *testing.T) {
	t.Setenv(testBreakGlassEnv, "1")

	f := &fakeCLI{opOut: "root-value"}

	_, err := f.source(nixPath).Token(context.Background(), testCfg(), Request{
		Preset: "x", AccountID: testAccount,
		Policies: []account.ChildTokenPolicy{{PermissionGroups: []string{"Account API Tokens Write"}, Scope: account.WholeAccountScope{}}},
	})
	if err == nil || len(f.named("op")) != 0 {
		t.Fatalf("got %v, op calls %d", err, len(f.named("op")))
	}
}

// binDir stands for the pinned toolchain (/nix/store in an estate): a real
// directory holding real, empty executables, because a path is resolved
// through symlinks before it is compared.
var binDir string

// nixPath stands for a devbox-installed CLI.
func nixPath(name string) (string, error) { return filepath.Join(binDir, name), nil }

// mints are the sluisctl calls that are not the version check.
func mints(calls []call) []call {
	var out []call

	for _, c := range calls {
		if len(c.args) == 0 || c.args[0] != "version" {
			out = append(out, c)
		}
	}

	return out
}

func useAPI(t *testing.T, u string) {
	t.Helper()

	old := cloudflareAPI
	cloudflareAPI = u

	t.Cleanup(func() { cloudflareAPI = old })
}

// sluisctl must come from the devbox profile and be new enough for --no-cache;
// an inherited SLUISCTL_* or OP_* variable (but an op session) never reaches a
// CLI.
func TestSluisctlIsPinnedAndClean(t *testing.T) {
	t.Setenv(testBreakGlassEnv, "")
	t.Setenv("SLUISCTL_ISSUER", "https://evil.example")
	t.Setenv("OP_CONNECT_TOKEN", "x")
	t.Setenv("OP_SESSION_my", "s")

	f := &fakeCLI{sluisOut: tokenJSON("v", now.Add(time.Hour))}

	_, err := (Source{Run: f.run, LookPath: func(string) (string, error) { return "/bin/sh", nil }, Now: func() time.Time { return now }}).
		Token(context.Background(), testCfg(), edgeReq)
	if err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("got %v", err)
	}

	versionMu.Lock()
	versionOK = map[string]bool{}
	versionMu.Unlock()

	f = &fakeCLI{sluisOut: tokenJSON("v", now.Add(time.Hour)), version: "1.76.7"}

	_, err = f.source(nixPath).Token(context.Background(), testCfg(), edgeReq)
	if err == nil || !strings.Contains(err.Error(), "older than "+testMin) || len(mints(f.named("sluisctl"))) != 0 {
		t.Fatalf("an old sluisctl was used: %v", err)
	}

	f = &fakeCLI{sluisOut: tokenJSON("v", now.Add(time.Hour)), version: "v1.77.0"}

	if _, err := f.source(nixPath).Token(context.Background(), testCfg(), edgeReq); err != nil {
		t.Fatal(err)
	}

	env := mints(f.named("sluisctl"))[0].env
	for _, kv := range env {
		if strings.HasPrefix(kv, "SLUISCTL_ISSUER=") || strings.HasPrefix(kv, "OP_CONNECT_TOKEN=") {
			t.Errorf("%s reached sluisctl", kv)
		}
	}

	if !slices.Contains(env, "OP_SESSION_my=s") {
		t.Error("the op session was dropped")
	}
}

func TestVersionAtLeast(t *testing.T) {
	for v, ok := range map[string]bool{"1.76.8": true, "v1.76.8": true, "1.77.0": true, "2.0.0": true,
		"1.76.7": false, "1.76.8-rc.1": false, "garbage": false, "": false} {
		if versionAtLeast(v, "1.76.8") != ok {
			t.Errorf("%s: want %v", v, ok)
		}
	}
}

// An answer that claims to live longer than asked is refused, and an unknown
// exit code carries no stderr.
func TestAnswerChecks(t *testing.T) {
	t.Setenv(testBreakGlassEnv, "")

	f := &fakeCLI{sluisOut: tokenJSON("v", now.Add(3*time.Hour))}

	_, err := f.source(nixPath).Token(context.Background(), testCfg(), edgeReq)
	if err == nil || !strings.Contains(err.Error(), "longer than") {
		t.Fatalf("got %v", err)
	}

	f = &fakeCLI{sluisCode: 9}

	_, err = f.source(nixPath).Token(context.Background(), testCfg(), edgeReq)
	if err == nil || strings.Contains(err.Error(), "refused") {
		t.Fatalf("an unknown exit code passed stderr on: %v", err)
	}

	if got := capStderr([]byte(strings.Repeat("x", 2000))); len(got) > stderrCap+3 {
		t.Errorf("stderr not capped: %d bytes", len(got))
	}
}

// The root is sent to api.cloudflare.com and nowhere else, over the system's
// own roots.
func TestBreakGlassHost(t *testing.T) {
	useAPI(t, "https://api.cloudflare.com.evil.example/client/v4")

	if _, err := newCFClient(testAccount, "r"); err == nil {
		t.Fatal("accepted another host")
	}

	useAPI(t, "https://api.cloudflare.com/client/v4")
	t.Setenv("SSL_CERT_FILE", "/tmp/evil.pem")

	if _, err := newCFClient(testAccount, "r"); err == nil || !strings.Contains(err.Error(), "SSL_CERT_FILE") {
		t.Fatalf("got %v", err)
	}
}

// The issuer travels as an argument: the inherited SLUISCTL_ISSUER is gone
// from the child's environment, so a stack cannot be pointed at another
// estate's issuer by its shell, and an estate with several issuers names its
// own.
func TestIssuerIsAnArgumentNotTheEnvironment(t *testing.T) {
	t.Setenv(testBreakGlassEnv, "")
	t.Setenv("SLUISCTL_ISSUER", "https://other.example.test")
	t.Setenv("SLUISCTL_CONFIG", "/tmp/other.yaml")

	f := &fakeCLI{sluisOut: tokenJSON("v", now.Add(time.Hour))}
	s := Source{Run: f.run, LookPath: nixPath, Now: func() time.Time { return now }}

	if _, err := s.Token(context.Background(), testCfg(), edgeReq); err != nil {
		t.Fatal(err)
	}

	c := mints(f.named("sluisctl"))[0]

	i := slices.Index(c.args, "--issuer")
	if i < 0 || c.args[i+1] != testIssuer {
		t.Errorf("args %v do not name the issuer", c.args)
	}

	for _, kv := range c.env {
		if strings.HasPrefix(kv, "SLUISCTL_ISSUER=") || strings.HasPrefix(kv, "SLUISCTL_CONFIG=") {
			t.Errorf("%s reached sluisctl", kv)
		}
	}

	// No issuer configured: no --issuer argument, sluisctl's own choice.
	cfg := testCfg()
	cfg.Issuer = ""
	f = &fakeCLI{sluisOut: tokenJSON("v", now.Add(time.Hour))}

	if _, err := f.source(nixPath).Token(context.Background(), cfg, edgeReq); err != nil {
		t.Fatal(err)
	}

	if slices.Contains(mints(f.named("sluisctl"))[0].args, "--issuer") {
		t.Error("--issuer passed with no issuer configured")
	}
}

// The path check is the estate's: only a prefix it names is accepted.
func TestBinaryPrefixesAreTheEstates(t *testing.T) {
	t.Setenv(testBreakGlassEnv, "")

	cfg := testCfg()
	other := t.TempDir()
	cfg.BinaryPrefixes = []string{other}
	f := &fakeCLI{sluisOut: tokenJSON("v", now.Add(time.Hour))}

	_, err := f.source(nixPath).Token(context.Background(), cfg, edgeReq)
	if err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("a path outside the estate's prefix passed: %v", err)
	}

	for _, name := range []string{"sluisctl", "op"} {
		if err := os.WriteFile(filepath.Join(other, name), nil, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	pinned := func(name string) (string, error) { return filepath.Join(other, name), nil }

	if _, err := f.source(pinned).Token(context.Background(), cfg, edgeReq); err != nil {
		t.Fatal(err)
	}
}

// Break-glass is off unless the estate configures it, whatever the shell sets.
func TestBreakGlassUnconfiguredIsOff(t *testing.T) {
	t.Setenv(testBreakGlassEnv, "1")

	cfg := testCfg()
	cfg.BreakGlass = BreakGlass{}
	f := &fakeCLI{sluisOut: tokenJSON("v", now.Add(time.Hour)), opOut: "root-value"}

	if _, err := f.source(nixPath).Token(context.Background(), cfg, edgeReq); err != nil {
		t.Fatal(err)
	}

	if len(f.named("op")) != 0 {
		t.Fatal("1Password was read with break-glass unconfigured")
	}
}

func TestConfigValidate(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*Config)
		want   string
	}{
		"ok":                {func(*Config) {}, ""},
		"no floor":          {func(c *Config) { c.SluisctlMin = "" }, "SluisctlMin"},
		"pre-release floor": {func(c *Config) { c.SluisctlMin = "1.76.8-rc.1" }, "SluisctlMin"},
		"no prefixes":       {func(c *Config) { c.BinaryPrefixes = nil }, "BinaryPrefixes"},
		"relative prefix":   {func(c *Config) { c.BinaryPrefixes = []string{"nix/store"} }, "absolute"},
		"http issuer":       {func(c *Config) { c.Issuer = "http://access.example.test" }, "https"},
		"flag issuer":       {func(c *Config) { c.Issuer = "--no-cache" }, "https"},
		"issuer userinfo":   {func(c *Config) { c.Issuer = "https://u:p@access.example.test" }, "https"},
		"floor over life":   {func(c *Config) { c.Lifetime = time.Hour; c.MinRemaining = 2 * time.Hour }, "MinRemaining"},
		"half a root":       {func(c *Config) { c.BreakGlass.Item = "" }, "Item is required"},
		"slash in vault":    {func(c *Config) { c.BreakGlass.Vault = "a/b" }, "slash"},
		"space in field":    {func(c *Config) { c.BreakGlass.Field = "a b" }, "whitespace"},
		"no break-glass":    {func(c *Config) { c.BreakGlass = BreakGlass{} }, ""},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := testCfg()
			tc.mutate(&cfg)

			err := cfg.Validate()
			if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

// A mistaken Config is refused before any CLI runs.
func TestInvalidConfigRunsNothing(t *testing.T) {
	cfg := testCfg()
	cfg.SluisctlMin = ""
	f := &fakeCLI{}

	if _, err := (Source{Run: f.run, LookPath: nixPath}).Token(context.Background(), cfg, Request{Preset: "example-edge"}); err == nil || len(f.calls) != 0 {
		t.Fatalf("got %v after %d calls", err, len(f.calls))
	}
}

// Break-glass names its children by the estate's prefix.
func TestBreakGlassChildName(t *testing.T) {
	t.Setenv(testBreakGlassEnv, "1")

	cf := &fakeCloudflare{}
	srv := httptest.NewServer(cf.handler(t))
	t.Cleanup(srv.Close)
	useAPI(t, srv.URL)

	f := &fakeCLI{opOut: "root-value"}
	s := Source{Run: f.run, LookPath: nixPath, Now: func() time.Time { return now }, Stderr: captureStderr(t)}

	_, err := s.Token(context.Background(), testCfg(), Request{Preset: "example-edge", AccountID: testAccount, Policies: []account.ChildTokenPolicy{
		{PermissionGroups: []string{"DNS Write"}, Scope: account.ZoneScope{ZoneID: testAccount}},
	}})
	if err != nil {
		t.Fatal(err)
	}

	if got, want := cf.created[0]["name"], "example-breakglass-example-edge-20261013T120000Z"; got != want {
		t.Errorf("child named %v, want %v", got, want)
	}
}

// A binary prefix is a specific, clean directory; a path matches only below it.
func TestBinaryPrefixValidation(t *testing.T) {
	for prefix, want := range map[string]string{
		"/nix/store/":       "clean",
		"/nix//store":       "clean",
		"/nix/store/../etc": "clean",
		"nix/store":         "clean",
		"/":                 "too broad",
		"/nix":              "too broad",
		"/usr":              "too broad",
		"/bin":              "too broad",
		"/sbin":             "too broad",
		"/home":             "too broad",
		"/tmp":              "too broad",
		"/var":              "too broad",
		"/opt":              "too broad",
		"/etc":              "too broad",
		"/root":             "too broad",
		"/nix/store":        "",
		"/usr/local/pinned": "",
	} {
		cfg := testCfg()
		cfg.BinaryPrefixes = []string{prefix}

		err := cfg.Validate()
		if want == "" && err != nil || want != "" && (err == nil || !strings.Contains(err.Error(), want)) {
			t.Errorf("%q: got %v, want %q", prefix, err, want)
		}
	}
}

// "/nix/store" does not match "/nix/store-evil", and a symlink out of the
// pinned directory is resolved before the comparison, seam or not.
func TestPrefixMatchesBelowTheDirectoryAndAfterSymlinks(t *testing.T) {
	t.Setenv(testBreakGlassEnv, "")

	pinned := t.TempDir()
	sibling := pinned + "-evil"

	if err := os.Mkdir(sibling, 0o700); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = os.RemoveAll(sibling) })

	for _, name := range []string{"sluisctl", "op"} {
		if err := os.WriteFile(filepath.Join(sibling, name), nil, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	if err := os.Symlink("/bin/sh", filepath.Join(pinned, "sluisctl")); err != nil {
		t.Fatal(err)
	}

	cfg := testCfg()
	cfg.BinaryPrefixes = []string{pinned}

	for name, look := range map[string]func(string) (string, error){
		"sibling directory": func(n string) (string, error) { return filepath.Join(sibling, n), nil },
		"symlink out":       func(n string) (string, error) { return filepath.Join(pinned, n), nil },
	} {
		f := &fakeCLI{sluisOut: tokenJSON("v", now.Add(time.Hour))}

		_, err := f.source(look).Token(context.Background(), cfg, edgeReq)
		if err == nil || !strings.Contains(err.Error(), "outside") || len(f.calls) != 0 {
			t.Errorf("%s: got %v after %d calls", name, err, len(f.calls))
		}
	}
}

func TestLifetimeBounds(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*Config)
		want   string
	}{
		"max":                {func(c *Config) { c.Lifetime = MaxLifetime }, ""},
		"over max":           {func(c *Config) { c.Lifetime = MaxLifetime + time.Second }, "at most"},
		"negative":           {func(c *Config) { c.Lifetime = -time.Hour }, "at most"},
		"floor 1m":           {func(c *Config) { c.MinRemaining = time.Minute }, ""},
		"floor under 1m":     {func(c *Config) { c.MinRemaining = 59 * time.Second }, "at least"},
		"floor over life":    {func(c *Config) { c.Lifetime = 10 * time.Minute; c.MinRemaining = 10 * time.Minute }, "under Lifetime"},
		"default floor, 10m": {func(c *Config) { c.Lifetime = 10 * time.Minute }, "under Lifetime"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := testCfg()
			tc.mutate(&cfg)

			err := cfg.Validate()
			if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}

	// Whatever the config, nothing is asked for or minted beyond MaxLifetime,
	// and an answer past MaxLifetime + slack is refused.
	if got := (Config{Lifetime: 5 * time.Hour}).lifetime(); got != MaxLifetime {
		t.Errorf("lifetime %s", got)
	}

	t.Setenv(testBreakGlassEnv, "")

	f := &fakeCLI{sluisOut: tokenJSON("v", now.Add(MaxLifetime+3*time.Minute))}
	if _, err := f.source(nixPath).Token(context.Background(), testCfg(), edgeReq); err == nil || !strings.Contains(err.Error(), "longer than") {
		t.Fatalf("got %v", err)
	}
}

func TestBreakGlassFieldRules(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*BreakGlass)
		want   string
	}{
		"env lowercase":   {func(b *BreakGlass) { b.Env = "example_breakglass" }, "must match"},
		"env ordinary":    {func(b *BreakGlass) { b.Env = "PATH" }, "must match"},
		"env CI":          {func(b *BreakGlass) { b.Env = "CI" }, "must match"},
		"env no marker":   {func(b *BreakGlass) { b.Env = "EXAMPLE_CLOUDFLARE" }, "must match"},
		"env digit lead":  {func(b *BreakGlass) { b.Env = "1BREAKGLASS" }, "must match"},
		"env bare marker": {func(b *BreakGlass) { b.Env = "BREAKGLASS" }, "must match"},
		"env marker":      {func(b *BreakGlass) { b.Env = "X_BREAKGLASS_ON" }, ""},
		"account dash":    {func(b *BreakGlass) { b.Account = "--session=x" }, "hyphen"},
		"vault dash":      {func(b *BreakGlass) { b.Vault = "-v" }, "hyphen"},
		"item dash":       {func(b *BreakGlass) { b.Item = "-i" }, "hyphen"},
		"field dash":      {func(b *BreakGlass) { b.Field = "-f" }, "hyphen"},
		"item query":      {func(b *BreakGlass) { b.Item = "i?attribute=otp" }, "? or #"},
		"field query":     {func(b *BreakGlass) { b.Field = "f?attribute=otp" }, "? or #"},
		"field fragment":  {func(b *BreakGlass) { b.Field = "f#x" }, "? or #"},
		"dash inside":     {func(b *BreakGlass) { b.Item = "cf-root" }, ""},
	} {
		t.Run(name, func(t *testing.T) {
			b := testCfg().BreakGlass
			tc.mutate(&b)

			err := b.Validate()
			if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestRequestFieldRules(t *testing.T) {
	t.Setenv(testBreakGlassEnv, "")

	for name, tc := range map[string]struct {
		req  Request
		want string
	}{
		"ok":                  {edgeReq, ""},
		"r2 without account":  {Request{Preset: "example-r2", R2: true}, ""},
		"api without account": {Request{Preset: "example-edge"}, "no account id"},
		"short account":       {Request{Preset: "example-edge", AccountID: "abc"}, "account id"},
		"account path":        {Request{Preset: "example-edge", AccountID: "../" + testAccount[3:]}, "account id"},
		"upper account":       {Request{Preset: "example-edge", AccountID: strings.ToUpper(testAccount)}, "account id"},
		"r2 bad account":      {Request{Preset: "example-r2", R2: true, AccountID: "x/y"}, "account id"},
		"preset empty":        {Request{AccountID: testAccount}, "preset"},
		"preset upper":        {Request{Preset: "Example", AccountID: testAccount}, "preset"},
		"preset flag":         {Request{Preset: "--lifetime", AccountID: testAccount}, "preset"},
		"preset slash":        {Request{Preset: "a/b", AccountID: testAccount}, "preset"},
		"preset space":        {Request{Preset: "a b", AccountID: testAccount}, "preset"},
		"preset long":         {Request{Preset: strings.Repeat("a", 64), AccountID: testAccount}, "preset"},
		"preset 63":           {Request{Preset: strings.Repeat("a", 63), AccountID: testAccount}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			var out string
			if tc.req.R2 {
				b, _ := json.Marshal(map[string]any{"Version": 1, "AccessKeyId": "i", "SecretAccessKey": "s", "Expiration": now.Add(time.Hour).Format(time.RFC3339)})
				out = string(b)
			} else {
				out = tokenJSON("v", now.Add(time.Hour))
			}

			f := &fakeCLI{sluisOut: out}

			_, err := f.source(nixPath).Token(context.Background(), testCfg(), tc.req)
			if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}

			if tc.want != "" && len(f.calls) != 0 {
				t.Errorf("%d CLI calls after a refused request", len(f.calls))
			}
		})
	}
}

// The account id is a path segment: it is escaped, whatever reaches the client.
func TestAccountIsPathEscaped(t *testing.T) {
	var got string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.EscapedPath()
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]string{"status": "active"}})
	}))
	t.Cleanup(srv.Close)
	useAPI(t, srv.URL)

	c, err := newCFClient("a/b?x", "t")
	if err != nil {
		t.Fatal(err)
	}

	if err := c.verify(context.Background()); err != nil {
		t.Fatal(err)
	}

	if got != "/accounts/a%2Fb%3Fx/tokens/verify" {
		t.Errorf("path %q", got)
	}
}
