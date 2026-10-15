package staticsite

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeECR is the ECR API: it issues AWS:<password> tokens, one new password
// per call, valid for 12 hours of the fake clock.
type fakeECR struct {
	mu    sync.Mutex
	clock *fakeClock
	calls int
	err   error
	pass  string // the password last issued
}

func (f *fakeECR) GetAuthorizationToken(
	_ context.Context, _ *ecr.GetAuthorizationTokenInput, _ ...func(*ecr.Options),
) (*ecr.GetAuthorizationTokenOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	f.pass = "s3cret-pass-" + strings.Repeat("x", f.calls)
	tok := base64.StdEncoding.EncodeToString([]byte("AWS:" + f.pass))
	exp := f.clock.Now().Add(12 * time.Hour)
	return &ecr.GetAuthorizationTokenOutput{AuthorizationData: []ecrtypes.AuthorizationData{{AuthorizationToken: &tok, ExpiresAt: &exp}}}, nil
}

// revoke makes the registry stop accepting the password issued last.
func (f *fakeECR) revoke() {
	f.mu.Lock()
	f.pass = "s3cret-revoked"
	f.mu.Unlock()
}

func (f *fakeECR) state() (calls int, pass string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls, f.pass
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newFakeECR() (*fakeECR, *fakeClock) {
	clk := &fakeClock{t: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)}
	return &fakeECR{clock: clk}, clk
}

func TestECRParseHost(t *testing.T) {
	cases := map[string]struct {
		host string
		ok   bool
		want ecrHost
	}{
		"commercial": {"123456789012.dkr.ecr.eu-central-1.amazonaws.com", true, ecrHost{Region: "eu-central-1"}},
		"fips":       {"123456789012.dkr.ecr-fips.us-east-1.amazonaws.com", true, ecrHost{Region: "us-east-1", FIPS: true}},
		"china":      {"123456789012.dkr.ecr.cn-north-1.amazonaws.com.cn", true, ecrHost{Region: "cn-north-1"}},
		"gov":        {"123456789012.dkr.ecr.us-gov-west-1.amazonaws.com", true, ecrHost{Region: "us-gov-west-1"}},
		"ghcr":       {"ghcr.io", false, ecrHost{}},
		"public ecr": {"public.ecr.aws", false, ecrHost{}},
		"short acct": {"1234.dkr.ecr.eu-central-1.amazonaws.com", false, ecrHost{}},
		"suffix":     {"123456789012.dkr.ecr.eu-central-1.amazonaws.com.evil.example", false, ecrHost{}},
		"prefix":     {"evil.123456789012.dkr.ecr.eu-central-1.amazonaws.com", false, ecrHost{}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got, ok := parseECRHost(c.host)
			assert.Equal(t, c.ok, ok)
			if c.ok {
				assert.Equal(t, c.want, got)
			}
		})
	}
	assert.Equal(t, "123456789012.dkr.ecr.eu-central-1.amazonaws.com", hostOnly("123456789012.dkr.ecr.eu-central-1.amazonaws.com:443"))
}

func TestECRTokenDecodedCachedAndRefreshed(t *testing.T) {
	api, clk := newFakeECR()
	src := &ecrTokenSource{api: api, now: clk.Now, log: slog.New(slog.DiscardHandler)}
	ctx := t.Context()

	user, pass, err := src.get(ctx)
	require.NoError(t, err)
	assert.Equal(t, "AWS", user)
	_, want := api.state()
	assert.Equal(t, want, pass)

	// Cached for half of the token's 12 hours.
	clk.Add(5*time.Hour + 59*time.Minute)
	_, pass2, err := src.get(ctx)
	require.NoError(t, err)
	assert.Equal(t, pass, pass2)
	calls, _ := api.state()
	assert.Equal(t, 1, calls)

	// Past the half-life it is replaced.
	clk.Add(2 * time.Minute)
	_, pass3, err := src.get(ctx)
	require.NoError(t, err)
	assert.NotEqual(t, pass, pass3)
	calls, _ = api.state()
	assert.Equal(t, 2, calls)

	// A failed refresh keeps the token while it has not expired...
	api.mu.Lock()
	api.err = errors.New("throttled")
	api.mu.Unlock()
	clk.Add(7 * time.Hour)
	_, pass4, err := src.get(ctx)
	require.NoError(t, err)
	assert.Equal(t, pass3, pass4)
	// ...and fails once it has.
	clk.Add(6 * time.Hour)
	_, _, err = src.get(ctx)
	assert.ErrorContains(t, err, "throttled")

	// invalidate forces a fetch.
	api.mu.Lock()
	api.err = nil
	api.mu.Unlock()
	src.invalidate()
	_, _, err = src.get(ctx)
	require.NoError(t, err)
}

func TestECRTokenMalformed(t *testing.T) {
	clk := &fakeClock{t: time.Now()}
	for name, tok := range map[string]string{
		"not base64": "!!!",
		"no colon":   base64.StdEncoding.EncodeToString([]byte("AWSpassword")),
		"empty pass": base64.StdEncoding.EncodeToString([]byte("AWS:")),
	} {
		t.Run(name, func(t *testing.T) {
			src := &ecrTokenSource{api: staticECR{tok: tok}, now: clk.Now, log: slog.New(slog.DiscardHandler)}
			_, _, err := src.get(t.Context())
			require.Error(t, err)
			assert.NotContains(t, err.Error(), tok)
		})
	}
	src := &ecrTokenSource{api: staticECR{empty: true}, now: clk.Now, log: slog.New(slog.DiscardHandler)}
	_, _, err := src.get(t.Context())
	assert.ErrorContains(t, err, "no authorization data")
}

type staticECR struct {
	tok   string
	empty bool
}

func (s staticECR) GetAuthorizationToken(context.Context, *ecr.GetAuthorizationTokenInput, ...func(*ecr.Options)) (*ecr.GetAuthorizationTokenOutput, error) {
	if s.empty {
		return &ecr.GetAuthorizationTokenOutput{}, nil
	}
	return &ecr.GetAuthorizationTokenOutput{AuthorizationData: []ecrtypes.AuthorizationData{{AuthorizationToken: &s.tok}}}, nil
}

// authedRegistry fronts the in-process registry at host with HTTP basic
// auth: only AWS:<current password> gets through. It returns its host:port.
func authedRegistry(t *testing.T, backend string, accept func() string) (host string, rejected *int) {
	t.Helper()
	u, err := url.Parse("http://" + backend)
	require.NoError(t, err)
	proxy := httputil.NewSingleHostReverseProxy(u)
	n := new(int)
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "AWS" || pass != accept() {
			mu.Lock()
			*n++
			mu.Unlock()
			w.Header().Set("WWW-Authenticate", `Basic realm="ecr"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://"), n
}

// ecrTestAuth makes a registryAuth that treats the test registry's host as an
// ECR host in eu-central-1 and uses api in place of the SDK.
func ecrTestAuth(t *testing.T, cfg *Config, api ECRAPI, clk *fakeClock, logs *bytes.Buffer) *registryAuth {
	t.Helper()
	t.Setenv("HOME", t.TempDir()) // no ~/.docker/config.json of the machine
	ra := newRegistryAuth(cfg, slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	ra.parseHost = func(string) (ecrHost, bool) { return ecrHost{Region: "eu-central-1"}, true }
	ra.newAPI = func(context.Context, ecrHost) (ECRAPI, error) { return api, nil }
	ra.now = clk.Now
	return ra
}

func siteRegistry(t *testing.T) (backend string, dgst string) {
	t.Helper()
	data := makeTar(t, true, []tarEntry{{name: "index.html", body: "<h1>hi</h1>"}})
	host, d := pushLayers(t, map[string]layer{"a": {mt: ocispec.MediaTypeImageLayerGzip, data: data, unpack: true}}, []string{"a"})
	return host, d.String()
}

func TestPullAuthenticatesToECRAndRecoversFromA401(t *testing.T) {
	backend, dgst := siteRegistry(t)
	api, clk := newFakeECR()
	host, rejected := authedRegistry(t, backend, func() string { _, p := api.state(); return p })
	cfg := pullCfg(host, "", dgst)
	var logs bytes.Buffer
	ra := ecrTestAuth(t, cfg, api, clk, &logs)

	dest := t.TempDir()
	_, err := pullWith(t.Context(), cfg, dest, ra)
	require.NoError(t, err)
	assert.FileExists(t, filepath.Join(dest, "index.html"))
	calls, pass := api.state()
	assert.Equal(t, 1, calls)

	// A second pull (a reload) reuses the cached token.
	_, err = pullWith(t.Context(), cfg, t.TempDir(), ra)
	require.NoError(t, err)
	calls, _ = api.state()
	assert.Equal(t, 1, calls)

	// Past the half-life a reload takes a new token.
	clk.Add(7 * time.Hour)
	_, err = pullWith(t.Context(), cfg, t.TempDir(), ra)
	require.NoError(t, err)
	calls, pass2 := api.state()
	assert.Equal(t, 2, calls)
	assert.NotEqual(t, pass, pass2)

	// The registry revokes the token early: the 401 drops it and the pull is
	// retried once with a fresh one.
	api.revoke()
	_, err = pullWith(t.Context(), cfg, t.TempDir(), ra)
	require.NoError(t, err)
	calls, _ = api.state()
	assert.Equal(t, 3, calls)
	assert.Positive(t, *rejected)

	out := logs.String()
	assert.Contains(t, out, "registry auth: ecr-sdk")
	assert.Contains(t, out, "registry refused the ecr token")
	assertNoCredentials(t, out, api)
}

// assertNoCredentials fails when the logs carry a password or token any
// fake call issued.
func assertNoCredentials(t *testing.T, logs string, api *fakeECR) {
	t.Helper()
	calls, _ := api.state()
	for i := 1; i <= calls; i++ {
		pass := "s3cret-pass-" + strings.Repeat("x", i)
		assert.NotContains(t, logs, pass)
		assert.NotContains(t, logs, base64.StdEncoding.EncodeToString([]byte("AWS:"+pass)))
	}
	assert.NotContains(t, logs, "s3cret")
}

func TestPullECRFailsWhenThereAreNoAWSCredentials(t *testing.T) {
	backend, dgst := siteRegistry(t)
	api, clk := newFakeECR()
	api.err = errors.New("failed to retrieve credentials: no EC2 IMDS role found")
	host, _ := authedRegistry(t, backend, func() string { return "never" })
	cfg := pullCfg(host, "", dgst)
	var logs bytes.Buffer
	_, err := pullWith(t.Context(), cfg, t.TempDir(), ecrTestAuth(t, cfg, api, clk, &logs))
	require.Error(t, err)
	assert.ErrorContains(t, err, "GetAuthorizationToken")
}

func TestRegistryAuthPrecedence(t *testing.T) {
	const ecrHostName = "123456789012.dkr.ecr.eu-central-1.amazonaws.com"
	home := t.TempDir()
	t.Setenv("HOME", home)

	cases := map[string]struct {
		mode, dockerDir, host string
		want                  string
		wantErr               bool
	}{
		"docker config wins over ecr":    {"", "/etc/registry-auth", ecrHostName, methodDockerConfig, false},
		"ecr host without docker config": {"", "", ecrHostName, methodECR, false},
		"ecr host with a port":           {"", "", ecrHostName + ":443", methodECR, false},
		"other host, no docker config":   {"", "", "ghcr.io", methodAnonymous, false},
		"other host, docker config":      {"auto", "/etc/registry-auth", "ghcr.io", methodDockerConfig, false},
		"explicit dockerconfig":          {"dockerconfig", "", ecrHostName, methodDockerConfig, false},
		"explicit none":                  {"none", "", ecrHostName, methodAnonymous, false},
		"explicit ecr":                   {"ecr", "/etc/registry-auth", ecrHostName, methodECR, false},
		"explicit ecr on a non-ECR host": {"ecr", "", "ghcr.io", "", true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := Defaults()
			cfg.RegistryAuth, cfg.DockerConfigDir = c.mode, c.dockerDir
			got, _, err := newRegistryAuth(&cfg, nil).resolve(c.host)
			if c.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, c.want, got)
		})
	}

	t.Run("~/.docker/config.json counts as configured", func(t *testing.T) {
		require.NoError(t, os.MkdirAll(filepath.Join(home, ".docker"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(home, ".docker", "config.json"), []byte(`{}`), 0o600))
		cfg := Defaults()
		got, _, err := newRegistryAuth(&cfg, nil).resolve(ecrHostName)
		require.NoError(t, err)
		assert.Equal(t, methodDockerConfig, got)
	})
}

func TestDockerConfigNeverCallsECR(t *testing.T) {
	backend, dgst := siteRegistry(t)
	api, clk := newFakeECR()
	cfg := pullCfg(backend, "", dgst)
	cfg.DockerConfigDir = t.TempDir() // configured, holds no credentials
	var logs bytes.Buffer
	ra := ecrTestAuth(t, cfg, api, clk, &logs)
	_, err := pullWith(t.Context(), cfg, t.TempDir(), ra)
	require.NoError(t, err)
	calls, _ := api.state()
	assert.Zero(t, calls)
	assert.Contains(t, logs.String(), "registry auth: dockerconfig")
}

func TestNonECRHostNeverCallsECR(t *testing.T) {
	backend, dgst := siteRegistry(t)
	cfg := pullCfg(backend, "", dgst)
	t.Setenv("HOME", t.TempDir())
	var logs bytes.Buffer
	ra := newRegistryAuth(cfg, slog.New(slog.NewJSONHandler(&logs, nil)))
	ra.newAPI = func(context.Context, ecrHost) (ECRAPI, error) {
		t.Fatal("the ECR client was built for a host that is not ECR")
		return nil, nil
	}
	_, err := pullWith(t.Context(), cfg, t.TempDir(), ra)
	require.NoError(t, err)
	assert.Contains(t, logs.String(), "registry auth: anonymous")
}

func TestECRCredentialIsForTheArtifactRegistryOnly(t *testing.T) {
	api, clk := newFakeECR()
	cfg := Defaults()
	var logs bytes.Buffer
	ra := ecrTestAuth(t, &cfg, api, clk, &logs)
	c, method, err := ra.client(t.Context(), "reg.example:5000")
	require.NoError(t, err)
	assert.Equal(t, methodECR, method)
	own, err := c.Credential(t.Context(), "reg.example:5000")
	require.NoError(t, err)
	assert.Equal(t, "AWS", own.Username)
	assert.NotEmpty(t, own.Password)
	other, err := c.Credential(t.Context(), "elsewhere.example")
	require.NoError(t, err)
	assert.Empty(t, other.Password)
}

func TestFromEnvRegistryAuth(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	c, err := FromEnv(env(map[string]string{"STATIC_SITE_ARTIFACT_REF": "r/x:1", "STATIC_SITE_REGISTRY_AUTH": "ecr", "DOCKER_CONFIG": "/d"}))
	require.NoError(t, err)
	assert.Equal(t, "ecr", c.RegistryAuth)
	assert.Equal(t, "/d", c.DockerConfigDir)
	_, err = FromEnv(env(map[string]string{"STATIC_SITE_ARTIFACT_REF": "r/x:1", "STATIC_SITE_REGISTRY_AUTH": "iam"}))
	assert.ErrorContains(t, err, "STATIC_SITE_REGISTRY_AUTH")
}
