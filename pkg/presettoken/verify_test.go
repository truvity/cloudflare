package presettoken

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/truvity/cloudflare/v2/pkg/account"
)

// TestMain points the API at a server that accepts every token, and makes
// waits instant, so no test reaches Cloudflare or sleeps; a test that cares
// replaces either.
func TestMain(m *testing.M) {
	srv := httptest.NewServer((&fakeVerify{}).handler())
	cloudflareAPI = srv.URL
	sleep = func(context.Context, time.Duration) error { return nil }

	code := m.Run()

	srv.Close()
	os.Exit(code)
}

// fakeVerify answers GET /accounts/<account>/tokens/verify: 401 (code
// 10000) for the first reject calls, then active.
type fakeVerify struct {
	mu     sync.Mutex
	reject int
	calls  []string // Authorization of each call
	paths  []string
}

func (f *fakeVerify) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.calls = append(f.calls, r.Header.Get("Authorization"))
		f.paths = append(f.paths, r.Method+" "+r.URL.Path)
		n := len(f.calls)
		f.mu.Unlock()

		if n <= f.reject {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []map[string]any{{"code": 10000, "message": "Authentication error"}}})

			return
		}

		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]string{"id": "tok-id", "status": "active"}})
	})
}

// sleeps records each wait and returns at once.
type sleeps struct {
	mu sync.Mutex
	d  []time.Duration
}

func (s *sleeps) use(t *testing.T) {
	t.Helper()

	old := sleep
	sleep = func(_ context.Context, d time.Duration) error {
		s.mu.Lock()
		s.d = append(s.d, d)
		s.mu.Unlock()

		return nil
	}

	t.Cleanup(func() { sleep = old })
}

func captureStderr(t *testing.T) *os.File {
	t.Helper()

	f, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}

	return f
}

func readAll(t *testing.T, f *os.File) string {
	t.Helper()

	_, _ = f.Seek(0, 0)
	b, _ := io.ReadAll(f)

	return string(b)
}

// A just-minted token Cloudflare refuses twice (401, code 10000) is retried
// every second and handed out once accepted; the token is sent only as its
// own bearer to the account's verify endpoint, and printed nowhere.
func TestNewTokenIsVerifiedBeforeUse(t *testing.T) {
	t.Setenv(testBreakGlassEnv, "")

	fv := &fakeVerify{reject: 2}
	srv := httptest.NewServer(fv.handler())
	t.Cleanup(srv.Close)
	useAPI(t, srv.URL)

	var sl sleeps
	sl.use(t)

	stderr := captureStderr(t)
	f := &fakeCLI{sluisOut: tokenJSON("edge-value", now.Add(time.Hour))}
	s := Source{Run: f.run, LookPath: nixPath, Now: func() time.Time { return now }, Stderr: stderr}

	cred, err := s.Token(context.Background(), testCfg(), Request{Preset: "example-edge", AccountID: testAccount})
	if err != nil {
		t.Fatal(err)
	}

	if cred.Token != "edge-value" {
		t.Fatalf("token %q", cred.Token)
	}

	if len(fv.calls) != 3 {
		t.Fatalf("%d verify calls, want 3", len(fv.calls))
	}

	for i, a := range fv.calls {
		if a != "Bearer edge-value" || fv.paths[i] != "GET /accounts/"+testAccount+"/tokens/verify" {
			t.Errorf("call %d: %s with the wrong bearer", i, fv.paths[i])
		}
	}

	if len(sl.d) != 2 || sl.d[0] != verifyEvery || sl.d[1] != verifyEvery {
		t.Errorf("waits %v, want two of %s", sl.d, verifyEvery)
	}

	if out := readAll(t, stderr); strings.Contains(out, "edge-value") || !strings.Contains(out, "Authentication error") {
		t.Errorf("stderr %q", out)
	}
}

// A token Cloudflare never accepts fails the run after a bounded number of
// calls, and the error does not carry it.
func TestNewTokenNeverAccepted(t *testing.T) {
	t.Setenv(testBreakGlassEnv, "")

	fv := &fakeVerify{reject: 1 << 30}
	srv := httptest.NewServer(fv.handler())
	t.Cleanup(srv.Close)
	useAPI(t, srv.URL)

	var sl sleeps
	sl.use(t)

	f := &fakeCLI{sluisOut: tokenJSON("edge-value", now.Add(time.Hour))}
	s := Source{Run: f.run, LookPath: nixPath, Now: func() time.Time { return now }, Stderr: captureStderr(t)}

	_, err := s.Token(context.Background(), testCfg(), Request{Preset: "example-edge", AccountID: testAccount})
	if err == nil || !strings.Contains(err.Error(), "did not accept") || strings.Contains(err.Error(), "edge-value") {
		t.Fatalf("got %v", err)
	}

	if len(fv.calls) != verifyAttempts || verifyAttempts != 21 {
		t.Errorf("%d verify calls, want %d (20s at 1s)", len(fv.calls), verifyAttempts)
	}
}

// An R2 pair has no verify endpoint: it is left alone for r2Settle, and
// nothing is sent to Cloudflare.
func TestNewR2PairWaits(t *testing.T) {
	t.Setenv(testBreakGlassEnv, "")

	fv := &fakeVerify{}
	srv := httptest.NewServer(fv.handler())
	t.Cleanup(srv.Close)
	useAPI(t, srv.URL)

	var sl sleeps
	sl.use(t)

	out, _ := json.Marshal(map[string]any{"Version": 1, "AccessKeyId": "ak", "SecretAccessKey": "sk", "Expiration": now.Add(time.Hour).Format(time.RFC3339)})
	f := &fakeCLI{sluisOut: string(out)}
	s := Source{Run: f.run, LookPath: nixPath, Now: func() time.Time { return now }}

	if _, err := s.Token(context.Background(), testCfg(), Request{Preset: "example-r2-admin", R2: true, AccountID: testAccount}); err != nil {
		t.Fatal(err)
	}

	if len(fv.calls) != 0 || len(sl.d) != 1 || sl.d[0] != r2Settle {
		t.Errorf("verify calls %d, waits %v", len(fv.calls), sl.d)
	}
}

// Break-glass verifies the child it minted, as the child, not as the root.
func TestBreakGlassVerifiesTheChild(t *testing.T) {
	t.Setenv(testBreakGlassEnv, "1")

	cf := &fakeCloudflare{}
	srv := httptest.NewServer(cf.handler(t))
	t.Cleanup(srv.Close)
	useAPI(t, srv.URL)

	f := &fakeCLI{opOut: "root-value"}
	s := Source{Run: f.run, LookPath: nixPath, Now: func() time.Time { return now }, Stderr: captureStderr(t)}

	cred, err := s.Token(context.Background(), testCfg(), Request{Preset: "example-edge", AccountID: testAccount, Policies: []account.ChildTokenPolicy{
		{PermissionGroups: []string{"DNS Write"}, Scope: account.ZoneScope{ZoneID: testAccount}},
	}})
	if err != nil {
		t.Fatal(err)
	}

	if cred.Token != "child-value" {
		t.Fatalf("token %q", cred.Token)
	}

	if last := cf.auth[len(cf.auth)-1]; last != "Bearer child-value" {
		t.Errorf("the verify went with %q", last)
	}
}
