package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/cloudflare/v2/internal/broker"
	"github.com/truvity/cloudflare/v2/internal/config"
	"github.com/truvity/cloudflare/v2/internal/mint"
)

// testIssuer, shared shape with internal/broker's own test helper but
// package-local: cmd/r2broker cannot import an internal test file from
// another package.
type testIssuer struct {
	server *httptest.Server
	key    *rsa.PrivateKey
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ti := &testIssuer{key: key}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                ti.server.URL,
			"jwks_uri":                              ti.server.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported":              []string{"id_token"},
			"subject_types_supported":               []string{"public"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}},
		})
	})

	ti.server = httptest.NewServer(mux)
	t.Cleanup(ti.server.Close)

	return ti
}

func (ti *testIssuer) token(t *testing.T, groups []string) string {
	t.Helper()

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: ti.key},
		(&jose.SignerOptions{}).WithHeader("kid", jose.HeaderKey("k1")).WithType("JWT"))
	require.NoError(t, err)

	claims := josejwt.Claims{
		Issuer: ti.server.URL, Subject: "ci:example/repo", Audience: josejwt.Audience{"r2-broker"},
		Expiry: josejwt.NewNumericDate(time.Now().Add(time.Hour)), IssuedAt: josejwt.NewNumericDate(time.Now().Add(-time.Minute)),
	}

	raw, err := josejwt.Signed(signer).Claims(claims).Claims(map[string]any{"groups": groups}).Serialize()
	require.NoError(t, err)

	return raw
}

func testHandler(t *testing.T, issuer string) *credentialsHandler {
	t.Helper()

	cfg := &config.Config{
		Issuer: issuer, Audience: "r2-broker", GroupsClaim: "groups",
		Account: config.Account{ID: "example-account-id", ParentTokenID: "parent-id"},
		Minting: config.Minting{Mode: config.MintModeLocal},
		Grants: []config.Grant{
			{
				Group: "ci:cache:writer", Bucket: "example-bucket", Prefixes: []string{"go-build/"},
				Permission: config.PermissionReadWrite, TTLSeconds: 900,
			},
		},
	}

	b, err := broker.New(context.Background(), cfg, mint.ParentToken{ID: "parent-id", Value: "parent-secret"}, nil, nil)
	require.NoError(t, err)

	return &credentialsHandler{broker: b, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func doRequest(h *credentialsHandler, authz, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/credentials", strings.NewReader(body))
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	return rec
}

func TestCredentialsHandlerMints(t *testing.T) {
	ti := newTestIssuer(t)
	h := testHandler(t, ti.server.URL)

	rec := doRequest(h, "Bearer "+ti.token(t, []string{"ci:cache:writer"}), `{"prefixes":["go-build/"]}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var out credentialsResponseBody
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	assert.NotEmpty(t, out.AccessKeyID)
	assert.NotEmpty(t, out.SecretAccessKey)
	assert.NotEmpty(t, out.SessionToken)
	assert.Equal(t, "example-bucket", out.Bucket)
	assert.NotEmpty(t, out.Expiration)
}

func TestCredentialsHandlerNoBodyUsesFullGrant(t *testing.T) {
	ti := newTestIssuer(t)
	h := testHandler(t, ti.server.URL)

	rec := doRequest(h, "Bearer "+ti.token(t, []string{"ci:cache:writer"}), "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
}

func TestCredentialsHandlerMissingAuthIs401(t *testing.T) {
	ti := newTestIssuer(t)
	h := testHandler(t, ti.server.URL)

	rec := doRequest(h, "", "")
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	var out errorResponseBody
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	assert.NotEmpty(t, out.Error)
}

func TestCredentialsHandlerBadTokenIs401(t *testing.T) {
	ti := newTestIssuer(t)
	h := testHandler(t, ti.server.URL)

	rec := doRequest(h, "Bearer not-a-jwt", "")
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestCredentialsHandlerNoMatchingGroupIs403(t *testing.T) {
	ti := newTestIssuer(t)
	h := testHandler(t, ti.server.URL)

	rec := doRequest(h, "Bearer "+ti.token(t, []string{"some:other:group"}), "")
	assert.Equal(t, http.StatusForbidden, rec.Code)

	var out errorResponseBody
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	assert.Contains(t, out.Error, "no group in the token maps to a grant")
}

func TestCredentialsHandlerMalformedBodyIs400(t *testing.T) {
	ti := newTestIssuer(t)
	h := testHandler(t, ti.server.URL)

	rec := doRequest(h, "Bearer "+ti.token(t, []string{"ci:cache:writer"}), "{not-json")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestCredentialsHandlerMintFailureIs502(t *testing.T) {
	ti := newTestIssuer(t)
	h := testHandler(t, ti.server.URL)
	h.broker.Minter = failingMinter{}

	rec := doRequest(h, "Bearer "+ti.token(t, []string{"ci:cache:writer"}), `{"prefixes":["go-build/"]}`)
	assert.Equal(t, http.StatusBadGateway, rec.Code)
}

// failingMinter always errs, standing in for "local signing broke and the
// API fallback also failed."
type failingMinter struct{}

func (failingMinter) Mint(context.Context, mint.Request) (mint.Credential, error) {
	return mint.Credential{}, errSimulatedMintFailure
}

var errSimulatedMintFailure = errors.New("mint: simulated total failure")

func TestHandleHealthz(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	handleHealthz(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "ok", rec.Body.String())
}

func TestBearerToken(t *testing.T) {
	assert.Equal(t, "abc", bearerToken("Bearer abc"))
	assert.Equal(t, "", bearerToken(""))
	assert.Equal(t, "", bearerToken("Basic abc"))
	assert.Equal(t, "abc", bearerToken("Bearer   abc"))
}
