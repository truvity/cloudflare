package broker

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/cloudflare/v2/internal/config"
	"github.com/truvity/cloudflare/v2/internal/mint"
)

// testIssuer is a minimal local OIDC provider, enough to exercise New and
// Broker.Mint end to end without a real issuer or a real Cloudflare
// account.
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

func (ti *testIssuer) token(t *testing.T, audience string, groups []string) string {
	t.Helper()

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: ti.key},
		(&jose.SignerOptions{}).WithHeader("kid", jose.HeaderKey("k1")).WithType("JWT"))
	require.NoError(t, err)

	claims := josejwt.Claims{
		Issuer:   ti.server.URL,
		Subject:  "ci:example/repo",
		Audience: josejwt.Audience{audience},
		Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt: josejwt.NewNumericDate(time.Now().Add(-time.Minute)),
	}

	raw, err := josejwt.Signed(signer).Claims(claims).Claims(map[string]any{"groups": groups}).Serialize()
	require.NoError(t, err)

	return raw
}

func testConfig(issuer string) *config.Config {
	return &config.Config{
		Issuer:      issuer,
		Audience:    "r2-broker",
		GroupsClaim: "groups",
		Account:     config.Account{ID: "example-account-id", ParentTokenID: "parent-id", ParentTokenEnv: "TOKEN"},
		Minting:     config.Minting{Mode: config.MintModeLocal},
		Grants: []config.Grant{
			{
				Group: "ci:cache:writer", Bucket: "example-bucket", Prefixes: []string{"go-build/"},
				Permission: config.PermissionReadWrite, TTLSeconds: 900,
			},
		},
	}
}

func (ti *testIssuer) issuerURL() string { return ti.server.URL }

func TestNewRequiresParentToken(t *testing.T) {
	ti := newTestIssuer(t)

	_, err := New(context.Background(), testConfig(ti.issuerURL()), mint.ParentToken{}, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parent token id and value are both required")
}

func TestBrokerMintEndToEnd(t *testing.T) {
	ti := newTestIssuer(t)
	cfg := testConfig(ti.issuerURL())

	b, err := New(context.Background(), cfg, mint.ParentToken{ID: "parent-id", Value: "parent-secret"}, nil, nil)
	require.NoError(t, err)

	token := ti.token(t, "r2-broker", []string{"ci:cache:writer"})

	result := b.Mint(context.Background(), Request{Token: token, Prefixes: []string{"go-build/"}})
	require.Equal(t, OutcomeMinted, result.Outcome, "%+v", result.Err)
	assert.Equal(t, "ci:example/repo", result.Subject)
	assert.Equal(t, "example-bucket", result.Decision.Bucket)
	assert.NotEmpty(t, result.Credential.AccessKeyID)
	assert.NotEmpty(t, result.Credential.SessionToken)

	// The credential is a locally-signed one (mode: local, no API
	// fallback needed): its session token decodes to "jwt/<jwt>",
	// verifiable against SHA-256(parent secret).
	decoded, err := base64.StdEncoding.DecodeString(result.Credential.SessionToken)
	require.NoError(t, err)
	rawJWT, ok := strings.CutPrefix(string(decoded), "jwt/")
	require.True(t, ok)
	sum := sha256.Sum256([]byte("parent-secret"))
	parsed, err := jose.ParseSigned(rawJWT, []jose.SignatureAlgorithm{jose.HS256})
	require.NoError(t, err)
	_, err = parsed.Verify(sum[:])
	require.NoError(t, err)
}

func TestBrokerMintNoToken(t *testing.T) {
	ti := newTestIssuer(t)
	b, err := New(context.Background(), testConfig(ti.issuerURL()), mint.ParentToken{ID: "id", Value: "secret"}, nil, nil)
	require.NoError(t, err)

	result := b.Mint(context.Background(), Request{})
	assert.Equal(t, OutcomeUnauthenticated, result.Outcome)
	require.Error(t, result.Err)
}

func TestBrokerMintBadToken(t *testing.T) {
	ti := newTestIssuer(t)
	b, err := New(context.Background(), testConfig(ti.issuerURL()), mint.ParentToken{ID: "id", Value: "secret"}, nil, nil)
	require.NoError(t, err)

	result := b.Mint(context.Background(), Request{Token: "not-a-jwt"})
	assert.Equal(t, OutcomeUnauthenticated, result.Outcome)
	require.Error(t, result.Err)
	assert.Empty(t, result.Subject)
}

func TestBrokerMintWrongAudience(t *testing.T) {
	ti := newTestIssuer(t)
	b, err := New(context.Background(), testConfig(ti.issuerURL()), mint.ParentToken{ID: "id", Value: "secret"}, nil, nil)
	require.NoError(t, err)

	token := ti.token(t, "some-other-audience", []string{"ci:cache:writer"})
	result := b.Mint(context.Background(), Request{Token: token})
	assert.Equal(t, OutcomeUnauthenticated, result.Outcome)
}

func TestBrokerMintNoMatchingGroup(t *testing.T) {
	ti := newTestIssuer(t)
	b, err := New(context.Background(), testConfig(ti.issuerURL()), mint.ParentToken{ID: "id", Value: "secret"}, nil, nil)
	require.NoError(t, err)

	token := ti.token(t, "r2-broker", []string{"some:other:group"})
	result := b.Mint(context.Background(), Request{Token: token})
	assert.Equal(t, OutcomeRefused, result.Outcome)
	require.Error(t, result.Err)
	assert.Contains(t, result.Err.Error(), "no group in the token maps to a grant")
	assert.Equal(t, "ci:example/repo", result.Subject, "subject is known even on refusal")
}

func TestBrokerMintAmbiguousRequestIsRefused(t *testing.T) {
	ti := newTestIssuer(t)
	cfg := testConfig(ti.issuerURL())
	cfg.Grants = append(cfg.Grants, config.Grant{
		Group: "ci:cache:writer", Bucket: "example-bucket", Prefixes: []string{"bazel-remote/"},
		Permission: config.PermissionReadWrite, TTLSeconds: 900,
	})
	b, err := New(context.Background(), cfg, mint.ParentToken{ID: "id", Value: "secret"}, nil, nil)
	require.NoError(t, err)

	token := ti.token(t, "r2-broker", []string{"ci:cache:writer"})
	// No prefix named: two rows now match by group+bucket alone.
	result := b.Mint(context.Background(), Request{Token: token})
	assert.Equal(t, OutcomeRefused, result.Outcome)
}

// failingMinter always errs, standing in for "local signing broke and the
// API fallback also failed" without needing a real Cloudflare account.
type failingMinter struct{}

func (failingMinter) Mint(context.Context, mint.Request) (mint.Credential, error) {
	return mint.Credential{}, errSimulatedMintFailure
}

var errSimulatedMintFailure = errors.New("mint: simulated total failure")

func TestBrokerMintFailurePropagatesOutcome(t *testing.T) {
	ti := newTestIssuer(t)
	cfg := testConfig(ti.issuerURL())

	b, err := New(context.Background(), cfg, mint.ParentToken{ID: "id", Value: "secret"}, nil, nil)
	require.NoError(t, err)

	b.Minter = failingMinter{}

	token := ti.token(t, "r2-broker", []string{"ci:cache:writer"})
	result := b.Mint(context.Background(), Request{Token: token, Prefixes: []string{"go-build/"}})
	assert.Equal(t, OutcomeMintFailed, result.Outcome)
	require.Error(t, result.Err)
	assert.Equal(t, "example-bucket", result.Decision.Bucket, "decide's own result is kept even though mint failed")
}

func TestBuildMinterSelectsAPIMode(t *testing.T) {
	cfg := testConfig("https://issuer.example")
	cfg.Minting.Mode = config.MintModeAPI

	m := buildMinter(cfg, mint.ParentToken{ID: "id", Value: "secret"}, nil, nil)
	_, isAPI := m.(*mint.APIMinter)
	assert.True(t, isAPI, "MintModeAPI must select a bare APIMinter, not a CompositeMinter")
}

func TestBuildMinterDefaultsToCompositeLocalFirst(t *testing.T) {
	cfg := testConfig("https://issuer.example")
	cfg.Minting.Mode = config.MintModeLocal

	m := buildMinter(cfg, mint.ParentToken{ID: "id", Value: "secret"}, nil, nil)
	_, isComposite := m.(*mint.CompositeMinter)
	assert.True(t, isComposite, "MintModeLocal must select a CompositeMinter (local first, API fallback)")
}
