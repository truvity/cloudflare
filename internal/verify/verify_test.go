package verify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	josejwt "github.com/go-jose/go-jose/v4/jwt"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testIssuer is a local OIDC provider: discovery document plus JWKS,
// serving both an RS256 and an ES384 signing key, so verify.New's
// acceptance of either algorithm can be exercised without a real
// provider.
type testIssuer struct {
	server   *httptest.Server
	rsaKey   *rsa.PrivateKey
	ecKey    *ecdsa.PrivateKey
	extraRSA *rsa.PrivateKey // a key NOT published in the JWKS, for bad-signature cases
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	extraRSA, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ti := &testIssuer{rsaKey: rsaKey, ecKey: ecKey, extraRSA: extraRSA}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                ti.server.URL,
			"jwks_uri":                              ti.server.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256", "ES384"},
			"response_types_supported":              []string{"id_token"},
			"subject_types_supported":               []string{"public"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				{Key: &rsaKey.PublicKey, KeyID: "rsa1", Algorithm: "RS256", Use: "sig"},
				{Key: &ecKey.PublicKey, KeyID: "ec1", Algorithm: "ES384", Use: "sig"},
			},
		})
	})

	ti.server = httptest.NewServer(mux)
	t.Cleanup(ti.server.Close)

	return ti
}

func (ti *testIssuer) issuer() string { return ti.server.URL }

type tokenOpts struct {
	alg      jose.SignatureAlgorithm
	kid      string
	key      any
	issuer   string
	audience string
	subject  string
	groups   []string
	expiry   time.Time
}

func (ti *testIssuer) sign(t *testing.T, o tokenOpts) string {
	t.Helper()

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: o.alg, Key: o.key},
		(&jose.SignerOptions{}).WithHeader("kid", jose.HeaderKey(o.kid)).WithType("JWT"))
	require.NoError(t, err)

	claims := josejwt.Claims{
		Issuer:   o.issuer,
		Subject:  o.subject,
		Audience: josejwt.Audience{o.audience},
		Expiry:   josejwt.NewNumericDate(o.expiry),
		IssuedAt: josejwt.NewNumericDate(time.Now().Add(-time.Minute)),
	}

	raw, err := josejwt.Signed(signer).
		Claims(claims).
		Claims(map[string]any{"groups": o.groups}).
		Serialize()
	require.NoError(t, err)

	return raw
}

func TestVerifyAcceptsRS256AndES384(t *testing.T) {
	ti := newTestIssuer(t)
	ctx := context.Background()

	v, err := New(ctx, ti.issuer(), "r2-broker", "groups")
	require.NoError(t, err)

	rsToken := ti.sign(t, tokenOpts{
		alg: jose.RS256, kid: "rsa1", key: ti.rsaKey,
		issuer: ti.issuer(), audience: "r2-broker", subject: "ci:example/repo",
		groups: []string{"ci:cache:reader"}, expiry: time.Now().Add(time.Hour),
	})

	res, err := v.Verify(ctx, rsToken)
	require.NoError(t, err)
	assert.Equal(t, "ci:example/repo", res.Subject)
	assert.Equal(t, []string{"ci:cache:reader"}, res.Groups)

	esToken := ti.sign(t, tokenOpts{
		alg: jose.ES384, kid: "ec1", key: ti.ecKey,
		issuer: ti.issuer(), audience: "r2-broker", subject: "workload:example",
		groups: []string{"ci:cache:writer", "ci:cache:reader"}, expiry: time.Now().Add(time.Hour),
	})

	res, err = v.Verify(ctx, esToken)
	require.NoError(t, err)
	assert.Equal(t, "workload:example", res.Subject)
	assert.Equal(t, []string{"ci:cache:writer", "ci:cache:reader"}, res.Groups)
}

func TestVerifyRefusesWrongAudience(t *testing.T) {
	ti := newTestIssuer(t)
	ctx := context.Background()

	v, err := New(ctx, ti.issuer(), "r2-broker", "groups")
	require.NoError(t, err)

	token := ti.sign(t, tokenOpts{
		alg: jose.RS256, kid: "rsa1", key: ti.rsaKey,
		issuer: ti.issuer(), audience: "some-other-audience", subject: "sub",
		expiry: time.Now().Add(time.Hour),
	})

	_, err = v.Verify(ctx, token)
	require.Error(t, err)
}

func TestVerifyRefusesWrongIssuer(t *testing.T) {
	ti := newTestIssuer(t)
	ctx := context.Background()

	v, err := New(ctx, ti.issuer(), "r2-broker", "groups")
	require.NoError(t, err)

	token := ti.sign(t, tokenOpts{
		alg: jose.RS256, kid: "rsa1", key: ti.rsaKey,
		issuer: "https://not-the-issuer.example", audience: "r2-broker", subject: "sub",
		expiry: time.Now().Add(time.Hour),
	})

	_, err = v.Verify(ctx, token)
	require.Error(t, err)
}

func TestVerifyRefusesExpiredToken(t *testing.T) {
	ti := newTestIssuer(t)
	ctx := context.Background()

	v, err := New(ctx, ti.issuer(), "r2-broker", "groups")
	require.NoError(t, err)

	token := ti.sign(t, tokenOpts{
		alg: jose.RS256, kid: "rsa1", key: ti.rsaKey,
		issuer: ti.issuer(), audience: "r2-broker", subject: "sub",
		expiry: time.Now().Add(-time.Hour),
	})

	_, err = v.Verify(ctx, token)
	require.Error(t, err)
}

func TestVerifyRefusesBadSignature(t *testing.T) {
	ti := newTestIssuer(t)
	ctx := context.Background()

	v, err := New(ctx, ti.issuer(), "r2-broker", "groups")
	require.NoError(t, err)

	// Signed with a real RS256 key, but one never published in the JWKS.
	token := ti.sign(t, tokenOpts{
		alg: jose.RS256, kid: "rsa1", key: ti.extraRSA,
		issuer: ti.issuer(), audience: "r2-broker", subject: "sub",
		expiry: time.Now().Add(time.Hour),
	})

	_, err = v.Verify(ctx, token)
	require.Error(t, err)
}

func TestNewRequiresIssuerAudienceAndGroupsClaim(t *testing.T) {
	ctx := context.Background()
	ti := newTestIssuer(t)

	_, err := New(ctx, "", "r2-broker", "groups")
	assert.ErrorContains(t, err, "issuer is required")

	_, err = New(ctx, ti.issuer(), "", "groups")
	assert.ErrorContains(t, err, "audience is required")

	_, err = New(ctx, ti.issuer(), "r2-broker", "")
	assert.ErrorContains(t, err, "groupsClaim is required")
}
