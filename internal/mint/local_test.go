package mint

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/cloudflare/v2/internal/config"
)

// decodeSession splits a session token into the JWT's three parts and
// returns the raw JWT, the decoded header and the decoded claims, as JSON
// maps so that every field name is checked as R2 will read it.
func decodeSession(t *testing.T, sessionToken string) (string, map[string]any, map[string]any) {
	t.Helper()

	decoded, err := base64.StdEncoding.DecodeString(sessionToken)
	require.NoError(t, err)

	raw, ok := strings.CutPrefix(string(decoded), "jwt/")
	require.True(t, ok, `session token must be base64("jwt/" + jwt)`)

	parts := strings.Split(raw, ".")
	require.Len(t, parts, 3)

	var header, claims map[string]any

	for i, into := range []*map[string]any{&header, &claims} {
		body, err := base64.RawURLEncoding.DecodeString(parts[i])
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, into))
	}

	return raw, header, claims
}

// hs256 is the signature Cloudflare's example computes:
// SignJWT(...).sign(new TextEncoder().encode(parentSecretAccessKey)),
// i.e. HMAC-SHA256 keyed with the UTF-8 bytes of the hex secret.
func hs256(key, signingInput string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(signingInput))

	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func TestLocalMinterFollowsCloudflaresExample(t *testing.T) {
	fixedNow := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)

	m := &LocalMinter{
		Token: ParentToken{ID: "parent-token-id", Value: "parent-token-secret-value"},
		Now:   func() time.Time { return fixedNow },
	}

	cred, err := m.Mint(context.Background(), Request{
		AccountID:  "example-account-id",
		Bucket:     "example-bucket",
		Permission: config.PermissionReadWrite,
		TTLSeconds: 900,
	})
	require.NoError(t, err)

	raw, header, claims := decodeSession(t, cred.SessionToken)

	assert.Equal(t, map[string]any{"alg": "HS256", "typ": "JWT"}, header)
	assert.Equal(t, map[string]any{
		"sub":    "example-account-id",
		"iss":    "parent-token-id",
		"aud":    "example-account-id.r2.cloudflarestorage.com",
		"iat":    float64(fixedNow.Unix()),
		"exp":    float64(fixedNow.Add(900 * time.Second).Unix()),
		"bucket": "example-bucket",
		"scope":  "object-read-write",
	}, claims, "no paths claim when the credential is not narrowed")

	// The key is the parent SECRET ACCESS KEY as text: hex(sha256(value)).
	parentSecret := sha256.Sum256([]byte("parent-token-secret-value"))
	key := hex.EncodeToString(parentSecret[:])
	assert.Equal(t, key, ParentSecretAccessKey("parent-token-secret-value"))

	cut := strings.LastIndex(raw, ".")
	assert.Equal(t, hs256(key, raw[:cut]), raw[cut+1:], "signed with the hex secret's bytes")
	assert.NotEqual(t, hs256(string(parentSecret[:]), raw[:cut]), raw[cut+1:],
		"the digest's raw bytes are the v2.7.1 key, which R2 refuses")

	secret := sha256.Sum256([]byte(raw))
	assert.Equal(t, "parent-token-id", cred.AccessKeyID)
	assert.Equal(t, hex.EncodeToString(secret[:]), cred.SecretAccessKey)
	assert.Equal(t, fixedNow.Add(900*time.Second), cred.Expiration)
}

func TestLocalMinterNarrowsWithPaths(t *testing.T) {
	m := &LocalMinter{Token: ParentToken{ID: "id", Value: "v"}}

	cred, err := m.Mint(context.Background(), Request{
		AccountID: "acct", Bucket: "b", Prefixes: []string{"go-build/"},
		Permission: config.PermissionReadOnly, TTLSeconds: 60,
	})
	require.NoError(t, err)

	_, _, claims := decodeSession(t, cred.SessionToken)
	assert.Equal(t, "object-read-only", claims["scope"])
	assert.Equal(t, map[string]any{
		"prefixPaths": []any{"go-build/"},
		"objectPaths": []any{},
	}, claims["paths"])
}

func TestLocalMinterHostOverride(t *testing.T) {
	m := &LocalMinter{Token: ParentToken{ID: "id", Value: "v"}, Host: "acct.eu.r2.cloudflarestorage.com"}

	cred, err := m.Mint(context.Background(), Request{
		AccountID: "acct", Bucket: "b", Permission: config.PermissionReadOnly, TTLSeconds: 60,
	})
	require.NoError(t, err)

	_, _, claims := decodeSession(t, cred.SessionToken)
	assert.Equal(t, "acct.eu.r2.cloudflarestorage.com", claims["aud"])
}

func TestLocalMinterWrongSecretDoesNotVerify(t *testing.T) {
	m := &LocalMinter{Token: ParentToken{ID: "id", Value: "correct-secret"}}

	cred, err := m.Mint(context.Background(), Request{
		AccountID: "acct", Bucket: "b", Permission: config.PermissionReadOnly, TTLSeconds: 60,
	})
	require.NoError(t, err)

	raw, _, _ := decodeSession(t, cred.SessionToken)
	cut := strings.LastIndex(raw, ".")
	assert.NotEqual(t, hs256(ParentSecretAccessKey("wrong-secret"), raw[:cut]), raw[cut+1:],
		"a credential signed with a different parent secret must not verify")
}

func TestLocalMinterRequiresParentToken(t *testing.T) {
	req := Request{AccountID: "acct", Bucket: "b", Permission: config.PermissionReadOnly, TTLSeconds: 60}

	_, err := (&LocalMinter{Token: ParentToken{ID: "id"}}).Mint(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parent token value is required")

	_, err = (&LocalMinter{Token: ParentToken{Value: "v"}}).Mint(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parent token id is required")
}

func TestLocalMinterValidatesRequest(t *testing.T) {
	m := &LocalMinter{Token: ParentToken{ID: "id", Value: "secret"}}

	cases := []struct {
		name string
		req  Request
	}{
		{"no bucket", Request{AccountID: "acct", Permission: config.PermissionReadOnly, TTLSeconds: 60}},
		{"bad permission", Request{AccountID: "acct", Bucket: "b", Permission: "admin-read-write", TTLSeconds: 60}},
		{"zero ttl", Request{AccountID: "acct", Bucket: "b", Permission: config.PermissionReadOnly}},
		{"no account", Request{Bucket: "b", Permission: config.PermissionReadOnly, TTLSeconds: 60}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := m.Mint(context.Background(), tc.req)
			assert.Error(t, err)
		})
	}
}
