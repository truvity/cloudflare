package mint

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/cloudflare/v2/internal/config"
)

func TestLocalMinterMint(t *testing.T) {
	fixedNow := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)

	m := &LocalMinter{
		Token: ParentToken{ID: "parent-token-id", Value: "parent-token-secret-value"},
		Now:   func() time.Time { return fixedNow },
	}

	req := Request{
		AccountID:  "example-account-id",
		Bucket:     "example-bucket",
		Prefixes:   []string{"go-build/"},
		Permission: config.PermissionReadWrite,
		TTLSeconds: 900,
	}

	cred, err := m.Mint(context.Background(), req)
	require.NoError(t, err)

	assert.Equal(t, "parent-token-id", cred.AccessKeyID, "UNVERIFIED: assumed equal to the parent token's own id")
	assert.Equal(t, fixedNow.Add(900*time.Second), cred.Expiration)
	assert.NotEmpty(t, cred.SecretAccessKey)

	// The session token decodes to "jwt/<signed-jwt>".
	decoded, err := base64.StdEncoding.DecodeString(cred.SessionToken)
	require.NoError(t, err)

	rawJWT, ok := strings.CutPrefix(string(decoded), "jwt/")
	require.True(t, ok, "session token must be base64(\"jwt/\" + jwt), per the doc")

	// UNVERIFIED: SecretAccessKey is the hex SHA-256 of the raw JWT.
	sum := sha256.Sum256([]byte(rawJWT))
	assert.Equal(t, hex.EncodeToString(sum[:]), cred.SecretAccessKey)

	// The JWT verifies against SHA-256(parent token value), signed
	// HS256, and carries the request's own scope.
	parentSecret := sha256.Sum256([]byte("parent-token-secret-value"))

	parsed, err := jose.ParseSigned(rawJWT, []jose.SignatureAlgorithm{jose.HS256})
	require.NoError(t, err)

	payload, err := parsed.Verify(parentSecret[:])
	require.NoError(t, err)

	var claims struct {
		josejwt.Claims
		unverifiedClaimsShape
	}
	require.NoError(t, json.Unmarshal(payload, &claims))

	assert.Equal(t, "example-account-id", claims.AccountID)
	assert.Equal(t, "example-bucket", claims.Bucket)
	assert.Equal(t, "object-read-write", claims.Permission)
	assert.Equal(t, []string{"go-build/"}, claims.Prefixes)
	assert.Equal(t, "parent-token-id", claims.ParentAccessKeyID)
	require.NotNil(t, claims.Expiry)
	assert.Equal(t, fixedNow.Add(900*time.Second).Unix(), int64(*claims.Expiry))
}

func TestLocalMinterWrongSecretDoesNotVerify(t *testing.T) {
	m := &LocalMinter{Token: ParentToken{ID: "id", Value: "correct-secret"}}

	cred, err := m.Mint(context.Background(), Request{
		Bucket: "b", Permission: config.PermissionReadOnly, TTLSeconds: 60,
	})
	require.NoError(t, err)

	decoded, err := base64.StdEncoding.DecodeString(cred.SessionToken)
	require.NoError(t, err)

	rawJWT, ok := strings.CutPrefix(string(decoded), "jwt/")
	require.True(t, ok)

	parsed, err := jose.ParseSigned(rawJWT, []jose.SignatureAlgorithm{jose.HS256})
	require.NoError(t, err)

	wrongSecret := sha256.Sum256([]byte("wrong-secret"))
	_, err = parsed.Verify(wrongSecret[:])
	assert.Error(t, err, "a credential signed with a different parent secret must not verify")
}

func TestLocalMinterRequiresParentTokenValue(t *testing.T) {
	m := &LocalMinter{Token: ParentToken{ID: "id"}}

	_, err := m.Mint(context.Background(), Request{
		Bucket: "b", Permission: config.PermissionReadOnly, TTLSeconds: 60,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parent token value is required")
}

func TestLocalMinterValidatesRequest(t *testing.T) {
	m := &LocalMinter{Token: ParentToken{ID: "id", Value: "secret"}}

	cases := []struct {
		name string
		req  Request
	}{
		{"no bucket", Request{Permission: config.PermissionReadOnly, TTLSeconds: 60}},
		{"bad permission", Request{Bucket: "b", Permission: "admin-read-write", TTLSeconds: 60}},
		{"zero ttl", Request{Bucket: "b", Permission: config.PermissionReadOnly}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := m.Mint(context.Background(), tc.req)
			assert.Error(t, err)
		})
	}
}
