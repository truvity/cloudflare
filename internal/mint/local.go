package mint

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
)

// DefaultR2Host is the S3 endpoint host of an account's R2, without the
// account id: <account-id>.r2.cloudflarestorage.com.
const DefaultR2Host = "r2.cloudflarestorage.com"

// LocalMinter builds a temporary R2 credential without calling
// Cloudflare. It follows Cloudflare's published client-side signing
// example, developers.cloudflare.com/r2/examples/authenticate-r2-temp-credentials/
// ("Generate locally (client-side signing)"):
//
//   - The JWT is HS256 with header {"alg":"HS256","typ":"JWT"}. It is
//     signed with the parent SECRET ACCESS KEY as a string: the lowercase
//     hex SHA-256 of the parent API token's value
//     (developers.cloudflare.com/r2/api/s3/tokens/). The example signs
//     `new TextEncoder().encode(parentSecretAccessKey)`, which is the
//     64 bytes of that hex text, not the 32 raw bytes of the digest.
//   - Its claims are sub (the account id), iss (the parent access key
//     id), aud (the host of the S3 endpoint), iat, exp, bucket, scope (a
//     permission name such as object-read-only) and, only when the
//     credential is narrowed, paths {prefixPaths, objectPaths}.
//   - The temporary access key id is the parent's. The temporary secret
//     is the hex SHA-256 of the signed JWT. The session token is
//     base64("jwt/" + JWT).
//
// Up to v2.7.1 this minter guessed the claim schema, because Cloudflare
// had not published it: accountId, permission, prefixes and
// parentAccessKeyId, no sub/iss/aud, and the digest's raw bytes as the
// HMAC key. R2 refused every such credential with 400 InvalidArgument:
// X-Amz-Security-Token. Nothing here saw it, because the token is only
// checked when it is used.
type LocalMinter struct {
	// Token is the parent API token this minter signs with.
	Token ParentToken
	// Host is the S3 endpoint host the credential is for, which becomes
	// the JWT's audience. Empty means <account-id>.DefaultR2Host, the
	// endpoint of an account with no jurisdiction. A jurisdiction-scoped
	// bucket (for example eu) is served from another host and needs it
	// set.
	Host string
	// Now returns the current time. Defaults to time.Now; tests set it
	// to get a deterministic iat/exp.
	Now func() time.Time
}

func (m *LocalMinter) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}

	return time.Now()
}

func (m *LocalMinter) host(accountID string) string {
	if m.Host != "" {
		return m.Host
	}

	return accountID + "." + DefaultR2Host
}

// ParentSecretAccessKey is the S3 secret access key R2 derives from an
// API token: the lowercase hex SHA-256 of the token's value.
func ParentSecretAccessKey(tokenValue string) string {
	sum := sha256.Sum256([]byte(tokenValue))

	return hex.EncodeToString(sum[:])
}

// Mint signs a new HS256 JWT for req and returns it as a temporary
// credential. It makes no network call.
func (m *LocalMinter) Mint(_ context.Context, req Request) (Credential, error) {
	if err := req.Validate(); err != nil {
		return Credential{}, err
	}

	if m.Token.Value == "" {
		return Credential{}, fmt.Errorf("mint: local: parent token value is required")
	}

	if m.Token.ID == "" {
		return Credential{}, fmt.Errorf("mint: local: parent token id is required")
	}

	if req.AccountID == "" {
		return Credential{}, fmt.Errorf("mint: local: accountID is required")
	}

	iat := m.now()
	exp := iat.Add(time.Duration(req.TTLSeconds) * time.Second)

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.HS256, Key: []byte(ParentSecretAccessKey(m.Token.Value))},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		return Credential{}, fmt.Errorf("mint: local: building signer: %w", err)
	}

	raw, err := josejwt.Signed(signer).Claims(localClaims(m.Token.ID, m.host(req.AccountID), req, iat, exp)).Serialize()
	if err != nil {
		return Credential{}, fmt.Errorf("mint: local: signing: %w", err)
	}

	secret := sha256.Sum256([]byte(raw))

	return Credential{
		AccessKeyID:     m.Token.ID,
		SecretAccessKey: hex.EncodeToString(secret[:]),
		SessionToken:    base64.StdEncoding.EncodeToString([]byte("jwt/" + raw)),
		Expiration:      exp,
	}, nil
}

// localPaths narrows a credential to prefixes or exact objects. Both
// arrays are always present once the object is, as in Cloudflare's
// example.
type localPaths struct {
	PrefixPaths []string `json:"prefixPaths"`
	ObjectPaths []string `json:"objectPaths"`
}

// localClaimsShape is the private-claim half of the JWT.
type localClaimsShape struct {
	Bucket string      `json:"bucket"`
	Scope  string      `json:"scope"`
	Paths  *localPaths `json:"paths,omitempty"`
}

func localClaims(parentAccessKeyID, host string, req Request, iat, exp time.Time) any {
	type claims struct {
		josejwt.Claims
		localClaimsShape
	}

	shape := localClaimsShape{Bucket: req.Bucket, Scope: string(req.Permission)}
	if len(req.Prefixes) > 0 {
		shape.Paths = &localPaths{PrefixPaths: req.Prefixes, ObjectPaths: []string{}}
	}

	return claims{
		Claims: josejwt.Claims{
			Subject:  req.AccountID,
			Issuer:   parentAccessKeyID,
			Audience: josejwt.Audience{host},
			IssuedAt: josejwt.NewNumericDate(iat),
			Expiry:   josejwt.NewNumericDate(exp),
		},
		localClaimsShape: shape,
	}
}
