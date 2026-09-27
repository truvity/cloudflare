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

// LocalMinter builds a temporary R2 credential without calling
// Cloudflare, following developers.cloudflare.com/r2/api/s3/temporary-credentials/'s
// documented local-signing mechanism:
//
//	"You can also generate temporary credentials locally by signing a JWT
//	with your parent API token's secret access key."
//	"Sign the JWT with HS256 using your parent secret access key."
//	"Encode the session token as base64(\"jwt/\" + <signed-jwt>)."
//
// and developers.cloudflare.com/r2/api/s3/tokens/'s confirmed parent-token
// mapping:
//
//	"Access Key ID: The id of the API token. Secret Access Key: The
//	SHA-256 hash of the API token value."
//
// That is everything Cloudflare's own docs confirm. They do not publish
// the JWT's claim schema, and they do not state how the credential's own
// AccessKeyID/SecretAccessKey are derived — see the UNVERIFIED block
// below, and design §8 (the live round-trip test that would confirm or
// correct it has not run yet: it needs a Cloudflare account credential
// broad enough to create an R2 bucket and a scoped API token, which is
// not something this estate's existing Cloudflare token can do).
type LocalMinter struct {
	// Token is the parent API token this minter signs with.
	Token ParentToken
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

// Mint signs a new HS256 JWT for req and returns it as a temporary
// credential. It makes no network call.
func (m *LocalMinter) Mint(_ context.Context, req Request) (Credential, error) {
	if err := req.Validate(); err != nil {
		return Credential{}, err
	}

	if m.Token.Value == "" {
		return Credential{}, fmt.Errorf("mint: local: parent token value is required")
	}

	iat := m.now()
	exp := iat.Add(time.Duration(req.TTLSeconds) * time.Second)

	// "Secret Access Key: The SHA-256 hash of the API token value" —
	// confirmed (developers.cloudflare.com/r2/api/s3/tokens/), and the
	// same value the local-signing doc calls "your parent secret access
	// key", i.e. the HMAC key below.
	parentSecret := sha256.Sum256([]byte(m.Token.Value))

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: parentSecret[:]}, nil)
	if err != nil {
		return Credential{}, fmt.Errorf("mint: local: building signer: %w", err)
	}

	raw, err := josejwt.Signed(signer).Claims(unverifiedClaims(m.Token.ID, req, iat, exp)).Serialize()
	if err != nil {
		return Credential{}, fmt.Errorf("mint: local: signing: %w", err)
	}

	// "Encode the session token as base64(\"jwt/\" + <signed-jwt>)" —
	// confirmed, verbatim.
	sessionToken := base64.StdEncoding.EncodeToString([]byte("jwt/" + raw))

	return Credential{
		AccessKeyID:     unverifiedAccessKeyID(m.Token.ID),
		SecretAccessKey: unverifiedSecretAccessKey(raw),
		SessionToken:    sessionToken,
		Expiration:      exp,
	}, nil
}

// --- UNVERIFIED until the live test (design §8) -------------------------
//
// Everything in this block is a best-effort reconstruction, not a
// confirmed Cloudflare contract. The local-signing doc names the
// algorithm, the key and the session-token encoding (quoted in
// LocalMinter's doc comment) but publishes neither the JWT's claim
// schema nor how the resulting credential's AccessKeyID/SecretAccessKey
// are derived. Isolating the guesswork here, instead of spreading it
// through Mint, means design §8's real-account round-trip test (mint
// locally, then PutObject/GetObject/ListObjectsV2 against real R2) has
// exactly one place to correct once it runs.
//
// The reasoning behind each guess:
//
//   - Claim names mirror the REST temporary-credentials request body's
//     own field names — bucket, permission, prefixes, objects — which
//     ARE confirmed (developers.cloudflare.com/api/resources/r2/subresources/temporary_credentials/methods/create/),
//     plus accountId and parentAccessKeyId to identify which token
//     signed the JWT, and registered iat/exp claims every JWT carries.
//   - AccessKeyID is assumed equal to the parent token's own id: the
//     only "id" fact anywhere in Cloudflare's docs is the parent-token
//     mapping quoted above, and reusing it lets a stateless verifier
//     look up which secret to check the HMAC against.
//   - SecretAccessKey is derived as the SHA-256 hash of the signed JWT
//     string, so both this minter and a stateless edge verifier that
//     also holds the JWT (it is embedded in the session token) could
//     recompute the same value without a database lookup — the only
//     derivation that does not require Cloudflare to keep server-side
//     state for a "locally" signed credential.
//
// The CompositeMinter's drift detection (see composite.go, design
// §1.2/§2.2) exists specifically to catch this guess being wrong once
// the estate is live: if locally-signed credentials start being refused
// by real R2 while API-mode keeps working for the same request, that is
// this block, not a Cloudflare outage.
type unverifiedClaimsShape struct {
	AccountID         string   `json:"accountId"`
	Bucket            string   `json:"bucket"`
	Permission        string   `json:"permission"`
	Prefixes          []string `json:"prefixes,omitempty"`
	ParentAccessKeyID string   `json:"parentAccessKeyId"`
}

func unverifiedClaims(parentAccessKeyID string, req Request, iat, exp time.Time) any {
	type claims struct {
		josejwt.Claims
		unverifiedClaimsShape
	}

	return claims{
		Claims: josejwt.Claims{
			IssuedAt: josejwt.NewNumericDate(iat),
			Expiry:   josejwt.NewNumericDate(exp),
		},
		unverifiedClaimsShape: unverifiedClaimsShape{
			AccountID:         req.AccountID,
			Bucket:            req.Bucket,
			Permission:        string(req.Permission),
			Prefixes:          req.Prefixes,
			ParentAccessKeyID: parentAccessKeyID,
		},
	}
}

func unverifiedAccessKeyID(parentAccessKeyID string) string {
	return parentAccessKeyID
}

func unverifiedSecretAccessKey(rawJWT string) string {
	sum := sha256.Sum256([]byte(rawJWT))

	return hex.EncodeToString(sum[:])
}

// --- end UNVERIFIED block -------------------------------------------
