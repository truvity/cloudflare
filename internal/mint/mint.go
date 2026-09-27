// Package mint builds temporary R2 credentials for one already-decided
// grant (see internal/decide): a bucket, an optional prefix list and a
// permission become an AWS-shaped access key id, secret access key and
// session token.
//
// Cloudflare offers two ways to get there
// (developers.cloudflare.com/r2/api/s3/temporary-credentials/):
//
//   - LocalMinter signs the credential itself — no Cloudflare API call,
//     immune to the account-wide REST rate limit, lowest latency. This
//     is the documented "generate temporary credentials locally" path,
//     not a reverse-engineered trick, but it is thinly specified (see
//     LocalMinter's doc comment).
//   - APIMinter calls the temporary-credentials REST endpoint. Slower
//     and rate-limited, but every byte of it is Cloudflare's own code
//     path.
//
// CompositeMinter tries local signing first and falls over to the API on
// error, because a silent change to the thinly-documented local contract
// should degrade a mint, not fail it — see CompositeMinter's doc comment
// for the drift-detection reasoning.
//
// The library's contract, shared by every public truvity module:
//
//   - Mechanism only. Nothing here names a real account or bucket; every
//     field arrives on Request.
//   - Credentials come in. ParentToken.Value is a caller input, read
//     from wherever the estate keeps secrets; this package never writes
//     it anywhere but the signature/bearer header it needs to reach.
//   - One small interface. Minter is the only thing the rest of the
//     broker depends on.
package mint

import (
	"context"
	"fmt"
	"time"

	"github.com/truvity/cloudflare/v2/internal/config"
)

// ParentToken is the Cloudflare API token both minting paths derive a
// signing key from (LocalMinter) or authenticate with (APIMinter).
type ParentToken struct {
	// ID is the parent token's own id — "Access Key ID: the id of the
	// API token" (developers.cloudflare.com/r2/api/s3/tokens/).
	ID string
	// Value is the parent token's secret value. Never logged, never
	// serialized: only used to compute a signing key (LocalMinter) or as
	// a bearer credential (APIMinter).
	Value string
}

// Request is one already-decided grant to mint a credential for. It is
// the output shape of internal/decide.Decision plus the account id, so
// package decide never needs to import package mint.
type Request struct {
	// AccountID owning the bucket.
	AccountID string
	// Bucket the credential is scoped to. Required.
	Bucket string
	// Prefixes to scope the credential to. Empty means the whole
	// bucket (within Permission).
	Prefixes []string
	// Permission minted.
	Permission config.Permission
	// TTLSeconds the credential should live for.
	TTLSeconds int
}

// Validate reports the first problem with r.
func (r Request) Validate() error {
	if r.Bucket == "" {
		return fmt.Errorf("mint: bucket is required")
	}

	if !r.Permission.Valid() {
		return fmt.Errorf("mint: permission %q is not valid", r.Permission)
	}

	if r.TTLSeconds <= 0 {
		return fmt.Errorf("mint: ttlSeconds must be > 0, got %d", r.TTLSeconds)
	}

	return nil
}

// Credential is a temporary R2 credential, shaped like the AWS
// SigV4/STS triple every S3-compatible SDK already expects.
type Credential struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
}

// Minter mints a temporary credential for an already-decided request.
type Minter interface {
	Mint(ctx context.Context, req Request) (Credential, error)
}
