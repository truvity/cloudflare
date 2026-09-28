package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/truvity/cloudflare/v2/internal/config"
	"github.com/truvity/cloudflare/v2/internal/mint"
)

// The `credentials` client-side cache exists for the same reason
// access-roster's AWS credential cache does: `credential_process` is not
// called once. A build with several concurrent uploaders (BuildKit, Go's
// GOCACHEPROG, bazel-remote) starts this command once per uploader, each
// with its own cold start, and design §2.7 is explicit that "a cold start
// by many callers is one exchange" — the cache (and withCacheLock,
// cache_lock.go) is what makes that true here instead of one Cloudflare
// API call, or one local-signing operation, per uploader.
//
// It is keyed by exactly what determines the credential — the source
// (which service or which local config), the requested scope, and a hash
// of the presented token, since a fresh sign-in may hand this command a
// different token on every invocation even when the requested scope has
// not changed. Written 0600, and treated as advisory throughout: any
// error reading it means mint afresh, never fail.

// cacheMargin is how long before Expiration a cached credential stops
// being offered, so a long-running upload never receives one that is
// about to expire mid-transfer. Design §2.7: "always re-mint a few
// minutes before expiry rather than at it."
const cacheMargin = 3 * time.Minute

// cachedCredential is what is written to and read from the cache file:
// the credential itself, plus enough of the request to be worth a
// sanity-check assertion in tests (the cache key already binds this, so
// these fields are not re-checked at read time).
type cachedCredential struct {
	mint.Credential
	Bucket   string   `json:"bucket"`
	Prefixes []string `json:"prefixes,omitempty"`
}

// cacheKey identifies exactly what a cached credential must have been
// minted for: the source (a service URL or a local config path — the two
// are never confused with each other, since a change from one mode to the
// other must never serve a stale entry from the other's cache), the
// requested scope, and the presented token (hashed: it is a bearer
// credential and does not belong in a filename or a log line even
// hashed-adjacent).
func cacheKey(source, bucket string, prefixes []string, permission config.Permission, token string) string {
	sorted := slices.Clone(prefixes)
	slices.Sort(sorted)

	tokenSum := sha256.Sum256([]byte(token))

	parts := []string{
		source, bucket, strings.Join(sorted, "\x00"), string(permission), hex.EncodeToString(tokenSum[:]),
	}

	sum := sha256.Sum256([]byte(strings.Join(parts, "\x1e")))

	return hex.EncodeToString(sum[:16])
}

// cacheDir is the base directory every cache entry (and its lock file)
// lives under. $R2BROKER_CACHE_DIR overrides it; otherwise
// os.UserCacheDir()/r2broker, the same per-user default access-roster's
// own commands use.
func cacheDir() (string, error) {
	if dir := os.Getenv("R2BROKER_CACHE_DIR"); dir != "" {
		return dir, nil
	}

	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("finding a user cache directory: %w", err)
	}

	return filepath.Join(base, "r2broker"), nil
}

func cachePath(key string) (string, error) {
	dir, err := cacheDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(dir, "credentials", key+".json"), nil
}

// readCredentialCache returns a cached credential that is still worth
// using. Every failure is a miss, never a hard error: a truncated file, a
// half-written one, or one from an older version of this command should
// all just mean "mint a fresh one," the same contract
// access-roster's readAWSCache keeps.
func readCredentialCache(path string) (cachedCredential, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return cachedCredential{}, false
	}

	var cred cachedCredential
	if err := json.Unmarshal(data, &cred); err != nil {
		return cachedCredential{}, false
	}

	if cred.AccessKeyID == "" || cred.SecretAccessKey == "" {
		return cachedCredential{}, false
	}

	if cred.Expiration.IsZero() || time.Until(cred.Expiration) <= cacheMargin {
		return cachedCredential{}, false
	}

	return cred, true
}

// writeCredentialCache stores cred atomically (temp file + rename, so a
// concurrent reader never sees a half-written file) and readable only by
// this account.
func writeCredentialCache(path string, cred cachedCredential) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}

	data, err := json.Marshal(cred)
	if err != nil {
		return fmt.Errorf("encoding cached credential: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".r2broker-*.tmp")
	if err != nil {
		return fmt.Errorf("create a temporary file: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()

		return fmt.Errorf("restrict %s: %w", tmp.Name(), err)
	}

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()

		return fmt.Errorf("write %s: %w", tmp.Name(), err)
	}

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmp.Name(), err)
	}

	return os.Rename(tmp.Name(), path)
}
