package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// withCacheLock runs fn while holding an exclusive lock for one cache
// entry.
//
// A cache alone does not fix the race it exists to prevent: on a cold
// start (a build tool with several concurrent uploaders — BuildKit, Go's
// GOCACHEPROG, bazel-remote — each starting their own `credential_process`)
// every caller misses at the same instant and all of them would otherwise
// mint at once, several times over, against whichever path the config
// selects — an unnecessary Cloudflare API cost on the API-mode fallback,
// and unnecessary local-signing work either way. The lock makes one
// caller do the work while the others wait, and they then find the answer
// already written. Copied from access-roster's own accessctl cache lock
// (cmd/accessctl/cache_lock.go) by PATTERN, not by import: r2broker is a
// different binary in a different repository with no dependency on
// access-roster (design §2.4).
//
// The lock is its own file, not the cache file, so the atomic rename that
// replaces the cache cannot pull the lock out from under a waiter.
func withCacheLock(path string, fn func() error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}

	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		// Not being able to lock is not a reason to refuse to mint: fall
		// back to doing it unsynchronized.
		return fn()
	}
	defer func() { _ = lock.Close() }()

	if err = lockFile(lock); err != nil {
		return fn()
	}
	defer func() { _ = unlockFile(lock) }()

	return fn()
}

// lockFile and unlockFile are the one part of this that is not portable,
// so they live in cache_lock_unix.go and cache_lock_windows.go. r2broker
// is built for Windows deliberately: `credentials` (unlike `serve`) is
// what an AWS SDK's credential_process can run directly on a laptop, and
// `go build` for the host platform never says so when a Windows-specific
// build tag is missing something.
