package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/cloudflare/v2/internal/config"
	"github.com/truvity/cloudflare/v2/internal/mint"
)

func TestCacheKeyStableAndDistinguishing(t *testing.T) {
	base := cacheKey("service:https://broker.example", "bucket-a", []string{"go-build/"}, config.PermissionReadWrite, "token-a")

	assert.Equal(t, base, cacheKey("service:https://broker.example", "bucket-a", []string{"go-build/"}, config.PermissionReadWrite, "token-a"),
		"same inputs must produce the same key")

	assert.Equal(t,
		cacheKey("service:https://broker.example", "bucket-a", []string{"a/", "b/"}, config.PermissionReadWrite, "token-a"),
		cacheKey("service:https://broker.example", "bucket-a", []string{"b/", "a/"}, config.PermissionReadWrite, "token-a"),
		"prefix order must not matter")

	distinguishers := []string{
		cacheKey("config:/other/broker.yaml", "bucket-a", []string{"go-build/"}, config.PermissionReadWrite, "token-a"),      // different source
		cacheKey("service:https://broker.example", "bucket-b", []string{"go-build/"}, config.PermissionReadWrite, "token-a"), // different bucket
		cacheKey("service:https://broker.example", "bucket-a", []string{"other/"}, config.PermissionReadWrite, "token-a"),    // different prefix
		cacheKey("service:https://broker.example", "bucket-a", []string{"go-build/"}, config.PermissionReadOnly, "token-a"),  // different permission
		cacheKey("service:https://broker.example", "bucket-a", []string{"go-build/"}, config.PermissionReadWrite, "token-b"), // different token
	}
	for _, d := range distinguishers {
		assert.NotEqual(t, base, d)
	}
}

func TestCredentialCacheRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cred.json")

	_, ok := readCredentialCache(path)
	assert.False(t, ok, "no file yet is a miss")

	cred := cachedCredential{
		Credential: mint.Credential{
			AccessKeyID: "AKID", SecretAccessKey: "secret", SessionToken: "session",
			Expiration: time.Now().Add(time.Hour),
		},
		Bucket: "example-bucket", Prefixes: []string{"go-build/"},
	}
	require.NoError(t, writeCredentialCache(path, cred))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	got, ok := readCredentialCache(path)
	require.True(t, ok)
	assert.Equal(t, cred.AccessKeyID, got.AccessKeyID)
	assert.Equal(t, cred.Bucket, got.Bucket)
}

func TestCredentialCacheExpiryMargin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cred.json")

	require.NoError(t, writeCredentialCache(path, cachedCredential{
		Credential: mint.Credential{
			AccessKeyID: "AKID", SecretAccessKey: "secret", Expiration: time.Now().Add(cacheMargin - time.Second),
		},
	}))

	_, ok := readCredentialCache(path)
	assert.False(t, ok, "a credential inside the margin must not be offered")
}

func TestCredentialCacheCorruptFileIsAMiss(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cred.json")
	require.NoError(t, os.WriteFile(path, []byte("{not json"), 0o600))

	_, ok := readCredentialCache(path)
	assert.False(t, ok)
}

func TestCacheDirHonorsEnvOverride(t *testing.T) {
	t.Setenv("R2BROKER_CACHE_DIR", "/tmp/r2broker-test-cache-dir")

	dir, err := cacheDir()
	require.NoError(t, err)
	assert.Equal(t, "/tmp/r2broker-test-cache-dir", dir)
}
