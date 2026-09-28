package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/cloudflare/v2/internal/config"
)

func TestResolveParentTokenValueFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	// A trailing newline, exactly what `op read` (without --no-newline)
	// or an editor's "always end with a newline" habit would leave.
	require.NoError(t, os.WriteFile(path, []byte("the-secret-value\n"), 0o600))

	value, err := resolveParentTokenValue(config.Account{ParentTokenFile: path})
	require.NoError(t, err)
	assert.Equal(t, "the-secret-value", value, "trailing whitespace must be trimmed")
}

func TestResolveParentTokenValueFromEnv(t *testing.T) {
	t.Setenv("R2_BROKER_TEST_PARENT_TOKEN", "  the-secret-value  \n")

	value, err := resolveParentTokenValue(config.Account{ParentTokenEnv: "R2_BROKER_TEST_PARENT_TOKEN"})
	require.NoError(t, err)
	assert.Equal(t, "the-secret-value", value)
}

func TestResolveParentTokenValueMissingFile(t *testing.T) {
	_, err := resolveParentTokenValue(config.Account{ParentTokenFile: filepath.Join(t.TempDir(), "does-not-exist")})
	require.Error(t, err)
}

func TestResolveParentTokenValueEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(path, []byte("   \n"), 0o600))

	_, err := resolveParentTokenValue(config.Account{ParentTokenFile: path})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestResolveParentTokenValueUnsetEnv(t *testing.T) {
	_, err := resolveParentTokenValue(config.Account{ParentTokenEnv: "R2_BROKER_TEST_DEFINITELY_UNSET"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unset or empty")
}
