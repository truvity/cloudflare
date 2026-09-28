package main

import (
	"bytes"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/cloudflare/v2/internal/broker"
	"github.com/truvity/cloudflare/v2/internal/mint"
)

func writeConfigFile(t *testing.T, issuer, parentTokenEnv string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "broker.yaml")
	body := `
issuer: ` + issuer + `
audience: r2-broker
groupsClaim: groups
account:
  id: example-account-id
  parentTokenId: parent-id
  parentTokenEnv: ` + parentTokenEnv + `
minting:
  mode: local
grants:
  - group: ci:cache:writer
    bucket: example-bucket
    prefixes: ["go-build/"]
    permission: object-read-write
    ttlSeconds: 900
`
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))

	return path
}

func TestResolveTokenPrecedence(t *testing.T) {
	fileTok := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(fileTok, []byte("from-flag\n"), 0o600))

	t.Setenv("R2BROKER_TOKEN_FILE", "")
	t.Setenv("R2BROKER_TOKEN", "from-env-raw")

	// --token-file wins over everything.
	tok, err := resolveToken(fileTok)
	require.NoError(t, err)
	assert.Equal(t, "from-flag", tok)

	// No flag: falls back to $R2BROKER_TOKEN.
	tok, err = resolveToken("")
	require.NoError(t, err)
	assert.Equal(t, "from-env-raw", tok)

	// $R2BROKER_TOKEN_FILE beats $R2BROKER_TOKEN.
	envFileTok := filepath.Join(t.TempDir(), "token2")
	require.NoError(t, os.WriteFile(envFileTok, []byte("from-env-file"), 0o600))
	t.Setenv("R2BROKER_TOKEN_FILE", envFileTok)

	tok, err = resolveToken("")
	require.NoError(t, err)
	assert.Equal(t, "from-env-file", tok)
}

func TestResolveTokenNoneSetIsUsageError(t *testing.T) {
	t.Setenv("R2BROKER_TOKEN_FILE", "")
	t.Setenv("R2BROKER_TOKEN", "")

	_, err := resolveToken("")
	require.Error(t, err)

	var usage usageError
	assert.ErrorAs(t, err, &usage)
}

func TestWriteCredentialProcess(t *testing.T) {
	var buf bytes.Buffer

	exp := time.Date(2026, 9, 27, 15, 0, 0, 0, time.UTC)
	require.NoError(t, writeCredentialProcess(&buf, mint.Credential{
		AccessKeyID: "AKID", SecretAccessKey: "secret", SessionToken: "session", Expiration: exp,
	}))

	assert.JSONEq(t,
		`{"Version":1,"AccessKeyId":"AKID","SecretAccessKey":"secret","SessionToken":"session","Expiration":"2026-09-27T15:00:00Z"}`,
		buf.String())
}

func TestWriteCredentialProcessRequiresCredential(t *testing.T) {
	var buf bytes.Buffer
	err := writeCredentialProcess(&buf, mint.Credential{})
	require.Error(t, err)
}

func TestMintInProcessEndToEnd(t *testing.T) {
	ti := newTestIssuer(t)
	t.Setenv("R2_BROKER_TEST_TOKEN", "parent-secret")

	configPath := writeConfigFile(t, ti.server.URL, "R2_BROKER_TEST_TOKEN")

	req := brokerRequestFor(t, ti, []string{"ci:cache:writer"})

	cred, decision, err := mintInProcess(configPath, req)
	require.NoError(t, err)
	assert.NotEmpty(t, cred.AccessKeyID)
	assert.Equal(t, "example-bucket", decision.Bucket)
}

func TestMintInProcessRefusalIsRefusedError(t *testing.T) {
	ti := newTestIssuer(t)
	t.Setenv("R2_BROKER_TEST_TOKEN_2", "parent-secret")

	configPath := writeConfigFile(t, ti.server.URL, "R2_BROKER_TEST_TOKEN_2")
	req := brokerRequestFor(t, ti, []string{"some:other:group"})

	_, _, err := mintInProcess(configPath, req)
	require.Error(t, err)

	var ref refusedError
	assert.ErrorAs(t, err, &ref)
}

// mintViaServiceEndToEnd exercises the FULL client/server loop: a real
// httptest.Server running the same credentialsHandler serve.go builds,
// called by mintViaService — the two halves of design §2.1's one HTTP
// contract, tested together.
func TestMintViaServiceEndToEnd(t *testing.T) {
	ti := newTestIssuer(t)
	h := testHandler(t, ti.server.URL)

	broker := httptest.NewServer(h)
	t.Cleanup(broker.Close)

	req := brokerRequestFor(t, ti, []string{"ci:cache:writer"})

	cred, decision, err := mintViaService(broker.URL, req)
	require.NoError(t, err)
	assert.NotEmpty(t, cred.AccessKeyID)
	assert.NotEmpty(t, cred.SessionToken)
	assert.Equal(t, "example-bucket", decision.Bucket)
}

func TestMintViaServiceRefusalIsRefusedError(t *testing.T) {
	ti := newTestIssuer(t)
	h := testHandler(t, ti.server.URL)

	broker := httptest.NewServer(h)
	t.Cleanup(broker.Close)

	req := brokerRequestFor(t, ti, []string{"no:such:group"})

	_, _, err := mintViaService(broker.URL, req)
	require.Error(t, err)

	var ref refusedError
	assert.ErrorAs(t, err, &ref)
}

func TestMintFuncSourceNamingDistinguishesConfigFromService(t *testing.T) {
	_, sourceConfig := mintFunc("/some/broker.yaml", "", broker.Request{})
	_, sourceService := mintFunc("", "https://broker.example", broker.Request{})

	assert.NotEqual(t, sourceConfig, sourceService)
	assert.Contains(t, sourceConfig, "config:")
	assert.Contains(t, sourceService, "service:")
}

func brokerRequestFor(t *testing.T, ti *testIssuer, groups []string) broker.Request {
	t.Helper()

	return broker.Request{Token: ti.token(t, groups), Prefixes: []string{"go-build/"}}
}

func TestCredentialsEndToEndWritesAndCaches(t *testing.T) {
	ti := newTestIssuer(t)
	t.Setenv("R2_BROKER_TEST_TOKEN_3", "parent-secret")

	configPath := writeConfigFile(t, ti.server.URL, "R2_BROKER_TEST_TOKEN_3")
	t.Setenv("R2BROKER_CACHE_DIR", t.TempDir())
	t.Setenv("R2BROKER_TOKEN", ti.token(t, []string{"ci:cache:writer"}))
	t.Setenv("R2BROKER_TOKEN_FILE", "")

	var out bytes.Buffer

	origStdout := stdout
	stdout = &out

	t.Cleanup(func() { stdout = origStdout })

	err := credentials([]string{"--config", configPath, "--prefix", "go-build/"})
	require.NoError(t, err)
	assert.Contains(t, out.String(), `"Version":1`)

	// The lock's cache directory now holds exactly the entry this mint
	// wrote — proof the client-side cache (design §2.7) is wired into the
	// command, not just unit-tested on its own.
	entries, err := os.ReadDir(filepath.Join(os.Getenv("R2BROKER_CACHE_DIR"), "credentials"))
	require.NoError(t, err)
	assert.Len(t, entries, 2, "the cache entry and its lock file")
}
