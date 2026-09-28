package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/truvity/cloudflare/v2/internal/broker"
	"github.com/truvity/cloudflare/v2/internal/config"
	"github.com/truvity/cloudflare/v2/internal/decide"
	"github.com/truvity/cloudflare/v2/internal/mint"
)

// clientTimeout bounds credentials' own work: reading the config (or
// calling the service), verifying, deciding and minting, end to end.
const clientTimeout = 20 * time.Second

// stringList collects a repeatable flag (--prefix) into a slice.
type stringList []string

func (s *stringList) String() string {
	if s == nil {
		return ""
	}

	return strings.Join(*s, ",")
}

func (s *stringList) Set(v string) error {
	*s = append(*s, v)

	return nil
}

// credentials answers the `credentials` command: mint one temporary R2
// credential and print it as an AWS credential_process document (Version
// 1) on stdout — nothing else goes there, since a credential_process
// consumer parses stdout AS the credential.
//
// Exactly one of --config (in-process, no central broker — design §2.6)
// or --service-url (a client of a centrally-deployed broker, what
// access-roster's `accessctl r2` execs against) selects the mode.
func credentials(args []string) error {
	flags := flag.NewFlagSet("credentials", flag.ContinueOnError)
	configPath := flags.String("config", "", "mint in-process from this local config file (no central broker)")
	serviceURL := flags.String("service-url", "", "call this running `r2broker serve` instead of minting locally")
	tokenFile := flags.String("token-file", "", "path to the bearer token (or $R2BROKER_TOKEN_FILE; $R2BROKER_TOKEN for the raw value)")
	bucket := flags.String("bucket", "", "bucket to request; required only when the token's groups reach more than one")
	permissionFlag := flags.String("permission", "", "permission to request (object-read-only|object-read-write); only needed to disambiguate")

	var prefixes stringList

	flags.Var(&prefixes, "prefix", "prefix to request; may repeat")

	if err := flags.Parse(args); err != nil {
		return usageError{err}
	}

	if (*configPath == "") == (*serviceURL == "") {
		return badUsage("exactly one of --config or --service-url is required")
	}

	permission := config.Permission(*permissionFlag)
	if *permissionFlag != "" && !permission.Valid() {
		return badUsage("--permission must be %q or %q", config.PermissionReadOnly, config.PermissionReadWrite)
	}

	token, err := resolveToken(*tokenFile)
	if err != nil {
		return err
	}

	req := broker.Request{Token: token, Bucket: *bucket, Prefixes: prefixes, Permission: permission}

	mintFn, source := mintFunc(*configPath, *serviceURL, req)

	key := cacheKey(source, req.Bucket, req.Prefixes, req.Permission, req.Token)

	path, cacheErr := cachePath(key)
	if cacheErr == nil {
		if cred, ok := readCredentialCache(path); ok {
			return writeCredentialProcess(stdout, cred.Credential)
		}
	}

	run := func() error {
		// Re-check under the lock: a caller that waited here while
		// another minted finds the answer already written.
		if cacheErr == nil {
			if cred, ok := readCredentialCache(path); ok {
				return writeCredentialProcess(stdout, cred.Credential)
			}
		}

		cred, decision, err := mintFn()
		if err != nil {
			return err
		}

		if cacheErr == nil {
			// A cache that cannot be written is not a reason to withhold
			// a credential the caller already has.
			_ = writeCredentialCache(path, cachedCredential{Credential: cred, Bucket: decision.Bucket, Prefixes: decision.Prefixes})
		}

		return writeCredentialProcess(stdout, cred)
	}

	if cacheErr != nil {
		return run()
	}

	return withCacheLock(path, run)
}

// mintFunc returns the mint operation for whichever mode was selected,
// and the cache key's source component — a service URL and a local
// config path are never allowed to share a cache entry, even if (in a
// contrived setup) they resolved to the same scope, since a mode change
// is exactly the kind of thing that must never serve a stale answer from
// the other mode.
func mintFunc(configPath, serviceURL string, req broker.Request) (func() (mint.Credential, decide.Decision, error), string) {
	if serviceURL != "" {
		return func() (mint.Credential, decide.Decision, error) {
			return mintViaService(serviceURL, req)
		}, "service:" + serviceURL
	}

	source := configPath
	if abs, err := filepath.Abs(configPath); err == nil {
		source = abs
	}

	return func() (mint.Credential, decide.Decision, error) {
		return mintInProcess(configPath, req)
	}, "config:" + source
}

// mintInProcess loads configPath and runs the whole verify -> decide ->
// mint pipeline right here, with no network hop to any broker service —
// "the installation that has no use for the rest of this repository"
// (design §2.6). It shares internal/broker (and, under it, internal/mint)
// with `serve`, so the two modes cannot drift from each other.
func mintInProcess(configPath string, req broker.Request) (mint.Credential, decide.Decision, error) {
	f, err := os.Open(configPath)
	if err != nil {
		return mint.Credential{}, decide.Decision{}, fmt.Errorf("opening %s: %w", configPath, err)
	}
	defer func() { _ = f.Close() }()

	cfg, err := config.Load(f)
	if err != nil {
		return mint.Credential{}, decide.Decision{}, err
	}

	tokenValue, err := resolveParentTokenValue(cfg.Account)
	if err != nil {
		return mint.Credential{}, decide.Decision{}, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), clientTimeout)
	defer cancel()

	b, err := broker.New(ctx, cfg, mint.ParentToken{ID: cfg.Account.ParentTokenID, Value: tokenValue}, http.DefaultClient, nil)
	if err != nil {
		return mint.Credential{}, decide.Decision{}, err
	}

	return outcomeToResult(b.Mint(ctx, req))
}

func outcomeToResult(result broker.Result) (mint.Credential, decide.Decision, error) {
	switch result.Outcome {
	case broker.OutcomeMinted:
		return result.Credential, result.Decision, nil
	case broker.OutcomeUnauthenticated, broker.OutcomeRefused:
		return mint.Credential{}, decide.Decision{}, refused(result.Err)
	default:
		return mint.Credential{}, decide.Decision{}, result.Err
	}
}

// mintViaService calls a running `r2broker serve`'s POST /v1/credentials,
// per design §2.1 — the shape access-roster's `accessctl r2` execs
// against for the estate's own centrally-deployed broker.
func mintViaService(serviceURL string, req broker.Request) (mint.Credential, decide.Decision, error) {
	body, err := json.Marshal(credentialsRequestBody{Bucket: req.Bucket, Prefixes: req.Prefixes, Permission: req.Permission})
	if err != nil {
		return mint.Credential{}, decide.Decision{}, fmt.Errorf("encoding request: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), clientTimeout)
	defer cancel()

	url := strings.TrimRight(serviceURL, "/") + "/v1/credentials"

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return mint.Credential{}, decide.Decision{}, fmt.Errorf("building request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+req.Token)

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return mint.Credential{}, decide.Decision{}, fmt.Errorf("calling %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return mint.Credential{}, decide.Decision{}, fmt.Errorf("reading response from %s: %w", url, err)
	}

	if resp.StatusCode != http.StatusOK {
		return mint.Credential{}, decide.Decision{}, serviceError(resp.StatusCode, data)
	}

	var out credentialsResponseBody
	if err := json.Unmarshal(data, &out); err != nil {
		return mint.Credential{}, decide.Decision{}, fmt.Errorf("decoding response from %s: %w", url, err)
	}

	cred := mint.Credential{
		AccessKeyID: out.AccessKeyID, SecretAccessKey: out.SecretAccessKey, SessionToken: out.SessionToken,
	}
	if out.Expiration != "" {
		if exp, err := time.Parse(time.RFC3339, out.Expiration); err == nil {
			cred.Expiration = exp
		}
	}

	return cred, decide.Decision{Bucket: out.Bucket, Prefixes: out.Prefixes}, nil
}

func serviceError(status int, body []byte) error {
	var errBody errorResponseBody
	_ = json.Unmarshal(body, &errBody)

	msg := errBody.Error
	if msg == "" {
		msg = strings.TrimSpace(string(body))
	}

	err := fmt.Errorf("the broker service refused the request (%d): %s", status, msg)

	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return refused(err)
	}

	return err
}

// resolveToken reads the bearer token: --token-file, then
// $R2BROKER_TOKEN_FILE, then the raw value in $R2BROKER_TOKEN. Never an
// argv value — a token is exactly the kind of thing `ps` should not see.
func resolveToken(tokenFileFlag string) (string, error) {
	path := tokenFileFlag
	if path == "" {
		path = os.Getenv("R2BROKER_TOKEN_FILE")
	}

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("reading token file %s: %w", path, err)
		}

		token := strings.TrimSpace(string(data))
		if token == "" {
			return "", fmt.Errorf("token file %s is empty", path)
		}

		return token, nil
	}

	token := strings.TrimSpace(os.Getenv("R2BROKER_TOKEN"))
	if token == "" {
		return "", badUsage("no token presented: set --token-file, $R2BROKER_TOKEN_FILE, or $R2BROKER_TOKEN")
	}

	return token, nil
}

// credentialProcessDocument is what the AWS SDKs read from
// `credential_process`. `Version` is the NUMBER 1, not a string, and the
// field names are capitalized exactly as written — a document that gets
// either wrong is rejected with a parse error naming neither this tool
// nor the profile. Shape confirmed against access-roster's own
// tokens.WriteCredentialProcess (the same contract, an independent
// implementation: r2broker has no dependency on access-roster).
type credentialProcessDocument struct {
	Version         int    `json:"Version"`
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken,omitempty"`
	Expiration      string `json:"Expiration,omitempty"`
}

func writeCredentialProcess(w io.Writer, cred mint.Credential) error {
	if cred.AccessKeyID == "" || cred.SecretAccessKey == "" {
		return fmt.Errorf("no credential to write")
	}

	doc := credentialProcessDocument{
		Version: 1, AccessKeyID: cred.AccessKeyID, SecretAccessKey: cred.SecretAccessKey, SessionToken: cred.SessionToken,
	}
	if !cred.Expiration.IsZero() {
		doc.Expiration = cred.Expiration.UTC().Format(time.RFC3339)
	}

	return json.NewEncoder(w).Encode(doc)
}
