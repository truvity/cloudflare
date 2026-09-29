package mint

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/cloudflare/v2/internal/config"
)

func TestAPIMinterMintSuccess(t *testing.T) {
	var gotBody temporaryCredentialsRequest
	var gotPath, gotAuth string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(temporaryCredentialsResponse{
			Success: true,
			Result: struct {
				AccessKeyID     string `json:"accessKeyId"`
				SecretAccessKey string `json:"secretAccessKey"`
				SessionToken    string `json:"sessionToken"`
			}{AccessKeyID: "ak", SecretAccessKey: "sk", SessionToken: "st"},
		})
	}))
	defer srv.Close()

	fixedNow := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	m := &APIMinter{
		Client:  srv.Client(),
		BaseURL: srv.URL,
		Token:   ParentToken{ID: "parent-token-id", Value: "parent-token-value"},
		Now:     func() time.Time { return fixedNow },
	}

	cred, err := m.Mint(context.Background(), Request{
		AccountID: "example-account-id", Bucket: "example-bucket",
		Prefixes: []string{"go-build/"}, Permission: config.PermissionReadWrite, TTLSeconds: 900,
	})
	require.NoError(t, err)

	assert.Equal(t, "/accounts/example-account-id/r2/temp-access-credentials", gotPath)
	assert.Equal(t, "Bearer parent-token-value", gotAuth)
	assert.Equal(t, "example-bucket", gotBody.Bucket)
	assert.Equal(t, "parent-token-id", gotBody.ParentAccessKeyID, "required by the API reference")
	assert.Equal(t, "object-read-write", gotBody.Permission)
	assert.Equal(t, []string{"go-build/"}, gotBody.Prefixes)
	assert.Equal(t, 900, gotBody.TTLSeconds)

	assert.Equal(t, "ak", cred.AccessKeyID)
	assert.Equal(t, "sk", cred.SecretAccessKey)
	assert.Equal(t, "st", cred.SessionToken)
	assert.Equal(t, fixedNow.Add(900*time.Second), cred.Expiration)
}

func TestAPIMinterRetriesOn429ThenSucceeds(t *testing.T) {
	attempts := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		if attempts < 3 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)

			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(temporaryCredentialsResponse{
			Success: true,
			Result: struct {
				AccessKeyID     string `json:"accessKeyId"`
				SecretAccessKey string `json:"secretAccessKey"`
				SessionToken    string `json:"sessionToken"`
			}{AccessKeyID: "ak", SecretAccessKey: "sk", SessionToken: "st"},
		})
	}))
	defer srv.Close()

	var slept []time.Duration

	m := &APIMinter{
		Client:  srv.Client(),
		BaseURL: srv.URL,
		Token:   ParentToken{ID: "id", Value: "v"},
		Sleep:   func(d time.Duration) { slept = append(slept, d) },
	}

	cred, err := m.Mint(context.Background(), Request{
		AccountID: "example-account-id", Bucket: "b", Permission: config.PermissionReadOnly, TTLSeconds: 60,
	})
	require.NoError(t, err)
	assert.Equal(t, "ak", cred.AccessKeyID)
	assert.Equal(t, 3, attempts)
	require.Len(t, slept, 2, "one sleep per 429 before the success")

	for _, d := range slept {
		assert.Equal(t, time.Second, d, "Retry-After: 1 must be honored over the built-in backoff")
	}
}

func TestAPIMinterGivesUpAfterMaxRetries(t *testing.T) {
	attempts := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	m := &APIMinter{
		Client:     srv.Client(),
		BaseURL:    srv.URL,
		Token:      ParentToken{ID: "id", Value: "v"},
		MaxRetries: 2,
		Sleep:      func(time.Duration) {},
	}

	_, err := m.Mint(context.Background(), Request{
		AccountID: "example-account-id", Bucket: "b", Permission: config.PermissionReadOnly, TTLSeconds: 60,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rate limited")
	assert.Equal(t, 3, attempts, "the initial attempt plus MaxRetries retries")
}

func TestAPIMinterBackoffDoublesWithoutRetryAfter(t *testing.T) {
	attempts := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		if attempts < 4 {
			w.WriteHeader(http.StatusTooManyRequests) // no Retry-After

			return
		}

		_ = json.NewEncoder(w).Encode(temporaryCredentialsResponse{Success: true})
	}))
	defer srv.Close()

	var slept []time.Duration

	m := &APIMinter{
		Client:  srv.Client(),
		BaseURL: srv.URL,
		Token:   ParentToken{ID: "id", Value: "v"},
		Sleep:   func(d time.Duration) { slept = append(slept, d) },
	}

	_, err := m.Mint(context.Background(), Request{
		AccountID: "example-account-id", Bucket: "b", Permission: config.PermissionReadOnly, TTLSeconds: 60,
	})
	require.NoError(t, err)
	require.Len(t, slept, 3)
	assert.Equal(t, defaultBackoff, slept[0])
	assert.Equal(t, defaultBackoff*2, slept[1])
	assert.Equal(t, defaultBackoff*4, slept[2])
}

func TestAPIMinterSurfacesNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":10000,"message":"authentication error"}]}`))
	}))
	defer srv.Close()

	m := &APIMinter{Client: srv.Client(), BaseURL: srv.URL, Token: ParentToken{ID: "id", Value: "v"}}

	_, err := m.Mint(context.Background(), Request{
		AccountID: "example-account-id", Bucket: "b", Permission: config.PermissionReadOnly, TTLSeconds: 60,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}

func TestAPIMinterRequiresBaseURLAndAccountID(t *testing.T) {
	req := Request{Bucket: "b", Permission: config.PermissionReadOnly, TTLSeconds: 60}

	_, err := (&APIMinter{Token: ParentToken{ID: "id", Value: "v"}}).Mint(context.Background(), req)
	assert.ErrorContains(t, err, "baseURL is required")

	_, err = (&APIMinter{Token: ParentToken{ID: "id", Value: "v"}, BaseURL: "https://example.com"}).Mint(context.Background(), req)
	assert.ErrorContains(t, err, "accountID is required")
}

func TestRetryAfterParsing(t *testing.T) {
	h := http.Header{}
	assert.Equal(t, time.Duration(0), retryAfter(h))

	h.Set("Retry-After", "5")
	assert.Equal(t, 5*time.Second, retryAfter(h))

	h.Set("Retry-After", "not-a-number")
	assert.Equal(t, time.Duration(0), retryAfter(h))

	h.Set("Retry-After", strconv.Itoa(-1))
	assert.Equal(t, time.Duration(0), retryAfter(h))
}
