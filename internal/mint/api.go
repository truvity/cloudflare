package mint

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// defaultMaxRetries bounds how many times APIMinter retries a 429 before
// giving up, when MaxRetries is left at zero.
const defaultMaxRetries = 5

// defaultBackoff is the first wait between retries when the response
// carries no Retry-After header; it doubles on every subsequent attempt.
const defaultBackoff = 200 * time.Millisecond

// APIMinter calls Cloudflare's temporary-credentials REST endpoint
// (developers.cloudflare.com/api/resources/r2/subresources/temporary_credentials/methods/create/)
// for every mint. It is the fallback CompositeMinter uses when local
// signing errors, and it can also be the primary minter for an
// installation that would rather spend a Cloudflare API call than trust
// the thinly-documented local contract (see LocalMinter).
type APIMinter struct {
	// Client makes the HTTP request. Required — inject an
	// *http.Client (or a fake RoundTripper) rather than relying on
	// http.DefaultClient, so a test never reaches the network.
	Client *http.Client
	// BaseURL is the Cloudflare API root, e.g.
	// "https://api.cloudflare.com/client/v4". Required, no default: a
	// default naming Cloudflare's real host would still be an estate
	// input worth stating explicitly, and a test points this at its own
	// httptest server.
	BaseURL string
	// Token authenticates the request (bearer auth with Token.Value).
	Token ParentToken
	// MaxRetries bounds 429 retries. Zero means defaultMaxRetries.
	MaxRetries int
	// Sleep is called between retries. Defaults to time.Sleep; tests
	// override it to avoid slowing down the suite.
	Sleep func(time.Duration)
	// Now returns the current time, used to compute Expiration when the
	// response does not carry its own. Defaults to time.Now.
	Now func() time.Time
}

// temporaryCredentialsRequest is the REST request body. Field names are
// confirmed verbatim by the API reference cited above: "pass prefixes and
// objects as top-level fields on the request body".
type temporaryCredentialsRequest struct {
	Bucket     string   `json:"bucket"`
	Permission string   `json:"permission"`
	Prefixes   []string `json:"prefixes,omitempty"`
	TTLSeconds int      `json:"ttlSeconds"`
}

// temporaryCredentialsResponse is the REST response envelope. The
// {success,errors,result} shape is Cloudflare's standard API v4
// convention, used consistently across the estate's other Cloudflare API
// calls; the exact casing of the three credential fields inside `result`
// is assumed to match the API's own camelCase convention elsewhere on
// this same page ("ttlSeconds") but has not been confirmed against a
// live response (design §8's round-trip test would confirm it).
type temporaryCredentialsResponse struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result struct {
		AccessKeyID     string `json:"accessKeyId"`
		SecretAccessKey string `json:"secretAccessKey"`
		SessionToken    string `json:"sessionToken"`
	} `json:"result"`
}

func (m *APIMinter) client() *http.Client {
	if m.Client != nil {
		return m.Client
	}

	return http.DefaultClient
}

func (m *APIMinter) sleep() func(time.Duration) {
	if m.Sleep != nil {
		return m.Sleep
	}

	return time.Sleep
}

func (m *APIMinter) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}

	return time.Now()
}

func (m *APIMinter) maxRetries() int {
	if m.MaxRetries > 0 {
		return m.MaxRetries
	}

	return defaultMaxRetries
}

// Mint calls the temporary-credentials endpoint, retrying a 429 with
// backoff (honoring Retry-After when the response sends one) up to
// MaxRetries times.
func (m *APIMinter) Mint(ctx context.Context, req Request) (Credential, error) {
	if err := req.Validate(); err != nil {
		return Credential{}, err
	}

	if m.BaseURL == "" {
		return Credential{}, fmt.Errorf("mint: api: baseURL is required")
	}

	if req.AccountID == "" {
		return Credential{}, fmt.Errorf("mint: api: accountID is required")
	}

	body, err := json.Marshal(temporaryCredentialsRequest{
		Bucket:     req.Bucket,
		Permission: string(req.Permission),
		Prefixes:   req.Prefixes,
		TTLSeconds: req.TTLSeconds,
	})
	if err != nil {
		return Credential{}, fmt.Errorf("mint: api: encoding request: %w", err)
	}

	url := m.BaseURL + "/accounts/" + req.AccountID + "/r2/temp-access-credentials"
	issued := m.now()
	backoff := defaultBackoff

	for attempt := 0; ; attempt++ {
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return Credential{}, fmt.Errorf("mint: api: building request: %w", err)
		}

		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Authorization", "Bearer "+m.Token.Value)

		resp, err := m.client().Do(httpReq)
		if err != nil {
			return Credential{}, fmt.Errorf("mint: api: request failed: %w", err)
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			wait := retryAfter(resp.Header)
			_ = resp.Body.Close()

			if attempt >= m.maxRetries() {
				return Credential{}, fmt.Errorf("mint: api: rate limited after %d attempts", attempt+1)
			}

			if wait <= 0 {
				wait = backoff
				backoff *= 2
			}

			m.sleep()(wait)

			continue
		}

		cred, err := m.decode(resp, issued, req.TTLSeconds)
		_ = resp.Body.Close()

		return cred, err
	}
}

func (m *APIMinter) decode(resp *http.Response, issued time.Time, ttlSeconds int) (Credential, error) {
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return Credential{}, fmt.Errorf("mint: api: reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return Credential{}, fmt.Errorf("mint: api: temporary-credentials endpoint returned %s: %s", resp.Status, data)
	}

	var out temporaryCredentialsResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return Credential{}, fmt.Errorf("mint: api: decoding response: %w", err)
	}

	if !out.Success {
		return Credential{}, fmt.Errorf("mint: api: request refused: %+v", out.Errors)
	}

	return Credential{
		AccessKeyID:     out.Result.AccessKeyID,
		SecretAccessKey: out.Result.SecretAccessKey,
		SessionToken:    out.Result.SessionToken,
		// The API reference confirms the endpoint "returns a new access
		// key ID, secret access key, and session token" but the design
		// doc found no confirmation of an expiration field in the
		// response; computed from the request's own ttlSeconds instead.
		Expiration: issued.Add(time.Duration(ttlSeconds) * time.Second),
	}, nil
}

// retryAfter parses a Retry-After header as whole seconds. Cloudflare's
// rate-limit docs promise a 429 "for the following five minute period"
// but do not confirm whether the response carries a Retry-After header;
// 0 (meaning "use the built-in backoff instead") is returned when it is
// absent or unparsable.
func retryAfter(h http.Header) time.Duration {
	v := h.Get("Retry-After")
	if v == "" {
		return 0
	}

	secs, err := strconv.Atoi(v)
	if err != nil || secs < 0 {
		return 0
	}

	return time.Duration(secs) * time.Second
}
