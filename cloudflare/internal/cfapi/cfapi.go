// Package cfapi is the small Cloudflare API v4 client the read and apply
// tools share: one bearer token, the response envelope, and errors that never
// carry the token.
package cfapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultBase is the Cloudflare API v4 root.
const DefaultBase = "https://api.cloudflare.com/client/v4"

// maxBody bounds what is read of any response.
const maxBody = 16 << 20

// Client talks to the Cloudflare API with one token.
type Client struct {
	// Base is the API root; empty means DefaultBase. Tests point it at an
	// httptest server.
	Base string
	// Token is the bearer token. It is sent in the Authorization header only,
	// and is never part of an error.
	Token string
	// HTTP is the transport; nil means a client with a 30 second timeout.
	HTTP *http.Client
}

// Envelope is Cloudflare's response wrapper.
type Envelope struct {
	Success    bool            `json:"success"`
	Errors     json.RawMessage `json:"errors"`
	Result     json.RawMessage `json:"result"`
	ResultInfo *ResultInfo     `json:"result_info,omitempty"`
}

// ResultInfo is the paging block of a list response.
type ResultInfo struct {
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	Count      int `json:"count"`
	TotalCount int `json:"total_count"`
}

// Do sends one request below the base and returns the envelope of a
// successful answer. path starts with a slash; query may be nil; body may be
// nil.
func (c *Client) Do(ctx context.Context, method, path string, query url.Values, body []byte) (*Envelope, error) {
	raw, err := c.send(ctx, method, path, query, body, true)
	if err != nil {
		return nil, err
	}

	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("%s %s: not a Cloudflare API response", method, path)
	}

	if !env.Success {
		return nil, errors.New(method + " " + path + ": " + redact(string(env.Errors), c.Token))
	}

	return &env, nil
}

// send is one round trip. With enveloped, a non-2xx answer is reported with
// the envelope's errors; without, with the status and the start of the body.
func (c *Client) send(ctx context.Context, method, path string, query url.Values, body []byte, enveloped bool) ([]byte, error) {
	base := strings.TrimRight(c.Base, "/")
	if base == "" {
		base = DefaultBase
	}

	target := base + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}

	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, target, rdr)
	if err != nil {
		return nil, errors.New("build request: " + redact(err.Error(), c.Token))
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}

	resp, err := hc.Do(req)
	if err != nil {
		return nil, errors.New(method + " " + path + ": " + redact(err.Error(), c.Token))
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, errors.New(method + " " + path + ": read response: " + redact(err.Error(), c.Token))
	}

	if resp.StatusCode/100 != 2 {
		detail := ""

		switch {
		case enveloped:
			var env Envelope
			if json.Unmarshal(raw, &env) == nil {
				detail = string(env.Errors)
			}
		case len(raw) > 512:
			detail = string(raw[:512])
		default:
			detail = string(raw)
		}

		return nil, errors.New(method + " " + path + ": HTTP " + resp.Status + ": " + redact(detail, c.Token))
	}

	return raw, nil
}

// redact removes the token from a message that may echo it.
func redact(s, token string) string {
	if token == "" {
		return s
	}

	return strings.ReplaceAll(s, token, "[token]")
}

// Raw sends one request and returns the body of a 2xx answer as is. It is for
// the GraphQL endpoint, whose answer is {data, errors} and not the REST
// envelope.
func (c *Client) Raw(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	return c.send(ctx, method, path, nil, body, false)
}
