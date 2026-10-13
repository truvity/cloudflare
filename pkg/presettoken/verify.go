package presettoken

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// A token Cloudflare has just minted is not always usable at once: a first
// apply on a freshly minted token failed with 401 "Authentication error"
// (code 10000), and the same token worked seconds later. So no credential is handed out before Cloudflare accepts it.
const (
	// verifyWindow bounds the wait for a new token, in all.
	verifyWindow = 20 * time.Second
	// verifyEvery is the pause between two verify calls.
	verifyEvery = time.Second
	// verifyAttempts bounds the calls even when a call returns at once.
	verifyAttempts = int(verifyWindow/verifyEvery) + 1
	// r2Settle is how long an R2 pair is left alone before use: an S3 pair
	// has no verify endpoint (its secret is a hash of the token, which
	// sluisctl does not hand out).
	r2Settle = 5 * time.Second
)

// sleep waits d or until ctx is done; tests replace it.
var sleep = func(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// settle returns once Cloudflare accepts the credential: an API token is
// verified (GET /accounts/<account>/tokens/verify: every preset is an
// account token, cloned from an account-owned prototype) every verifyEvery
// for at most verifyWindow; an R2 pair is waited on for r2Settle. The token
// travels only to api.cloudflare.com, over the same fixed client as
// break-glass, and no error carries it.
func (s Source) settle(ctx context.Context, req Request, cred Credential) error {
	if req.R2 {
		if err := sleep(ctx, r2Settle); err != nil {
			return fmt.Errorf("cloudflare preset %s: waiting for the new R2 credential: %w", req.Preset, err)
		}

		return nil
	}

	if req.AccountID == "" {
		return fmt.Errorf("cloudflare preset %s: no account to verify the new token in", req.Preset)
	}

	c, err := newCFClient(req.AccountID, cred.Token)
	if err != nil {
		return fmt.Errorf("cloudflare preset %s: %w", req.Preset, err)
	}

	ctx, cancel := context.WithTimeout(ctx, verifyWindow)
	defer cancel()

	var last error

	for attempt := 1; attempt <= verifyAttempts; attempt++ {
		last = c.verify(ctx)
		if last == nil {
			if attempt > 1 {
				s.notice("cloudflare preset %s: the new token is accepted (attempt %d)", req.Preset, attempt)
			}

			return nil
		}

		if attempt == 1 {
			s.notice("cloudflare preset %s: Cloudflare does not accept the new token yet (%v); retrying for up to %s", req.Preset, last, verifyWindow)
		}

		if attempt == verifyAttempts {
			break
		}

		if err := sleep(ctx, verifyEvery); err != nil {
			break
		}
	}

	return fmt.Errorf("cloudflare preset %s: Cloudflare did not accept the new token within %s: %w", req.Preset, verifyWindow, last)
}

// verify asks Cloudflare whether the client's token is an active account
// token.
func (c *cfClient) verify(ctx context.Context) error {
	var v struct {
		Status string `json:"status"`
	}

	if err := c.do(ctx, http.MethodGet, "/accounts/"+url.PathEscape(c.account)+"/tokens/verify", nil, &v); err != nil {
		return err
	}

	if v.Status != "active" {
		return fmt.Errorf("the token's status is %q, not active", v.Status)
	}

	return nil
}
