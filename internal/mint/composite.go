package mint

import (
	"context"
	"fmt"
)

// Path names which minter actually produced a credential, for
// CompositeMinter's Observe callback.
type Path string

const (
	// PathLocal means LocalMinter produced the credential.
	PathLocal Path = "local"
	// PathAPI means the Cloudflare API produced the credential — either
	// because CompositeMinter fell back to it, or because it is
	// configured as the primary.
	PathAPI Path = "api"
)

// CompositeMinter tries Local first and falls over to API on error.
//
// Local signing rests on a thinly-documented contract (see LocalMinter's
// doc comment): Cloudflare could change the JWT's claim shape or HMAC
// details without a versioned API bump, since it is not exposed as a
// `/client/v4/...` endpoint with its own changelog entry. Treating API
// mode as a live, exercised fallback — rather than a paper option nobody
// runs until the day local signing breaks — is what makes preferring
// local signing safe: a caller wires Observe to its own metrics/alerts,
// and a shift from "local" to "api" outcomes for the same kind of request
// is the signal that Cloudflare changed something under the local
// contract, not a Cloudflare outage.
type CompositeMinter struct {
	// Local is tried first.
	Local Minter
	// API is used when Local returns an error.
	API Minter
	// Observe, if set, is called once per Mint with which path produced
	// the result (or was last attempted, on a total failure) and that
	// path's error, if any. It is the hook the estate wires to drift
	// detection — this package does no alerting itself.
	Observe func(path Path, err error)
}

// Mint tries m.Local, and on error falls back to m.API.
func (m *CompositeMinter) Mint(ctx context.Context, req Request) (Credential, error) {
	cred, localErr := m.Local.Mint(ctx, req)
	if localErr == nil {
		m.observe(PathLocal, nil)

		return cred, nil
	}

	cred, apiErr := m.API.Mint(ctx, req)
	if apiErr != nil {
		m.observe(PathAPI, apiErr)

		return Credential{}, fmt.Errorf("mint: local signing failed (%v) and the api fallback also failed: %w", localErr, apiErr)
	}

	m.observe(PathAPI, nil)

	return cred, nil
}

func (m *CompositeMinter) observe(path Path, err error) {
	if m.Observe != nil {
		m.Observe(path, err)
	}
}
