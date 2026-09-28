// Package broker is the R2 credential broker's one decision pipeline:
// verify a bearer token, decide which grant it may act under, and mint a
// credential for it.
//
// cmd/r2broker's two entry points — "serve" (the HTTP service) and
// "credentials --config" (the in-process CLI, for an installation with no
// central broker) — both call New and Broker.Mint, so they share this
// pipeline and can never drift (design decision R3: one binary, two
// modes, sharing internal/mint — and, by construction here, also
// internal/verify and internal/decide). Only the transport differs: an
// HTTP handler in cmd/r2broker/serve.go, or a direct function call in
// cmd/r2broker/credentials.go.
package broker

import (
	"context"
	"fmt"
	"net/http"

	"github.com/truvity/cloudflare/v2/internal/config"
	"github.com/truvity/cloudflare/v2/internal/decide"
	"github.com/truvity/cloudflare/v2/internal/mint"
	"github.com/truvity/cloudflare/v2/internal/verify"
)

// CloudflareAPIBaseURL is Cloudflare's own REST API root. Not a config
// field: this is a fixed fact about Cloudflare, not an estate decision
// (contrast with issuer, audience, account id — every one of those is a
// caller input; this one is not, the same way access-roster's STSEndpoint
// is not configurable).
const CloudflareAPIBaseURL = "https://api.cloudflare.com/client/v4"

// Request is what a caller — already holding a raw bearer token — asks
// the broker for. It is the union of the service's request body
// (design §2.1) and the CLI's flags: both build one of these and call
// Broker.Mint.
type Request struct {
	// Token is the raw, unverified bearer token.
	Token string
	// Bucket the caller wants; required only when the token's groups
	// reach more than one bucket (see internal/decide).
	Bucket string
	// Prefixes the caller wants; a subset of exactly one grant row's own
	// prefixes, or empty for that row's full list.
	Prefixes []string
	// Permission the caller wants; only needed to disambiguate rows that
	// are otherwise identical.
	Permission config.Permission
}

// Outcome is which stage of the pipeline a Request reached, so a caller
// (an HTTP handler, a CLI command, and — in a later change — an audit
// emitter) can answer or record it without re-deriving it from Err.
type Outcome int

const (
	// OutcomeMinted means every stage succeeded; Result.Credential is set.
	OutcomeMinted Outcome = iota
	// OutcomeUnauthenticated means the token was missing, malformed,
	// expired, or failed verification against the configured issuer.
	OutcomeUnauthenticated
	// OutcomeRefused means the token verified, but internal/decide found
	// no grant covering the request (no matching group, an unreachable
	// bucket or prefix, or an ambiguous request).
	OutcomeRefused
	// OutcomeMintFailed means decide succeeded, but the minter itself
	// failed (local signing AND its API fallback, when composed).
	OutcomeMintFailed
)

// Result is everything a caller needs to answer a request and, once a
// later change wires audit emission, record it.
type Result struct {
	Outcome Outcome
	// Subject and Groups are set whenever verification succeeded
	// (OutcomeMinted, OutcomeRefused and OutcomeMintFailed), never on
	// OutcomeUnauthenticated.
	Subject string
	Groups  []string
	// Decision is set on OutcomeMinted and OutcomeMintFailed — decide
	// succeeded either way.
	Decision decide.Decision
	// Credential is set only on OutcomeMinted.
	Credential mint.Credential
	// Err is set on every outcome except OutcomeMinted.
	Err error
}

// Broker is the pipeline verify -> decide -> mint, built once (by New)
// from a loaded Config and reused for every request.
type Broker struct {
	Verifier  verify.Verifier
	Grants    []config.Grant
	Minter    mint.Minter
	AccountID string
}

// New builds a Broker from cfg: an OIDC verifier (discovery against
// cfg.Issuer happens now, so New typically runs once at startup), and a
// Minter chosen by cfg.Minting.Mode — MintModeAPI uses the Cloudflare API
// for every mint; anything else (including the zero value, which Load
// already normalizes to MintModeLocal) gets a CompositeMinter that signs
// locally and falls back to the API on error (R1: local signing is the
// default, with an API-mode fallback).
//
// httpClient is used for the OIDC discovery/JWKS fetches and, when built,
// the API minter's calls; nil means http.DefaultClient. observe, if set,
// is called once per mint with which path produced it — see
// mint.CompositeMinter.Observe; this is the drift-detection hook design
// §1.2 calls for (a shift from "local" to "api" outcomes for the same
// kind of request is the signal that Cloudflare changed something under
// the local-signing contract, not an outage).
func New(
	ctx context.Context, cfg *config.Config, parentToken mint.ParentToken,
	httpClient *http.Client, observe func(mint.Path, error),
) (*Broker, error) {
	if cfg == nil {
		return nil, fmt.Errorf("broker: config is required")
	}

	if parentToken.ID == "" || parentToken.Value == "" {
		return nil, fmt.Errorf("broker: parent token id and value are both required")
	}

	verifier, err := verify.New(ctx, cfg.Issuer, cfg.Audience, cfg.GroupsClaim)
	if err != nil {
		return nil, fmt.Errorf("broker: %w", err)
	}

	minter := buildMinter(cfg, parentToken, httpClient, observe)

	return &Broker{Verifier: verifier, Grants: cfg.Grants, Minter: minter, AccountID: cfg.Account.ID}, nil
}

func buildMinter(cfg *config.Config, token mint.ParentToken, httpClient *http.Client, observe func(mint.Path, error)) mint.Minter {
	api := &mint.APIMinter{Client: httpClient, BaseURL: CloudflareAPIBaseURL, Token: token}

	if cfg.Minting.Mode == config.MintModeAPI {
		return api
	}

	local := &mint.LocalMinter{Token: token}

	return &mint.CompositeMinter{Local: local, API: api, Observe: observe}
}

// Mint runs the whole pipeline for one request: verify req.Token, decide
// what it may mint under b.Grants, then mint it. It never panics on a bad
// or hostile request — every failure comes back as a Result whose Outcome
// says which stage refused it.
func (b *Broker) Mint(ctx context.Context, req Request) Result {
	if req.Token == "" {
		return Result{Outcome: OutcomeUnauthenticated, Err: fmt.Errorf("broker: no bearer token presented")}
	}

	verified, err := b.Verifier.Verify(ctx, req.Token)
	if err != nil {
		return Result{Outcome: OutcomeUnauthenticated, Err: err}
	}

	decision, err := decide.Decide(decide.Request{
		Groups:     verified.Groups,
		Bucket:     req.Bucket,
		Prefixes:   req.Prefixes,
		Permission: req.Permission,
	}, b.Grants)
	if err != nil {
		return Result{Outcome: OutcomeRefused, Subject: verified.Subject, Groups: verified.Groups, Err: err}
	}

	cred, err := b.Minter.Mint(ctx, mint.Request{
		AccountID:  b.AccountID,
		Bucket:     decision.Bucket,
		Prefixes:   decision.Prefixes,
		Permission: decision.Permission,
		TTLSeconds: decision.TTLSeconds,
	})
	if err != nil {
		return Result{
			Outcome: OutcomeMintFailed, Subject: verified.Subject, Groups: verified.Groups,
			Decision: decision, Err: err,
		}
	}

	return Result{
		Outcome: OutcomeMinted, Subject: verified.Subject, Groups: verified.Groups,
		Decision: decision, Credential: cred,
	}
}
