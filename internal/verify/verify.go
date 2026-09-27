// Package verify checks an incoming bearer token against an OIDC issuer
// and reads its groups claim.
//
// The library's contract, shared by every public truvity module:
//
//   - Mechanism only. Nothing here names a real issuer or audience; both
//     are caller inputs.
//   - Any OIDC issuer, not one estate's. The broker this package serves
//     must work standalone, so verification is standard OIDC —
//     discovery, JWKS, issuer, audience and expiry — with nothing
//     specific to any one identity provider.
//   - One small interface. Verifier is the only thing the rest of the
//     broker depends on, so a different verification library is a
//     one-file swap.
package verify

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Result is what a verified token yielded: who it was issued to, and
// which groups it carries.
type Result struct {
	// Subject is the token's sub claim.
	Subject string
	// Groups is the token's groups claim (see Config.GroupsClaim),
	// exactly as the issuer wrote it. Missing or empty is not an error
	// here — it simply means the caller (internal/decide) finds no
	// grant, the same outcome as a groups claim with no matching group.
	Groups []string
}

// Verifier checks a raw bearer token and reports who it was for. The rest
// of the broker depends only on this interface, never on
// *OIDCVerifier or go-oidc directly, so a different verification library
// is a one-file swap (design decision: keep verification behind one small
// interface).
type Verifier interface {
	Verify(ctx context.Context, rawToken string) (Result, error)
}

// OIDCVerifier verifies a bearer token issued by any standards-compliant
// OIDC provider: issuer, audience and expiry, via the provider's
// discovery document and JWKS.
type OIDCVerifier struct {
	verifier    *oidc.IDTokenVerifier
	groupsClaim string
}

// New builds an OIDCVerifier for issuer, requiring audience in a token's
// aud claim, and reading groupsClaim as the group list. It performs OIDC
// discovery against issuer immediately, so a caller typically builds one
// verifier at startup and reuses it.
func New(ctx context.Context, issuer, audience, groupsClaim string) (*OIDCVerifier, error) {
	if issuer == "" {
		return nil, fmt.Errorf("verify: issuer is required")
	}

	if audience == "" {
		return nil, fmt.Errorf("verify: audience is required")
	}

	if groupsClaim == "" {
		return nil, fmt.Errorf("verify: groupsClaim is required")
	}

	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("verify: discovering %s: %w", issuer, err)
	}

	return &OIDCVerifier{
		verifier:    provider.Verifier(&oidc.Config{ClientID: audience}),
		groupsClaim: groupsClaim,
	}, nil
}

// Verify checks rawToken's signature against the provider's JWKS, and its
// issuer, audience and expiry (all via go-oidc's IDTokenVerifier), then
// reads Subject and the configured groups claim.
func (v *OIDCVerifier) Verify(ctx context.Context, rawToken string) (Result, error) {
	idToken, err := v.verifier.Verify(ctx, rawToken)
	if err != nil {
		return Result{}, fmt.Errorf("verify: %w", err)
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return Result{}, fmt.Errorf("verify: decoding claims: %w", err)
	}

	groups, err := stringSlice(claims[v.groupsClaim])
	if err != nil {
		return Result{}, fmt.Errorf("verify: claim %q: %w", v.groupsClaim, err)
	}

	return Result{Subject: idToken.Subject, Groups: groups}, nil
}

// stringSlice reads a JSON-decoded claim value as a list of strings.
// nil (the claim is absent) is not an error: it yields no groups.
func stringSlice(v any) ([]string, error) {
	if v == nil {
		return nil, nil
	}

	raw, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("expected a list of strings, got %T", v)
	}

	out := make([]string, 0, len(raw))

	for _, e := range raw {
		s, ok := e.(string)
		if !ok {
			return nil, fmt.Errorf("expected a list of strings, found a %T element", e)
		}

		out = append(out, s)
	}

	return out, nil
}
