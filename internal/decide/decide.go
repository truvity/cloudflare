// Package decide chooses which grant a verified request may act under,
// and refuses to hand out anything wider than what a config.Grant row
// allows.
//
// Every function here is pure: given a request and the config's grant
// rows, decide what it may do, with no I/O and no clock. Verification
// (internal/verify) and minting (internal/mint) are separate concerns —
// this package sits between them, deciding, not authenticating or
// signing.
package decide

import (
	"fmt"
	"slices"

	"github.com/truvity/cloudflare/v2/internal/config"
)

// Request is what a caller asks for, after its token has already been
// verified.
type Request struct {
	// Groups the verified token carries (verify.Result.Groups).
	Groups []string
	// Grant optionally names which group's row to use, when the token
	// carries more than one group with a matching row — mirrors the
	// broker's own API (design §2.1): a caller says explicitly which
	// grant it wants rather than the broker silently picking one. Empty
	// is fine when at most one grant row matches Groups.
	Grant string
	// Prefixes optionally narrows the chosen grant's own prefix list.
	// Empty means "the grant's full prefix list". Every entry must
	// already be one of the grant's own Prefixes — decide never widens.
	Prefixes []string
}

// Decision is what Decide chose: a caller may mint exactly this.
type Decision struct {
	Bucket     string
	Prefixes   []string
	Permission config.Permission
	TTLSeconds int
}

// Decide picks the one config.Grant that req's groups and req.Grant
// resolve to, then narrows its prefixes per req.Prefixes. It refuses:
//
//   - no group in req.Groups has a matching row;
//   - more than one row matches and req.Grant does not say which;
//   - req.Grant names a group that is not among req.Groups, or that has
//     no row for it (either way, req did not earn that grant);
//   - a requested prefix that is not already in the chosen grant's own
//     prefix list (narrowing is allowed, widening is not).
func Decide(req Request, grants []config.Grant) (Decision, error) {
	candidates := matchingGrants(req.Groups, grants)
	if len(candidates) == 0 {
		return Decision{}, fmt.Errorf("no group in the token maps to a grant")
	}

	grant, err := pickGrant(candidates, req.Grant)
	if err != nil {
		return Decision{}, err
	}

	prefixes, err := narrowPrefixes(grant.Prefixes, req.Prefixes)
	if err != nil {
		return Decision{}, err
	}

	return Decision{
		Bucket:     grant.Bucket,
		Prefixes:   prefixes,
		Permission: grant.Permission,
		TTLSeconds: grant.TTLSeconds,
	}, nil
}

// matchingGrants returns every grant row whose Group is in groups, in
// the config's own order.
func matchingGrants(groups []string, grants []config.Grant) []config.Grant {
	var out []config.Grant

	for _, g := range grants {
		if slices.Contains(groups, g.Group) {
			out = append(out, g)
		}
	}

	return out
}

// pickGrant resolves candidates (already known non-empty) to exactly one
// grant, using requestedGroup to disambiguate when there is more than
// one.
func pickGrant(candidates []config.Grant, requestedGroup string) (config.Grant, error) {
	if requestedGroup == "" {
		if len(candidates) > 1 {
			return config.Grant{}, fmt.Errorf(
				"the token's groups map to %d grants — request must name which one with \"grant\"", len(candidates))
		}

		return candidates[0], nil
	}

	for _, g := range candidates {
		if g.Group == requestedGroup {
			return g, nil
		}
	}

	return config.Grant{}, fmt.Errorf("requested grant %q is not among the token's groups", requestedGroup)
}

// narrowPrefixes validates a caller-requested subset of a grant's own
// prefixes and returns it, or the grant's full list when nothing was
// requested.
func narrowPrefixes(grantPrefixes, requested []string) ([]string, error) {
	if len(requested) == 0 {
		return grantPrefixes, nil
	}

	for _, p := range requested {
		if !slices.Contains(grantPrefixes, p) {
			return nil, fmt.Errorf("requested prefix %q is not in the grant's own prefix list — a request may narrow, never widen", p)
		}
	}

	return requested, nil
}
