// Package decide chooses which grant row a verified request may act
// under, and refuses to hand out anything wider than what that row
// allows.
//
// Every function here is pure: given a request and the config's grant
// rows, decide what it may do, with no I/O and no clock. Verification
// (internal/verify) and minting (internal/mint) are separate concerns —
// this package sits between them, deciding, not authenticating or
// signing.
//
// A request selects by WHAT it wants — bucket, prefixes, permission —
// never by naming a group or a row directly. That keeps this package
// group-only: the token's groups say which rows are reachable at all,
// and the request narrows among those by scope, the same vocabulary the
// grant rows themselves are written in. The estate's own convention is
// one prefix per row per cache tool, so a group commonly owns several
// rows in the same bucket that differ only by Prefixes (or, less often,
// only by Permission) — Decide resolves that ambiguity from what the
// request asks for, or refuses rather than guess.
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
	// Bucket the request wants. Required only when the token's groups
	// reach more than one bucket; a token reaching exactly one bucket
	// needs no Bucket to say so.
	Bucket string
	// Prefixes the request wants, a subset of exactly one grant row's
	// own Prefixes. Empty means "the resolved row's full prefix list".
	// A set of prefixes that is only satisfiable by combining more than
	// one row is refused: one credential mints from exactly one row.
	Prefixes []string
	// Permission the request wants. Only needed to disambiguate rows
	// that are otherwise identical (same bucket, same prefix reach) but
	// differ in Permission — e.g. a reader and a writer grant on the
	// same group. Empty is fine whenever bucket and prefix matching
	// already resolve to one row.
	Permission config.Permission
}

// Decision is what Decide chose: a caller may mint exactly this.
type Decision struct {
	Bucket     string
	Prefixes   []string
	Permission config.Permission
	TTLSeconds int
}

// Decide narrows grants to the rows req's groups hold, then to req's
// requested bucket, then to the rows whose own Prefixes contain every
// prefix req asked for, then — if more than one row still remains — to
// the one matching req.Permission. It refuses:
//
//   - no group in req.Groups holds any row;
//   - req.Bucket names a bucket none of the held rows reaches;
//   - req.Prefixes is not entirely contained in any single held row
//     (including the case where each requested prefix belongs to a
//     *different* row — one credential mints from exactly one row);
//   - a requested prefix that is not in any held row at all (narrowing
//     is allowed, widening is not);
//   - more than one row still matches after bucket and prefix
//     narrowing, and req.Permission does not resolve it to exactly one.
func Decide(req Request, grants []config.Grant) (Decision, error) {
	held := matchingGrants(req.Groups, grants)
	if len(held) == 0 {
		return Decision{}, fmt.Errorf("no group in the token maps to a grant")
	}

	byBucket, err := filterByBucket(held, req.Bucket)
	if err != nil {
		return Decision{}, err
	}

	byPrefix, err := filterByPrefixes(byBucket, req.Prefixes)
	if err != nil {
		return Decision{}, err
	}

	grant, err := resolvePermission(byPrefix, req.Permission)
	if err != nil {
		return Decision{}, err
	}

	prefixes := req.Prefixes
	if len(prefixes) == 0 {
		prefixes = grant.Prefixes
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

// filterByBucket narrows rows (already known non-empty) to
// requestedBucket, or — when requestedBucket is empty — requires that
// rows reach only one bucket in the first place.
func filterByBucket(rows []config.Grant, requestedBucket string) ([]config.Grant, error) {
	if requestedBucket != "" {
		var out []config.Grant

		for _, g := range rows {
			if g.Bucket == requestedBucket {
				out = append(out, g)
			}
		}

		if len(out) == 0 {
			return nil, fmt.Errorf("requested bucket %q is not reachable by the token's groups", requestedBucket)
		}

		return out, nil
	}

	if n := len(distinctBuckets(rows)); n > 1 {
		return nil, fmt.Errorf("the token's groups reach %d buckets — request must name which one with \"bucket\"", n)
	}

	return rows, nil
}

func distinctBuckets(rows []config.Grant) []string {
	var out []string

	for _, g := range rows {
		if !slices.Contains(out, g.Bucket) {
			out = append(out, g.Bucket)
		}
	}

	return out
}

// filterByPrefixes narrows rows (already known non-empty) to those whose
// own Prefixes contain every entry of requested. Empty requested is a
// no-op — it narrows nothing and leaves every row as a candidate for
// resolvePermission.
func filterByPrefixes(rows []config.Grant, requested []string) ([]config.Grant, error) {
	if len(requested) == 0 {
		return rows, nil
	}

	var out []config.Grant

	for _, g := range rows {
		if containsAll(g.Prefixes, requested) {
			out = append(out, g)
		}
	}

	if len(out) == 0 {
		if spansRows(rows, requested) {
			return nil, fmt.Errorf(
				"requested prefixes %v are not all in any single grant row — one credential mints from exactly one row", requested)
		}

		return nil, fmt.Errorf("a requested prefix is not in any grant row reachable by the token — a request may narrow, never widen")
	}

	return out, nil
}

// containsAll reports whether every entry of want is present in have.
func containsAll(have, want []string) bool {
	for _, w := range want {
		if !slices.Contains(have, w) {
			return false
		}
	}

	return true
}

// spansRows reports whether every individually-requested prefix belongs
// to SOME row, even though (as filterByPrefixes has already established)
// no single row holds all of them — i.e. the request is asking to
// combine rows, not to widen past what is configured at all.
func spansRows(rows []config.Grant, requested []string) bool {
	for _, p := range requested {
		if !slices.ContainsFunc(rows, func(g config.Grant) bool { return slices.Contains(g.Prefixes, p) }) {
			return false
		}
	}

	return true
}

// resolvePermission narrows rows (already known non-empty) to exactly
// one, using requestedPermission when more than one row remains. Never
// picks silently: it is an error to leave resolvePermission more than
// one candidate without a permission that narrows to exactly one.
func resolvePermission(rows []config.Grant, requestedPermission config.Permission) (config.Grant, error) {
	if requestedPermission != "" {
		var out []config.Grant

		for _, g := range rows {
			if g.Permission == requestedPermission {
				out = append(out, g)
			}
		}

		rows = out
	}

	switch len(rows) {
	case 0:
		return config.Grant{}, fmt.Errorf("requested permission %q does not match any grant row reachable by bucket and prefix", requestedPermission)
	case 1:
		return rows[0], nil
	default:
		return config.Grant{}, fmt.Errorf(
			"%d grant rows still match after bucket and prefix narrowing — request must name which one, e.g. with \"permission\"", len(rows))
	}
}
