// Command r2broker is the R2 temporary-credentials broker: one binary,
// two modes (design decision R3).
//
//   - "serve" runs the long-running HTTP service: it verifies a bearer
//     OIDC token, decides which configured grant it covers, and mints a
//     temporary R2 credential for it. This is what a centrally-deployed
//     installation runs, and what `accessctl r2` (in access-roster) execs
//     against over HTTP.
//   - "credentials" is a client of that service (--service-url) OR, for
//     an installation with no central broker at all, mints in-process
//     from a local config file (--config) — "the installation that has
//     no use for the rest of this repository" (design §2.6). Either way
//     it prints an AWS credential_process document (Version 1) to
//     stdout, so an AWS SDK's `credential_process` setting can name this
//     command directly.
//
// Both modes share internal/broker (verify -> decide -> mint) and, under
// it, internal/mint, internal/decide, internal/verify and
// internal/config, so "serve" and "credentials --config" can never drift
// from each other.
//
// Nothing in this binary knows a real issuer, account, bucket or group
// name: every one of those is a --config file or an environment variable,
// supplied by whoever deploys it. See internal/config's doc comment.
package main
