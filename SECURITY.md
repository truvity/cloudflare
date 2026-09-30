# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability, please report it privately via
[GitHub Security Advisories](https://github.com/truvity/cloudflare/security/advisories/new).

Do NOT open a public issue for security vulnerabilities.

## Supported Versions

Only the latest release is supported with security updates.

## What is in scope

This repository publishes:

- The Go packages `pkg/account`, `pkg/zone`, `pkg/tunnel`, `pkg/r2` and `pkg/cfnames`, and the audit catalogue.
- `cmd/r2broker`, the R2 temporary-credentials broker, and its chart `r2-broker`.
- The chart `cloudflared`.
- The documentation, where it tells an adopter to do something unsafe.

Reports that matter most:

- The broker minting credentials it should refuse: a token that is not group-only OIDC, a grant wider than the caller's groups, a bucket outside the grant, or a mint or refusal that is not audited.
- `NewChildToken` or `NewChildTokenSet` creating a token with wider permissions or scope than requested.
- A chart default that weakens authentication or network policy, or that turns `grants: []` into something other than a broker that refuses everything.
- A token, tunnel secret or R2 credential reaching a log line, an error, a rendered manifest or Pulumi state in the clear.

A finding that depends on how a particular deployment uses this repository
belongs with that deployment's owner.
