# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability, please report it privately via
[GitHub Security Advisories](https://github.com/truvity/edge/security/advisories/new).

Do NOT open a public issue for security vulnerabilities.

## Supported Versions

Only the latest release is supported with security updates.

## What is in scope

This repository publishes:

- The Go packages under `cloudflare/` (`account`, `zone`, `tunnel`, `r2`, `cfnames` and the rest) and the gateway `catalog/`.
- The charts `cloudflared`, `gateway-fleet`, `gateway-groups`, `gateway-policies`, `gateway-projects` and `gateway-routes`, as published to `oci://ghcr.io/truvity/charts`.
- The documentation, where it tells an adopter to do something unsafe, or to expose or trust something it should not.

Reports that matter most:

- `NewChildToken` or `NewChildTokenSet` creating a token with wider permissions or scope than requested.
- A chart default that weakens authentication, TLS or network policy, or widens which namespaces or hostnames may attach to a Gateway.
- A `SecurityPolicy` the gateway charts render that lets an unauthenticated or wrongly authorised request reach a gated route, or a CSRF or JWT check that can be skipped.
- A group claiming another group's hostname, or any render-time refusal that accepts input it should reject.
- A token, tunnel secret or R2 credential reaching a log line, an error, a rendered manifest or Pulumi state in the clear.

A finding that depends on how a particular deployment uses this repository
belongs with that deployment's owner.
