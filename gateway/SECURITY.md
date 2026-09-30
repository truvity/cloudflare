# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability, please report it privately via
[GitHub Security Advisories](https://github.com/truvity/gateway/security/advisories/new).

Do NOT open a public issue for security vulnerabilities.

## Supported Versions

Only the latest release is supported with security updates.

## What is in scope

This repository publishes:

- The charts `gateway-fleet`, `gateway-groups`, `gateway-policies` and `gateway-routes`, as published to `oci://ghcr.io/truvity/charts`.
- The documentation, where it tells an adopter to expose or trust something it should not.

Reports that matter most:

- A chart default that weakens TLS, widens which namespaces or hostnames may attach to a Gateway, or drops the baseline ClientTrafficPolicy or NetworkPolicy.
- A `SecurityPolicy` the charts render that lets an unauthenticated or wrongly authorised request reach a gated route, or a CSRF or JWT check that can be skipped.
- A group claiming another group's hostname, or any render-time refusal that accepts input it should reject.
- A secret or token reaching a rendered manifest or an error message.

A finding that depends on how a particular deployment uses this repository
belongs with that deployment's owner.
