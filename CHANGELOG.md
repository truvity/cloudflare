# Changelog

What changed for a consumer, per version, newest first. A version with no
heading here is a patch cut automatically for dependency bumps alone; its
GitHub Release lists them. The chart and the Go module are released
together at every version.

## v2.0.1

- **Use this release, not v2.0.0, for Go.** The module path is now
  `github.com/truvity/cloudflare/v2`; v2.0.0's `go.mod` still declared the
  v1 path, and Go refuses a major-version tag whose module path disagrees.
  The chart is unchanged apart from the version.

## v2.0.0

- **Breaking: accounts and zones are data.** `pkg/account` binds one API
  token to one account and hands back the resource option every zone,
  tunnel and record in that account is created with; the account id is no
  longer a string on `tunnel.Args` with the provider arriving ambiently.
- **`pkg/zone`**: the three zone settings an estate decides — origin SSL
  mode, minimum TLS version and Total TLS — each opt-in; a zone that would
  manage nothing is refused.
- **Breaking: `charts/cloudflared` installs once per account.** The
  Deployment, PodDisruptionBudget and ServiceAccount are named after the
  release, and the pod selector gains `app.kubernetes.io/instance`. A
  selector is immutable, so an existing install is deleted and recreated
  rather than upgraded in place; with the release named `cloudflared`
  every object keeps its name and only the selector changes.
  `serviceAccount.name` now defaults to empty, meaning "named after the
  release".
- **`tunnel.Args.Validate` refuses an ingress list in which an earlier
  rule already catches a later one**: a wildcard before an exact host
  under it, a broad wildcard before a deeper one, a duplicate hostname, a
  catch-all before anything else. cloudflared uses the first matching
  rule's hostname as the origin SNI, so a shadowed host answers 502 with a
  configuration that reads correctly.
- Dependency updates that clear GO-2026-6443 and GO-2026-6348 (gRPC,
  transitive).

## v1.2.0

- **`pkg/tunnel`**: a Pulumi component that provisions a remotely managed
  tunnel from one plain-data struct — the tunnel, its ordered ingress
  rules with the catch-all appended, proxied CNAMEs, and an opt-in
  Advanced Certificate block. The tunnel secret is a caller input and the
  token a secret output; child resource names are a documented contract.

## v1.1.0

- **`values.schema.json`**: an unknown key fails the render.

## v1.0.0

- First release: the `cloudflared` chart and the Go module skeleton.
