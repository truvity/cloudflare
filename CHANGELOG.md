# Changelog

What changed for a consumer, per version, newest first. A version with no
heading here is a patch cut automatically for dependency bumps alone; its
GitHub Release lists them. The chart and the Go module are released
together at every version.

## v2.5.0

- **`r2broker`: the R2 temporary-credentials broker's service, CLI and
  chart.** One binary, two modes, sharing the `internal/mint`,
  `internal/decide` and `internal/verify` groundwork v2.3.0 shipped:
  `r2broker serve` runs `POST /v1/credentials` (a bearer OIDC token in, a
  group -> grant decision, a minted credential out) and `r2broker
  credentials` either calls a running service or mints in-process from a
  local config, printing an AWS `credential_process` document either way.
  A file-locked, per-scope client-side cache keeps several concurrent
  callers in one build to one mint. `charts/r2-broker` deploys the
  service: `grants: []` is the default, and renders a broker that
  verifies tokens and refuses every request rather than a load error.
  `internal/config.Account` gained `parentTokenId` (required): the
  parent token's own id, needed to mint locally, that the original
  config schema had no field for. See
  [docs/reference.md](docs/reference.md#cmdr2broker-and-chartsr2-broker).
- **The broker writes its own audit trail.** Its own catalogue
  (`catalogue/r2broker.yaml`, source `r2broker`, independent of
  access-roster's `roster.*`): `r2broker.credential.minted` and
  `r2broker.credential.refused`, never the credential itself.
  `internal/decide.Decision` gained `Group` (the row that resolved the
  decision), so a minted record can say which group authorized it.
  `r2broker serve` gains `--audit-receiver-url` / `--audit-token-file`
  (or `$R2BROKER_AUDIT_RECEIVER_URL` / `$R2BROKER_AUDIT_TOKEN_FILE`); with
  neither set, every record is still validated against the catalogue and
  logged, kept nowhere else. `charts/r2-broker` gains `audit.receiverUrl`
  and, when it is set, mounts a projected ServiceAccount token (audience
  `audit`) — the broker needs no audit credential of its own.
  `just audit-catalogue` (`audit validate` + `audit check-emitters`) runs
  in CI.

## v2.4.0

- **`pkg/account` gains `NewChildToken`: a generic, least-privilege
  child-token helper.** It mints one account-owned Cloudflare API token
  (`cloudflare.AccountToken`) scoped to a caller-chosen set of policies —
  each a permission-group list plus a `Scope` (`WholeAccountScope`,
  `ZoneScope{ZoneID}` or `R2BucketScope{Jurisdiction, Bucket}`) — under the
  root, account-owned token the estate's Pulumi program runs as. It is the
  generalised form of the token `pkg/r2` has minted for its own bucket
  since v2.2.0: the same by-name, account-scoped permission-group lookup
  (explicit provider carried into the invoke, never the default one), the
  same `Rotation`-forces-`REPLACE` mechanism, and the same
  refuse-before-registering validation, now available to any caller that
  needs a token scoped to a zone or a whole account, not only to an R2
  bucket. A `PermissionGroups` entry naming `Account API Tokens Read` or
  `Account API Tokens Write` is refused outright: only the root token that
  mints child tokens may ever hold either. See
  [docs/reference.md#newchildtoken](docs/reference.md#newchildtoken) and
  [docs/safety.md#pkgaccount](docs/safety.md#pkgaccount).
- **`pkg/r2` now mints its bucket token through `account.NewChildToken`.**
  `Config`, `New`'s signature and every `R2` output are unchanged; the
  underlying `cloudflare.AccountToken` keeps the exact same child name and
  type in Pulumi's state (`NewChildToken`'s result is deliberately not a
  component resource, precisely so this move is invisible to an existing
  deployment — see [docs/reference.md#newchildtoken](docs/reference.md#newchildtoken)).
  No consumer of `pkg/r2` needs to change anything.

## v2.3.1

- **Fix: `pkg/r2`'s permission-group lookup no longer double-encodes the
  Name filter.** It pre-encoded spaces as `%20` before calling
  `getAccountApiTokenPermissionGroupsList`, but the provider URL-encodes
  that argument itself — the request arrived as
  `name=Workers%2520R2%2520Storage%2520Bucket%2520Item%2520Write`,
  Cloudflare filtered by that literal string, and the lookup found
  nothing even when the token had the permission. The name is now passed
  plain. The lookup also now refuses rather than guesses when the
  (undocumented-as-exact) filter returns zero or more than one entry
  whose name matches exactly.

## v2.3.0

- **Internal groundwork for an R2 temporary-credentials broker**, under
  `internal/`: OIDC verification behind a small `Verifier` interface
  (`github.com/coreos/go-oidc/v3`), a group-only config schema
  (`group → bucket/prefixes/permission`, no claim-matching fields), a
  `Minter` that signs temporary credentials locally per Cloudflare's
  documented HS256 mechanism with an API-mode fallback, and pure
  group-to-grant decision logic (a request selects by bucket/prefixes/
  permission, never by naming a group or a row directly). No service,
  CLI, chart, or release artifact ships yet — this change has no
  consumer-visible effect.
- **Fix: `pkg/r2`'s permission-group lookup, and `pkg/tunnel`'s token
  lookup, now carry the account's explicit Cloudflare provider.** Neither
  invoke had one: a resource inherits its parent component's provider
  automatically, but a plain invoke does not, so both fell back to the
  DEFAULT Cloudflare provider regardless of what `opts` gave `New`. An
  estate that disables that default provider saw the whole apply fail at
  preview the moment an R2 bucket's token was enabled, before touching a
  single resource. `account.InvokeOptionsFromResourceOptions(opts...)`
  (and the new `Account.Invoke()`, `Use()`'s invoke-side counterpart) now
  threads the same explicit provider the sibling resources use into both
  invokes. A caller who already passes `acct.Use()` needs no code change.
  See [safety.md](docs/safety.md#an-invoke-does-not-inherit-a-provider-the-way-a-resource-does).

## v2.2.0

- **`pkg/r2`**: a Pulumi component for one R2 bucket, an opt-in expiry
  lifecycle, and an account-owned API token scoped to exactly that bucket,
  plus the S3-compatible credential pair (access key id, secret access
  key) Cloudflare derives from it. The permission group named in the
  token's policy is looked up by name, through the account-scoped
  permission-group list, at apply time — never a hard-coded id.
  `Token.Rotation` forces the token to be replaced — a fresh id and value
  — when changed to any new value, never an in-place rename. No consumer
  currently references it; additive.

## v2.1.0

- **`pkg/zone` gains `cache`: which hostnames a zone may cache at all.**
  Without it a zone caches by file extension — a response under a `.js`
  or `.css` name is stored at the edge whether or not its origin asked,
  and where the origin sent no `Cache-Control` the zone gives the browser
  four hours. The block renders the `http_request_cache_settings` phase
  as two rules whose expressions partition the zone, so exactly one
  matches any request: a listed host is cached only as far as its own
  `Cache-Control` goes, and everything else is bypassed.
  `respectOriginBrowserTtl` sets the zone's Browser Cache TTL to "Respect
  Existing Headers", which is what stops the four hours being added to
  responses no rule caches. Additive: a zone without the block keeps the
  caching it has. New children: `cache-rules-<name>` and
  `setting-<name>-browser-cache-ttl`. A zone has one ruleset per phase,
  so adopting a zone that already has cache rules means importing or
  deleting them first — see [reference.md](docs/reference.md#pkgzone).

## v2.0.1

- **Use this release, not v2.0.0, for Go.** The module path is now
  `github.com/truvity/cloudflare/v2`; v2.0.0's `go.mod` still declared the
  v1 path, and Go refuses a major-version tag whose module path disagrees.
  The chart is unchanged apart from the version.

## v2.0.0

- **Accounts and zones are data.** The new `pkg/account` binds one API
  token to one account and hands back the resource option
  (`acct.Use()`, an explicit provider) that binds a zone, tunnel or
  record to that account, where the provider otherwise arrives
  ambiently. It is additive: `tunnel.Args` still carries the account id
  as a string, and `pkg/tunnel`'s only change in this release is the
  ingress-order check below.
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
