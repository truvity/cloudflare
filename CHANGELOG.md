# Changelog

What changed for a consumer, per version, newest first. A version with no
heading here is a patch cut automatically for dependency bumps alone; its
GitHub Release lists them. The chart and the Go module are released
together at every version.

## v2.11.1

- Dependency updates.

## v2.11.0

- **`r2broker` and `charts/r2-broker`: OpenTelemetry.** `r2broker serve` now
  pushes metrics and traces over OTLP/HTTP, configured by OpenTelemetry's own
  environment only (`OTEL_EXPORTER_OTLP_ENDPOINT` and friends) and only when a
  collector is named: without one nothing is installed and nothing is exported.
  It publishes `r2broker_grants` (steady), `r2broker_credentials_minted_total`
  (by `path`), `r2broker_credentials_failed_total` (by `outcome`),
  `r2broker_credentials_duration_seconds`, `r2broker_mint_api_fallbacks_total`
  and a server span per credential request. The chart gains
  `telemetry.otlp` (`endpoint`, `protocol`, `extraEnv`), which renders
  `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_PROTOCOL` and
  `OTEL_SERVICE_NAME=r2-broker`; it refuses a non-http(s) endpoint and any
  `extraEnv` key that is not `OTEL_*`. Empty renders nothing, so an existing
  release renders byte for byte what it did. See `docs/reference.md`,
  Telemetry.

## v2.10.1

- Dependency updates.

## v2.10.0

- **`zone`: `RateLimits`, the zone's rate limiting rules, validated against
  the plan.** A new optional `Args.RateLimits` (`rateLimits`: `plan` and
  `rules`) manages the zone's whole `http_ratelimit` entry point ruleset as
  one `cloudflare.Ruleset` child, `ratelimit-<name>`. Each rule is a name,
  `endpoints` (host and path or path-prefix pairs, ORed into one expression
  with every value restricted to a character set that needs no escaping) or
  a hand-written `expression`, `characteristics` (default `ip.src`;
  `cf.colo.id` is added for you), `period`, `requests`, `mitigationTimeout`
  and `action`. `plan` is `free`, `pro` or `business` and the limits are
  constants per plan: rule count (Pro: 2), periods (Pro: 10 or 60), block
  durations, counting keys, and the fields Pro lacks (no request method, no
  separate counting expression) are refused before the apply, as is the
  Enterprise-only `log` action. Several endpoints in one rule share one
  counter per address per data center, which is how a small quota covers
  several endpoints; see `docs/reference.md`. Nil manages nothing, so
  existing zones are unchanged; a declared zone owns the whole phase, and
  the token needs `Zone WAF Write` (`EdgePoliciesWithWAF`).

## v2.9.0

- **`account`: `EdgePoliciesWithWAF`, the edge preset with an opt-in WAF
  grant.** `EdgePoliciesWithWAF(wafZoneIDs, zoneIDs...)` returns exactly
  what `EdgePolicies(zoneIDs...)` returns, plus one zone-scoped policy per
  zone in `wafZoneIDs` granting `Zone WAF Write`, the permission
  `zone.Args.TrustedClients` needs. `EdgePolicies` itself is unchanged, and
  an empty `wafZoneIDs` gives identical output. See `docs/reference.md`.

## v2.8.0

- **`zone`: `TrustedClients`, one skip rule for known client ranges.** A new
  optional `Args.TrustedClients` (`trustedClients`: `zone`, `hosts`,
  `ranges`, `description`) creates one zone Ruleset child,
  `firewall-custom-<name>`, in the `http_request_firewall_custom` phase with
  one `skip` rule: a request to one of the hosts from an address in one of
  the ranges skips the remaining custom rules, managed rules, rate
  limiting, Super Bot Fight Mode and the legacy security products. Hosts
  must be lower-case exact names inside the zone; ranges must be CIDR
  blocks with no host bits, no shorter than /8 (IPv4) or /16 (IPv6). Both
  lists empty manages no ruleset. The token needs `Zone WAF Write` on the
  zone, which `EdgePolicies` does not grant. See `docs/reference.md`.

## v2.7.2

- **`r2broker`: locally signed credentials are ones R2 accepts.** The local
  minter had guessed the JWT's claims, because Cloudflare had not published
  them. It now follows Cloudflare's published client-side signing example
  ([Authenticate against R2 with temporary credentials](https://developers.cloudflare.com/r2/examples/authenticate-r2-temp-credentials/)).
  The header gains `typ: JWT`. The claims are `sub` (account id), `iss`
  (parent access key id), `aud` (the S3 endpoint host), `iat`, `exp`,
  `bucket`, `scope`, and `paths.prefixPaths` when the grant has prefixes;
  they used to be `accountId`, `permission`, `prefixes` and
  `parentAccessKeyId`. The HMAC key is the parent secret access key as
  text (hex SHA-256 of the token value), where it used to be the digest's
  raw bytes. Up to v2.7.1, R2 refused every locally minted credential with
  `400 InvalidArgument: X-Amz-Security-Token`, and the broker could not
  see it, because local signing never fails and the API fallback runs only
  on a signing error.
- **`r2broker`: `minting.mode: api` sends `parentAccessKeyId`**, which the
  temporary-credentials endpoint requires.

## v2.7.1

- OpenTelemetry exporters bumped to the current stable line (`otlploggrpc` v0.22.0, `otlptrace` v1.46.0); govulncheck reports no reachable vulnerability.
- `doc.go` lists every package, command and chart, including `pkg/r2`, `pkg/cfnames`, `cmd/r2broker` and `charts/r2-broker`; README follows the component contract's heading order with `Consumers` and `Neighbours` (gateway and tailscale as the other layers of the exposure path) and pins the install example.

## v2.7.0

- **`charts/r2-broker`: `account.id` and `account.parentTokenId` can each
  come from the same Secret as the parent token's value, not just a
  plain value.** New `account.idSecretKey` / `account.parentTokenIdSecretKey`
  values (default `""`) name a key in `account.parentTokenSecretName`;
  when set, the chart mounts that key read-only and points
  `internal/config.Account`'s new `idFile` / `parentTokenIdFile` fields at
  it instead of `id` / `parentTokenId`. The plain values stay the default
  and fully supported — this is additive. `values.schema.json` refuses a
  values file that sets both or neither of a pair. A file's contents are
  trimmed of exactly one trailing newline; any other whitespace fails the
  load. See
  [docs/reference.md#chartsr2-broker-values](docs/reference.md#chartsr2-broker-values).
- **A new SDK-free package, `pkg/cfnames`, holds the R2 jurisdiction list
  and the R2 bucket-name syntax check.** `pkg/account`'s
  `ValidR2Jurisdiction` and `ValidR2BucketName` now delegate to it;
  behaviour is unchanged. Unlike `pkg/account` and `pkg/r2`, `pkg/cfnames`
  imports nothing outside the standard library (enforced by its own
  test), so a downstream config layer that only needs to validate a
  jurisdiction or a bucket name no longer has to pull in the Pulumi/
  Cloudflare SDK, or keep its own copy of the jurisdiction list, to do it.

## v2.6.0

- **`pkg/account` gains `NewChildTokenSet`: the "one root token mints
  every least-privilege child" pattern, reusable instead of hand-written
  once per estate.** It mints one child token per entry of a
  `map[string]ChildTokenConfig`, in sorted key order, and returns them
  keyed by the same name. It is a plain iteration convenience over
  `NewChildToken`: every minted resource's Pulumi name, type and provider
  come entirely from the map's own keys, exactly as they would from the
  equivalent hand-written `NewChildToken` calls, so migrating several such
  calls onto one `NewChildTokenSet` call is a zero-diff change in Pulumi's
  state as long as the map's keys are the names those calls already used.
  Three optional presets — `EdgePolicies(zoneIDs...)`, `R2AdminPolicies()`
  and `R2BucketParentPolicies(jurisdiction, bucket)` — build the
  `[]ChildTokenPolicy` for a common child role from Cloudflare's own live
  permission-group names. See
  [docs/reference.md#newchildtokenset](docs/reference.md#newchildtokenset)
  and the new [docs/layout.md](docs/layout.md), a worked root/edge/r2
  split using this and `NewChildToken` together.
- **`pkg/r2`'s `Config.Token` (and `TokenConfig`) is deprecated.** Mint a
  bucket's parent token separately instead, with `NewChildToken`/
  `NewChildTokenSet` and the new `R2BucketParentPolicies`, then call `New`
  with `Token.Enabled: false` — see
  [docs/reference.md#token-is-deprecated](docs/reference.md#token-is-deprecated).
  `Config.Token` is unchanged and keeps working; this is a documentation
  change only, not a removal.
- **Docs: two stale "(dashboard: … — Edit)" cross-references, in `pkg/r2`'s
  package doc and `docs/reference.md`, are corrected.** Cloudflare's own
  `getAccountApiTokenPermissionGroupsList` names every group this library
  grants with "Write"/"Read" (`Cloudflare Tunnel Write`, `DNS Write`, `SSL
  and Certificates Write`, `Zone Settings Write`, `Cache Settings Write`,
  `Workers R2 Storage Write`, `Workers R2 Storage Bucket Item Write`);
  there is no "Cache Rules" group. No permission-group name this library
  actually looks up changed — only the doc text describing it.

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
