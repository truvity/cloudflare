# Changelog

What changed for a consumer, per version, newest first. Every tag has a
heading; one whose only change was a dependency or CI-pin bump says so and
points at the GitHub Release for the commit list. Every chart is released
at every version.

## Unreleased

- **Feature:** new chart `gateway-projects`: the edge of every project on one Kubernetes cluster in one release. `groups` takes the values of `gateway-groups` (one ListenerSet per project, its listeners and Certificates) and `policies` those of `gateway-policies` (default-deny, allow, sign-in and bearer-token policies); each section renders exactly what its own chart renders for the same values (the templates are carried over by `hack/sync-gateway-projects.sh`, which CI checks, and a test compares the objects). Removing a project's entries removes its objects. `gateway-policies`' TLS floor is on by default there as in its own chart; a project release usually sets `policies.tlsBaseline.enabled: false`. The existing charts are unchanged.

## v1.10.0

- **A Go library: `github.com/truvity/gateway/catalog`.** The edge catalog
  an estate keeps (exposures, and per cluster the groups whose ListenerSets
  attach to them) as a loader and a validator, the queries every reader of
  it needs (`Groups`, `ExposuresOn`, `TunnelHosts`, `Classes`, ...), and the
  Gateway API grant shapes. Moved here from the estate repository that wrote
  it first; nothing in the charts changes, and no chart render differs.
- **Per-project groups are generated.** An exposure with a `project_groups`
  section gets one group per project per cluster, from the projects the
  caller passes to `Config.WithProjects`: named after the project,
  answering to its hostnames on that cluster, admitting only its own
  namespace (by `kubernetes.io/metadata.name`), served from its own
  ListenerSet. Adding a hostname to a project is the whole change for its
  listener. `project_groups.overrides` keeps what is already live (a group
  name, listener and Secret names, a description). A generated group never
  replaces a written one: a name clash is an error, and so is an override
  for a project with nothing to serve on that cluster.
- `just test` also runs the Go tests; the devbox carries Go.

## v1.9.1

- Dependency updates.

## v1.9.0

- **`gateway-policies`: `securityPolicies.<name>.type: deny` and `allow`.**
  A SecurityPolicy that carries only `authorization.defaultAction`: `deny`
  renders `Deny` (written out, though it is the controller's default), `allow`
  renders `Allow`. Meant for a default-deny on a ListenerSet, so a route that
  lands before its own policy is refused instead of served unauthenticated,
  and an explicit allow on a route or rule (`sectionName`) that is public on
  purpose; a route-level policy replaces the listener-level one. Neither type
  takes `oidc`/`jwt`; CSRF must be off, `targetRefs` non-empty, and a target
  is claimed once as for every type. Additive: an existing render is
  byte-identical. Test cases `gateway-policies/deny-allow-listenerset`,
  `deny-allow-route-rule` and five negative fixtures.
- **`gateway-fleet`: optional connection age and idle timeout on the client
  traffic policy.** `clientTraffic.connection.maxConnectionDuration`,
  `clientTraffic.idleTimeout` and `clientTraffic.http1.disableSafeMaxConnectionDuration`
  render `spec.connection.connectionLimit.maxConnectionDuration`,
  `spec.timeout.http.idleTimeout` and `spec.http1.disableSafeMaxConnectionDuration`
  on the Gateway-level ClientTrafficPolicy, next to the claim-header removal
  list, so one policy carries both. Capping the connection age makes a client
  that holds keep-alive connections (cloudflared) reconnect within the cap
  after a ListenerSet move, whatever order it was synced in; HTTP/2 streams are
  cut at the cap. Each key is omitted when unset, so an existing render is
  byte-identical. Test case `gateway-fleet/connection-lifetime` and three
  negative fixtures.

## v1.8.0

- **`gateway-groups`: `groups.<name>.routes`.** The HTTPRoutes the platform
  owns on a group's ListenerSet, parented to it, with the group's
  hostnames as the default and the only allowed values (a hostname the group
  does not serve fails the render instead of attaching to no listener).
  Rules are named, matched verbatim (path, method, query parameters),
  and send to `backend`/`backends` or carry filters; the API server's
  defaults (backend group, kind, weight) are written out. An annotation on a
  route overrides `commonAnnotations`, so a route can take a sync wave of
  its own. Empty by default: an existing render is byte-identical. Standard
  Gateway API only; a policy attached to a route stays with the fleet side.
  Test case `gateway-groups/routes` and ten negative fixtures.

## v1.7.0

- **Security hardening: `gateway-fleet` `clientTraffic.earlyRequestHeaders.remove`.**
  A header the gateway sets from verified token claims
  (`claimToHeaders`, for example `x-auth-request-email`) is added to the
  request, not written over a copy the client sent, so a client could supply
  the header ahead of time and a backend reading the first value would see
  the client's. The new list, empty by default (an existing render is
  byte-identical), renders `spec.headers.earlyRequestHeaders.remove` on every
  ClientTrafficPolicy the chart renders, which removes those headers before
  any HTTP filter runs. **Set it to every header named in a `claimToHeaders`.**
  It needs `clientTrafficPolicy.enabled: true` on every enabled exposure (the
  render fails otherwise) and refuses pseudo-headers, non-lowercase names,
  duplicates and headers whose removal would break traffic (`host`,
  `content-length`, `transfer-encoding`, `cookie`, `authorization`, ...).
- Docs: `claimToHeaders` ADDS the header; the earlier wording said it
  overwrote the client's copy, which was wrong. `gateway-policies` values and
  docs now state the pairing rule.
- **`gateway-fleet`: `clientTrafficPolicy.tls.enabled`** (default `true`,
  every existing render is byte-identical). `false` renders no `tls` block,
  so an exposure can carry a ClientTrafficPolicy holding only the header
  removal without gaining a TLS floor. Refused together with
  `tls.clientValidation.enabled`, and refused when the remove list is empty.
- Test cases `gateway-fleet/early-request-headers` and
  `gateway-fleet/early-request-headers-no-tls`, and eleven negative fixtures.

## v1.6.0

- **`gateway-fleet`: `metrics.podMonitor`**, off by default (an existing
  render is byte-identical). With `enabled: true` the chart renders a
  PodMonitor for the proxies (`/stats/prometheus`, one per namespace that
  holds a proxy) and one for the Envoy Gateway controller (`/metrics`;
  `controller.enabled: false` drops it). The proxy scrape keeps only the
  families Envoy Gateway's own dashboards read (`proxy.keep`; `[]` keeps
  everything; setting it replaces the list), then any `proxy.metricRelabelings`
  of your own. `interval` and `labels` apply to every monitor. Every relabel
  rule writes `action`, and a rule of yours without one is refused.
- **`gateway-fleet`: `metrics.networkPolicy.from`**. The peers named there
  get one ingress row, last, on every exposure NetworkPolicy, for the
  proxies' stats port (`metrics.networkPolicy.port`, 19001). Empty renders
  no row.
- Test cases `gateway-fleet/metrics` and `gateway-fleet/metrics-keep-all`,
  and two negative fixtures.

## v1.5.3

Dependency and CI-pin bumps only — nothing a consumer's render moves for.
See the GitHub Release for the commit list.

## v1.5.2

Dependency and CI-pin bumps only — nothing a consumer's render moves for.
See the GitHub Release for the commit list.

## v1.5.1

`oidc.backendSettings` could be stated, Accepted and still not reach the
proxy. This is the other half of it.

- **`gateway-policies`: `backendSettings` on `remoteJWKS`**, both
  `oidc.idToken.remoteJWKS` and `jwt.remoteJWKS`, in the same pass-through
  form and with the same closed block names as `oidc.backendSettings`.
- **Why it is needed.** Envoy Gateway derives an upstream cluster from
  each URL the gateway must call and names it after the **host and port**
  alone. An issuer that serves its keys from the host it serves tokens
  from — the ordinary arrangement — therefore collapses both onto one
  cluster, and the translator keeps the first built and returns early for
  the second, on the assumption that one name means one set of settings.
  The losing side's settings are dropped with nothing reported: the policy
  is `Accepted`, the rendered YAML still shows the block, and the cluster
  carries none of it. The filter-scoped parts (`retry`, `timeout`) survive
  either way, because they live in the OIDC filter rather than the
  cluster; `tcpKeepalive` and the other cluster-scoped blocks do not.
  Stating the same settings on both sides makes the order stop mattering.
  Giving the JWKS side `backendRefs` also separates them, since a cluster
  built from a backend reference is named for that backend.
- New test case `gateway-policies/jwks-backend-settings` (one host shared
  by the token endpoint and the key set, settings on both sides via a YAML
  anchor, plus a machine route whose keys come from a Service) and a
  negative fixture for a misspelt block name under `remoteJWKS`.
- Every existing values file renders byte-for-byte as in 1.5.0.
  See [docs/safety.md](docs/safety.md#and-stating-it-in-one-place-may-not-be-enough).

## v1.5.0

The gateway calls the issuer itself, and nothing said how it should hold
that connection open.

- **`gateway-policies`: `oidc.backendSettings`**, on `defaults` and on
  every entry, passed through verbatim to the SecurityPolicy's
  `oidc.provider.backendSettings` — Envoy Gateway's own `BackendSettings`
  (`circuitBreaker`, `connection`, `dns`, `healthCheck`, `http2`,
  `loadBalancer`, `proxyProtocol`, `retry`, `tcpKeepalive`, `timeout`).
  This is how the gateway **reaches** the issuer, as against what it asks
  for, and it matters most when the issuer is across a NAT or a stateful
  firewall: such a device forgets an idle TCP flow after its own timeout
  and usually forgets it *silently*, so a pooled connection stays in the
  pool looking healthy and the next sign-in or token refresh written to it
  hangs until a timeout — an intermittent failure whose only symptom is
  people bounced back to sign-in, with no connect failure anywhere.
  `tcpKeepalive` keeps the flow from going idle that long, `retry` spends
  an attempt rather than a session on one that was dropped anyway. The
  values are the estate's: the chart names no number and renders nothing
  until asked. A block name that is not one of the ten is refused at
  render, because the API server would prune it and Accept the rest.
  See [docs/reference.md](docs/reference.md#oidc--browser-sign-in) and
  [docs/safety.md](docs/safety.md#an-idle-connection-to-the-issuer-can-be-dead-without-saying-so).
- New test case `gateway-policies/oidc-backend-settings` (shared block,
  one entry merging over it key by key, and a `jwt` entry that gets
  neither) and a negative fixture for the misspelt block name.
- Every existing values file renders byte-for-byte as in 1.4.0.

## v1.4.0

- **New chart: `gateway-routes`, a library chart for the application's
  side.** `{{ include "gateway-routes.productRoute" (dict "root" $ "route" .Values.route) }}`
  renders one HTTPRoute whose rules are **named**: `app`, the gated
  surface (the shell, the API, everything a more specific rule does not
  claim), and `static`, the public one, rendered only when given path
  prefixes. Further anonymous rules — a redirect, a well-known document —
  go in `extraRules`. The names are the contract a policy targets; `/` is
  refused on any rule no policy gates, and an unknown input key fails the
  render as `values.schema.json` does for the other charts. See
  [charts/gateway-routes/README.md](charts/gateway-routes/README.md) and
  [docs/reference.md](docs/reference.md#gateway-routes).
- **`gateway-policies`: `securityPolicies.<name>.targetRefs[].sectionName`
  can name a route RULE**, not only a Gateway's listener — the rendered
  target is `{group: gateway.networking.k8s.io, kind: HTTPRoute, name:
  <route>, sectionName: app}`. It was already passed through; it is now
  documented, checked against the section-name shape, and covered by a
  golden case. A section name that matches no rule leaves the policy
  unapplied and the route **serving**, so
  [docs/safety.md](docs/safety.md#gateway-routes) says how to read that.
- `gateway-fleet`, `gateway-groups` and existing `gateway-policies` values
  are unchanged: they render byte-for-byte as in 1.2.0.

## v1.3.0

The charts assumed a cloud and a certificate on a curve Envoy already
prefers. Neither assumption is in the design; both were in the
documentation and, for one of them, in a missing value.

- **`gateway-policies`: `tls.ecdhCurves`**, on the baseline and on every
  stricter policy. Envoy's own list is `X25519:P-256`, and under TLS 1.2
  the server's signature is made on a group from that list — so an estate
  whose certificates are **P-384 cannot complete a 1.2 handshake at all**,
  while every 1.3 client works and nothing in the objects says why.
  Raising `minVersion` does not help; the cipher list does not either.
  `[]` keeps Envoy's default, so existing installs render as before. A
  name Envoy does not know is refused at render: it is not a weaker floor,
  it is a policy the proxy rejects whole, which stops the floor applying.
- **`docs/adoption.md`: one operator, one cluster, no cloud.** The
  bare-metal shape written down — a public exposure on a plain ClusterIP
  because the tunnel dials outward, and a private one published by the
  cluster's own IPAM controller, which takes its address from
  `proxy.service.annotations` rather than a `loadBalancerClass`. The
  annotations path already worked; nothing said so.
- **`docs/adoption.md`: from one Gateway per service.** The shape every
  0.x consumer has, converted without a hostname going dark: the mapping,
  the order, the explicit check for "dark" (a route attached to nothing is
  an error nowhere), and the one-deployment rule where a pruning
  controller owns the objects.
- Test cases for both: `gateway-fleet/bare-metal` and
  `gateway-policies/p384-floor`, plus two negative fixtures for a curve
  name that is not one.

## v1.2.0

- **New chart: `gateway-policies`.** The Envoy Gateway policies that
  protect what the other two charts expose, from generic values:
  - `tlsBaseline`: one ClientTrafficPolicy per namespace selecting every
    Gateway without the `tls-baseline-exempt` label. **On by default**,
    so a new install of this chart renders it: TLS 1.2 or later and the
    six ECDHE AEAD cipher suites in the release namespace.
  - `tlsPolicies`: stricter TLS on named Gateways or listeners.
  - `securityPolicies`: an OIDC or JWT SecurityPolicy per protected route
    or listener, with an `authenticated` or `groups` posture and CSRF
    `off`, `shadow` or `enforce`. CSRF defaults to `shadow` on OIDC and is
    refused on JWT. Nothing is rendered until given an issuer.
  - `backendTLSPolicies`: verify a private-chain backend.
  See [docs/reference.md](docs/reference.md#gateway-policies) and
  [docs/adoption.md](docs/adoption.md#the-zero-diff-gate) for moving
  hand-written policies onto it.
- `gateway-fleet` and `gateway-groups` are unchanged: existing installs
  render byte-for-byte as in 1.1.0.

## v1.1.0

- **`proxy.accessLog.extraFields` adds fields to the proxy's JSON access
  log.** The chart renders the controller's default fields as well and
  merges the extra ones over them, because a JSON format replaces the
  default line rather than extending it. With no extra fields nothing is
  rendered and existing installs render byte-for-byte as in 1.0.0.
- The repository and the charts' `home`/`sources` URLs are now
  `truvity/gateway`. OCI chart paths are unchanged.

## v1.0.0

- **Breaking: one chart becomes two.** `envoy-gateway-fleet` is replaced
  by `gateway-fleet` (GatewayClass, EnvoyProxy, one Gateway per exposure
  with its health listener, `allowedListeners`, baseline
  ClientTrafficPolicy and NetworkPolicy) and `gateway-groups` (one
  ListenerSet per project group, a listener and a Certificate per domain,
  optional BackendTLSPolicy and NetworkPolicy). The OCI paths change with
  the names.
- **Breaking: `fleets` is replaced by `classes` and `exposures`.** Named
  listener registrations, `additionalServices` and the infra-health block
  move to `gateway-groups` or to per-exposure values. See
  [docs/adoption.md](docs/adoption.md#0x-envoy-gateway-fleet-to-10).
- A split class (`mergeGateways: false`) gives every exposure its own
  proxy, Service and address.
- From Envoy Gateway 1.9: `shutdown.healthCheckFailureDelay`,
  `backendTLS.clientCertificateRef`, and `clientValidation` on the
  baseline ClientTrafficPolicy.
- Relational mistakes fail the render: duplicate object names, a hostname
  claimed by two groups on one exposure, a per-exposure proxy on a merged
  class, an empty `Selector` grant. Each rule has a negative fixture.

## v0.3.0

- Named listener registrations, additional Services and an infra-health
  contract in `envoy-gateway-fleet`, each validated at render time.
- Listener specificity is preserved: a wildcard cannot overlap a more
  specific listener.

## v0.2.0

- **`values.schema.json`:** an unknown key fails the render.

## v0.1.0

- First release: the `envoy-gateway-fleet` chart.
