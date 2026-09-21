# Changelog

What changed for a consumer, per version, newest first. A version with no
heading here is a patch cut automatically for dependency bumps alone; its
GitHub Release lists them. Every chart is released at every version.

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
