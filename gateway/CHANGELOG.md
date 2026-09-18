# Changelog

What changed for a consumer, per version, newest first. A version with no
heading here is a patch cut automatically for dependency bumps alone; its
GitHub Release lists them. Every chart is released at every version.

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
