# Changelog

What changed for a consumer, per version, newest first. A version with no
heading here is a patch cut automatically for dependency bumps alone; its
GitHub Release lists them. Both charts are released at every version.

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
