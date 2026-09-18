# Adoption

## Prerequisites

- Kubernetes with the Gateway API CRDs, including ListenerSet (Gateway
  API 1.5 or later).
- Envoy Gateway 1.9 or later, installed from upstream's `gateway-helm`.
  ListenerSet as a policy target and the proxy shutdown and backend
  client-certificate fields need it.
- cert-manager, and an issuer the estate owns.

## Install order

1. The controller, from `gateway-helm`.
2. `gateway-fleet`: the classes and the exposures. Each exposure comes up
   serving only its health listener.
3. `gateway-groups`: one group per project claim. Pin **both charts at the
   same version** — one tag releases both, and a lag between them is a
   version nobody tested together.
4. The projects' HTTPRoutes, each naming its group's ListenerSet as
   parent.

## The zero-diff gate

Adopt a release only when your render is byte-identical to what runs, or
differs by exactly the change the release announces in
[CHANGELOG.md](../CHANGELOG.md). Render both charts with your values at
the pinned version and at the new one and compare; a diff you cannot
explain from the CHANGELOG is a reason to stop.

The same gate applies when moving from hand-written objects to the
charts: set `gatewayName`, `listenerSetName`, Secret and Certificate names
so the render reproduces the live objects' names exactly, and make the
switch one change whose render diff is empty. A changed name is a delete
and a create, and for a Gateway that is an outage.

## Upgrading

### 0.x (`envoy-gateway-fleet`) to 1.0

1.0 split the single chart into `gateway-fleet` and `gateway-groups` and
changed the values shape. Breaking:

- the chart `envoy-gateway-fleet` is replaced by `gateway-fleet` and
  `gateway-groups`, at new OCI paths;
- `fleets` is replaced by `classes` and `exposures`;
- named listener registrations, `additionalServices` and the infra-health
  block move to `gateway-groups` or to per-exposure values.

Move in one change, keeping object names, so the render diff contains only
the objects that genuinely change shape; see the gate above.
