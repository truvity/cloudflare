# Adoption

## Prerequisites

- Kubernetes with the Gateway API CRDs, including ListenerSet (Gateway
  API 1.5 or later).
- Envoy Gateway 1.9 or later, installed from upstream's `gateway-helm`.
  ListenerSet as a policy target and the proxy shutdown and backend
  client-certificate fields need it.
- cert-manager, and an issuer the estate owns.
- For `gateway-policies`: Envoy Gateway 1.9 (the chart is written against
  the 1.9.1 CRDs — the SecurityPolicy `csrf` block, OIDC `cookieConfig` and
  `endSessionEndpoint` are recent), Gateway API with `BackendTLSPolicy` v1,
  and, for sign-in, an OIDC issuer with a client per protected application
  and its secret delivered as a Secret (key `client-secret`) in the
  application's namespace.

## Install order

1. The controller, from `gateway-helm`.
2. `gateway-fleet`: the classes and the exposures. Each exposure comes up
   serving only its health listener.
3. `gateway-groups`: one group per project claim.
4. `gateway-policies`: the TLS floor first (it is on by default), then one
   SecurityPolicy per protected route. Pin **every chart at the same
   version** — one tag releases them all, and a lag between them is a
   version nobody tested together.
5. The projects' HTTPRoutes, each naming its group's ListenerSet as
   parent. A SecurityPolicy may exist before its route; it attaches when
   the route appears.

## The zero-diff gate

Adopt a release only when your render is byte-identical to what runs, or
differs by exactly the change the release announces in
[CHANGELOG.md](../CHANGELOG.md). Render the charts with your values at
the pinned version and at the new one and compare; a diff you cannot
explain from the CHANGELOG is a reason to stop.

The same gate applies when moving from hand-written objects to the
charts: set `gatewayName`, `listenerSetName`, Secret and Certificate names
so the render reproduces the live objects' names exactly, and make the
switch one change whose render diff is empty. A changed name is a delete
and a create, and for a Gateway that is an outage.

For `gateway-policies` the names are the policy names (`tlsBaseline.name`,
each entry's `name` or map key), and the values must state what the
hand-written objects state: set `tlsBaseline.tls.ciphers: []` if the live
floor has no cipher list, `cookieSameSite: ""` if it sets no `SameSite`,
`csrf.mode: "off"` where it has no CSRF block. Compare the rendered
objects as data, not text; hand-written templates carry comments and a
key order the chart does not reproduce. Render each policy from the same
GitOps application that owned the hand-written object, so the switch is
an in-place update and never a prune followed by a create — for a
SecurityPolicy, the window between the two is a route without sign-in.

Tightening a default — a TLS 1.3 floor, CSRF from `shadow` to `enforce` —
is a separate change after the switch, adopted on its own evidence.

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
