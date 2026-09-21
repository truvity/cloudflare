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

## One operator, one cluster, no cloud

The charts describe a cloud estate by default — an NLB with a class and
source ranges, a tunnel in front of the public way in. Neither is
required. `tests/cases/gateway-fleet/bare-metal` is the whole of a
single-operator install:

- one class, `mergeGateways: false`;
- a **public** exposure whose Service is a plain `ClusterIP`, because the
  tunnel client dials outward and is reached inside the cluster;
- a **private** exposure published by the cluster's own IPAM controller,
  which takes its address from an annotation:

```yaml
    proxy:
      service:
        type: LoadBalancer
        annotations:
          lbipam.cilium.io/ips: 192.0.2.40
```

`proxy.service.annotations` reaches the proxy's Service, which is how any
controller that reads annotations — LB-IPAM, MetalLB, a cloud's own — is
told what to do. There is no `loadBalancerClass` here on purpose: with one
controller in the cluster, naming a class only narrows what can serve it.

Two exposures rather than one is worth the second set of pods even here:
it is what keeps a public-side overload from taking away the operator's
own way in.

## Upgrading

### From one Gateway per service

Consumers of `envoy-gateway-fleet` 0.x, and anyone who started from the
Gateway API's own examples, have **one Gateway and one Certificate per
service**. That shape is what the 1.0 split replaces, and it converts
without any hostname going dark.

The mapping:

| before | after |
|---|---|
| one `Gateway` per service | one **listener** in its project group's `ListenerSet` |
| the Gateway's `tls.certificateRefs` Secret | the group's per-domain `Certificate`, issued by the chart |
| `HTTPRoute.parentRefs` → the service's Gateway | → the group's `ListenerSet` (`kind: ListenerSet`) |
| a policy targeting the service's Gateway | a policy targeting the `ListenerSet`, or the route |

The order that keeps traffic serving:

1. Install `gateway-fleet`: the exposure comes up with only its health
   listener, serving nothing that exists yet. The old Gateways are
   untouched.
2. Install `gateway-groups` with the group's domains. Its ListenerSet and
   Certificates come up **beside** the old Gateways; both now hold a
   certificate for the same hostname, which is allowed — nothing routes to
   the new one yet.
3. Wait for every new Certificate to be `Ready`. A `parentRef` moved to a
   listener with no certificate is a hostname that goes dark.
4. Move each `HTTPRoute`'s `parentRef`, one route at a time. Traffic for
   that hostname moves with it.
5. Delete the old Gateway and its Certificate only after its routes have
   moved and been checked.

**Check for "dark" explicitly at each step.** A route that attaches to
nothing is not an error anywhere — the Gateway is Ready, the route exists,
and the hostname simply stops answering. Before and after each move:

```sh
curl -sS -o /dev/null -w '%{http_code} %{ssl_verify_result}\n' \
  --resolve "$host:443:$address" "https://$host/"
```

A changed code, or a verify result that stops being `0`, is the move to
revert — the `parentRef` is one field, so reverting is one edit.

If a pruning controller owns these objects, do step 4 for all routes in
**one** deployment: a controller that sees the old Gateway removed and the
new parentRef in separate syncs can delete the old listener while routes
still point at it.

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
