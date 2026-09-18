# Doctrine — the design rules

## Two charts, along the line that divides them

**gateway-fleet is the vendor half.** GatewayClass and EnvoyProxy are
Envoy Gateway's; the Gateway per exposure, its baseline
ClientTrafficPolicy and the proxy's NetworkPolicy are shaped by it. A
change of gateway implementation rewrites this chart.

**gateway-groups is the standard half.** ListenerSet, cert-manager
Certificate, BackendTLSPolicy and NetworkPolicy — Gateway API and core
Kubernetes only. A change of gateway implementation leaves it alone.

The controller itself is neither: it is upstream's `gateway-helm`, and
these charts own what it reconciles.

## Exposures, groups, routes: three owners

An **exposure** is one way in: a public entry point behind a tunnel or a
load balancer, a private one on an internal address, one that asks for a
client certificate. It is a Gateway, and the platform owns it.

A **group** is one project's claim on an exposure: the hostnames it serves
and the namespaces whose routes may attach to them. It is a ListenerSet,
and the platform owns it too — which hostnames exist and who may attach is
exactly the grant.

A **route** is the project's: its HTTPRoutes name a ListenerSet as their
parent. Route-level policy (authentication, authorization, rate limits)
belongs with the route, not here.

The fleet chart therefore never grows a list of the estate's domains, and
adding a project is a group, never an edit to an exposure.

## Ownership contract

| This repository | The consuming estate |
|---|---|
| GatewayClass, EnvoyProxy, Gateway, ListenerSet, Certificate, BackendTLSPolicy, ClientTrafficPolicy, NetworkPolicy — the objects and their relations | which hostnames exist, which namespaces may attach, which issuer signs, which address is pinned, which cloud annotations apply |
| that two objects never silently share a name, a hostname or a Secret | DNS, tunnels, load balancers, trust distribution |
| the defaults that make a partial values file render something coherent | the values themselves |

## Rules a change must keep

- **Relational mistakes fail the render.** A new rule comes with its
  fixture in `tests/invalid/<chart>/`.
- **The issuer, the addresses and the cloud are inputs.** A default that
  names one is a leak; a default that picks one is a decision the estate
  did not make.
- **A new capability renders nothing until asked for.** An existing
  values file renders byte-for-byte the same after an upgrade unless the
  release says otherwise (see [adoption.md](adoption.md)).
