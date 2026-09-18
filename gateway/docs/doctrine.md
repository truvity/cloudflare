# Doctrine — the design rules

## Three charts, along the lines that divide them

**gateway-fleet is the vendor half.** GatewayClass and EnvoyProxy are
Envoy Gateway's; the Gateway per exposure, its baseline
ClientTrafficPolicy and the proxy's NetworkPolicy are shaped by it. A
change of gateway implementation rewrites this chart.

**gateway-groups is the standard half.** ListenerSet, cert-manager
Certificate, BackendTLSPolicy and NetworkPolicy — Gateway API and core
Kubernetes only. A change of gateway implementation leaves it alone.

**gateway-policies is what protects them.** The TLS floor, stricter TLS
per listener, sign-in and token validation per route, CSRF, and backend
certificate verification. It is Envoy Gateway's (every object but
BackendTLSPolicy is its CRD), so it is not the standard half; and it is
per route, so it is not the fleet: the fleet owns the ways in, the policies
own who gets through them. Its defaults follow one rule — **safe where
being wrong is silent, off where being wrong is loud**: the TLS floor is on
and CSRF watches in shadow, because their absence is invisible; sign-in and
token checks render nothing until given an issuer, and CSRF is never
enforced by default, because a wrong guess there refuses real traffic.

The controller itself is none of them: it is upstream's `gateway-helm`,
and these charts own what it reconciles.

## Exposures, groups, routes: three owners

An **exposure** is one way in: a public entry point behind a tunnel or a
load balancer, a private one on an internal address, one that asks for a
client certificate. It is a Gateway, and the platform owns it.

A **group** is one project's claim on an exposure: the hostnames it serves
and the namespaces whose routes may attach to them. It is a ListenerSet,
and the platform owns it too — which hostnames exist and who may attach is
exactly the grant.

A **route** is the project's: its HTTPRoutes name a ListenerSet as their
parent. Who may use the route — sign-in, token validation, a groups
allow-list, CSRF — is a `gateway-policies` value, stated by whoever owns
the grant, usually the platform; traffic policy such as rate limits stays
with the route.

The fleet chart therefore never grows a list of the estate's domains, and
adding a project is a group, never an edit to an exposure.

## Ownership contract

| This repository | The consuming estate |
|---|---|
| GatewayClass, EnvoyProxy, Gateway, ListenerSet, Certificate, BackendTLSPolicy, ClientTrafficPolicy, SecurityPolicy, NetworkPolicy — the objects and their relations | which hostnames exist, which namespaces may attach, which issuer signs, which address is pinned, which cloud annotations apply |
| that a policy is never rendered half-configured, and never two on one target | the OIDC issuer, its clients and their Secrets; which routes are protected and for whom; the CA bundles |
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
