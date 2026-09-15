# envoy-gateway-fleet

Envoy Gateway for Kubernetes estates, as reusable mechanism: the plane the
controller manages, split into the half that is vendor-specific and the half
that is not.

| Artifact | What | Status |
|---|---|---|
| `charts/gateway-fleet` | GatewayClass and EnvoyProxy per class; one Gateway per exposure, with its health listener, its `allowedListeners` rule, its baseline ClientTrafficPolicy and its NetworkPolicy | shipped |
| `charts/gateway-groups` | One ListenerSet per project group, a listener and a Certificate per domain, an optional BackendTLSPolicy and the ingress rule that lets the gateway reach the group's workloads | shipped |

Charts publish to `oci://ghcr.io/truvity/charts/<chart>` on every tag.

The Envoy Gateway **controller** is not here: install it from upstream's
`gateway-helm`. These charts own what it reconciles.

## The rule that makes this repository public

**Mechanism only.** Nothing here names an account, a zone, a hostname, a
cluster, an issuer or a secret path. Every such thing is an input with a
neutral default, and the consuming estate supplies it from its own (private)
repository. `hack/leak-canary.sh` enforces this in CI, and public history
cannot be unpublished — so the rule is mechanical, not remembered.

## How the two charts fit together

An **exposure** is one way in: a public entry point behind a tunnel or a load
balancer, a private one on an internal address, later one that asks for a
client certificate. It is a Gateway, and the platform owns it.

A **group** is one project's claim on an exposure: the hostnames it serves and
the namespaces whose routes may attach to them. It is a ListenerSet, and the
platform owns it too — which hostnames exist and who may attach is exactly the
grant. The project owns only its HTTPRoutes, which name a ListenerSet as their
parent.

```
gateway-fleet                       gateway-groups              the project
─────────────                       ──────────────              ───────────
GatewayClass  ── parametersRef ──►  EnvoyProxy
  │
  └─ Gateway "public"  ◄── parentRef ── ListenerSet "argocd"  ◄── HTTPRoute
       health listener                    listener + Certificate    (argocd ns)
       allowedListeners                   per domain
       ClientTrafficPolicy                optional BackendTLSPolicy
       NetworkPolicy
```

Two consequences worth stating, because both are load-bearing:

- **The exposure's listener is a health endpoint, not a route.** A Gateway
  with no listener has no proxies, so without it an exposure would be dark
  until the first group attached — and would go dark again when the last one
  left.
- **`allowedListeners` is the wall.** Its default admits only the exposure's
  own namespace, so a project cannot open a listener by creating an object in
  a namespace it controls.

## charts/gateway-fleet

```sh
helm install fleet oci://ghcr.io/truvity/charts/gateway-fleet \
  --namespace envoy-gateway-system \
  --values fleet-values.yaml
```

```yaml
classes:
  internal:
    # false: every Gateway of this class gets its own Deployment and
    # Service, so one exposure can carry a pinned address or a load
    # balancer without the others. true: they collapse onto one of each.
    mergeGateways: false

exposures:
  public:
    class: internal
    health:
      hostname: gateway-health.example.com
      certificate:
        issuerRef: { name: example-ca, kind: ClusterIssuer, group: cert-manager.io }
    proxy:
      service: { name: gateway-public }

  private:
    class: internal
    health:
      hostname: gateway-health.internal.example
      certificate:
        issuerRef: { name: example-private-ca, kind: ClusterIssuer, group: cert-manager.io }
    proxy:
      service:
        name: gateway-private
        type: LoadBalancer
        clusterIP: 10.0.0.60                 # a stable address inside the cluster
        loadBalancerClass: example.com/network-load-balancer
        loadBalancerSourceRanges: [10.0.0.0/14]
      shutdown:
        healthCheckFailureDelay: 5s          # drain before the balancer notices
```

| Value | Default | Notes |
|---|---|---|
| `controllerName` | `gateway.envoyproxy.io/gatewayclass-controller` | as installed by `gateway-helm` |
| `classes.<n>.mergeGateways` | `false` | `true` shares one proxy across every Gateway of the class; no exposure may then bring its own |
| `classes.<n>.proxy.enabled` | follows `mergeGateways` | a merged class needs its class proxy; a split one does not, because each exposure brings its own |
| `exposures.<n>.class` | *required* | must name an enabled class |
| `exposures.<n>.health.hostname` | *required* | exact, never a wildcard: a wildcard here would shadow every group |
| `exposures.<n>.health.certificate.issuerRef.name` | *required* when the listener is HTTPS | the issuer is the estate's |
| `exposures.<n>.health.directResponse.enabled` | `false` | answers without a backend, so the exposure can be probed when everything behind it is down |
| `exposures.<n>.allowedListeners.namespaces.from` | `Same` | `None`, `Same`, `All` or `Selector` |
| `exposures.<n>.proxy.service.clusterIP` | `""` | a pinned address; reaches the Service through the controller's patch hook |
| `exposures.<n>.proxy.shutdown.healthCheckFailureDelay` | `""` | fail readiness this long before draining, so a load balancer removes the endpoint first |
| `exposures.<n>.proxy.backendTLS.clientCertificateRef` | unset | the certificate Envoy presents to a backend that asks for one |
| `exposures.<n>.clientTrafficPolicy.tls.clientValidation` | disabled | turns an exposure into one only a certificate holder can reach |
| `exposures.<n>.networkPolicy` | disabled | rules are the estate's; only the xDS egress is structural, because without it the proxies never get a configuration |

Cloud annotations, load-balancer classes, source ranges, issuers, addresses
and scheduling are all inputs: only the estate knows those.

## charts/gateway-groups

```sh
helm install groups oci://ghcr.io/truvity/charts/gateway-groups \
  --namespace envoy-gateway-system \
  --values groups-values.yaml
```

```yaml
defaults:
  parent: { name: public }
  certificate:
    issuerRef: { name: example-ca, kind: ClusterIssuer, group: cert-manager.io }

groups:
  argocd:
    domains:
      - argocd.example.com
      # A rename in flight: the old host is a second domain of the same
      # group until the soak is over. Delete the entry and its listener,
      # Certificate and Secret go with it.
      - host: argocd.old.example.com
        listenerName: legacy
        secretName: argocd-legacy-tls
    allowedRoutes:
      namespaces:
        from: Selector
        selector:
          matchLabels:
            gateway.example.com/route-grant-argocd: "true"
```

| Value | Default | Notes |
|---|---|---|
| `defaults` | see `values.yaml` | merged under every group, so a shared issuer or exposure is stated once |
| `groups.<n>.parent.name` | *required* | the exposure's Gateway |
| `groups.<n>.domains` | *required*, non-empty | a string, or an object giving one domain its own listener, Secret or issuer |
| `groups.<n>.allowedRoutes.namespaces` | `from: Same` | a selector naming a label the platform writes is how a grant is expressed |
| `groups.<n>.certificate.issuerRef.name` | *required* when HTTPS | per group or once in `defaults` |
| `groups.<n>.backendTLS` | disabled | re-encrypt to the backend; `validation` is mandatory when enabled, because TLS that is never verified is not re-encryption |
| `groups.<n>.networkPolicy` | disabled | the other half of the grant: the namespace label lets the route attach, this lets the packet arrive |

One Certificate per domain, never one with every domain as a SAN: a group's
domains are renamed and retired one at a time, and a SAN list cannot be.

Hostnames are checked for uniqueness across the whole release, per exposure
and port — two groups claiming one host is a listener conflict that takes
both of them down, and it is not otherwise visible until it is live.

## Ownership contract

| This repository | The consuming estate |
|---|---|
| GatewayClass, EnvoyProxy, Gateway, ListenerSet, Certificate, BackendTLSPolicy, ClientTrafficPolicy, NetworkPolicy — the objects and their relations | which hostnames exist, which namespaces may attach, which issuer signs, which address is pinned, which cloud annotations apply |
| that two objects never silently share a name, a hostname or a Secret | DNS, tunnels, load balancers, trust distribution |
| the defaults that make a partial values file render something coherent | the values themselves |

Project charts own their HTTPRoutes and their backends; route-level policy
(authentication, authorization, rate limits) belongs with the route, not here.

## Development

```sh
devbox shell        # or direnv
just check          # lint + golden renders + leak canary
just golden         # regenerate tests/golden after a template change — review the diff
```

`tests/invalid/<chart>/` holds one fixture per validation rule. Each must
fail to render; `just lint` proves it. A rule without a fixture is a rule
that will quietly stop working.

## Releasing

Push a tag `vX.Y.Z`. The shared release workflow creates the GitHub Release
and pushes every chart at that version — a chart's own `version` field is a
placeholder that never moves.

## Licence

MIT — see [LICENSE](LICENSE).
