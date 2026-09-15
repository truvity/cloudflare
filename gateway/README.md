# envoy-gateway-fleet

The fleet half of an [Envoy Gateway](https://gateway.envoyproxy.io) install.
For each audience, this Helm chart declares one **GatewayClass + EnvoyProxy**
with `mergeGateways` enabled, optional central Gateways/listeners and
Certificates, listener-scoped ClientTrafficPolicies, fleet NetworkPolicy,
additional exposure Services, and optional infra direct-response health.
Upstream's `gateway-helm` chart installs the controller.

Published to `oci://ghcr.io/truvity/charts/envoy-gateway-fleet` on every tag.

## The model

```text
                         ┌─ GatewayClass internal ──▶ EnvoyProxy internal-config ──▶ ONE Deployment
 tunnel / LB ──▶ ........┤                                                       ├─ Service gateway-internal
                         └─ central/additional exposure Services ────────────────┘

 central or project Gateway (gatewayClassName: internal) ─┐
 project HTTPRoute/GRPCRoute (parentRef → Gateway) ────────┴─ merged into the class fleet
```

- **One controller, N classes, one fleet per class.** `mergeGateways: true`
  collapses every Gateway naming a class into one Envoy Deployment. The
  controller creates its stable primary Service.
- **Audience is structural.** Internal and customer traffic can use separate
  classes, policies, and exposure while sharing the same chart contract.
- **Central listeners are additive.** Projects may continue to own complete
  Gateway/Route stacks. Named registrations exist for centrally managed
  entrypoints without changing the fleet join key.
- **Compatibility is retained.** The original `healthListener`, including its
  permissive legacy Secret name behavior, remains supported.

## Ownership contract

| Owner | Resources / responsibility |
| --- | --- |
| This chart | GatewayClass, EnvoyProxy, central Gateways/listeners, cert-manager Certificates, listener ClientTrafficPolicies, fleet NetworkPolicies, additional exposure Services, and enabled infra health HTTPRouteFilter/HTTPRoute resources |
| GitOps | Chart values; issuer, trust, and approval resources; DNS and Cloudflare/provider configuration; cloud-specific Service annotations and `loadBalancerClass` values |
| Project charts | Business Routes, Services/backends, and backend policies |

The chart never embeds AWS, Cloudflare, account, DNS-zone, issuer, or trust
particulars. Additional Services are generic Kubernetes Services: the chart
owns their immutable fleet selector, while values supply exposure details.

## Usage

```yaml
commonAnnotations:
  argocd.argoproj.io/sync-wave: "65"
fleets:
  internal:
    envoyProxy:
      pod:
        tolerations: [{key: arch, operator: Exists}]
    healthListener:
      enabled: true
      hostname: gateway-health.internal.example.com
    networkPolicy:
      enabled: true
      ingress:
        - from:
            - namespaceSelector:
                matchLabels: {kubernetes.io/metadata.name: edge-system}
              podSelector:
                matchLabels: {app.kubernetes.io/name: edge-tunnel}
          ports: [{port: 10443, protocol: TCP}]
  customer:
    envoyProxy:
      enabled: false
```

```sh
helm install fleets oci://ghcr.io/truvity/charts/envoy-gateway-fleet --version <tag> -f values.yaml
```

Every field and default is documented in
[`charts/envoy-gateway-fleet/values.yaml`](charts/envoy-gateway-fleet/values.yaml).

### Compatibility health listener

A merged fleet with zero listeners has zero proxies. `healthListener` is the
original bootstrap Gateway that keeps the fleet alive before the first project
Gateway and after the last one leaves. Its input API and existing exact-hostname
behavior are preserved. Prefer a specific hostname: a compatibility wildcard
can overlap other fleet listeners.

### Named central listeners

`fleets.<class>.listeners` is keyed by a stable registration name. Gateway name
defaults to `<fleet>-<registration>`. Each registration renders one Gateway and
may render its Certificate, listener-scoped ClientTrafficPolicy, and infra
health direct response.

Exact hostnames are the safe default. A wildcard is accepted only as one
leading `*.` with `allowWildcard: true`, and it must include a specific DNS
suffix (for example `*.apps.example.com`, not `*.com`). The chart rejects
malformed DNS names and duplicate `(fleet, port, protocol, hostname)` claims.
Gateway API specificity remains available: exact hosts win over wildcards, and
nested wildcards with more labels win over broader wildcards.

```yaml
fleets:
  internal:
    listeners:
      private-entrypoint:
        namespace: application-gateway
        hostname: gateway.internal.example.com
        certificate:
          issuerRef:
            name: application-server
            kind: Issuer
            group: cert-manager.io
        allowedRoutes:
          namespaces:
            from: Selector
            selector:
              matchLabels:
                tenancy.example.com/audience: internal
                tenancy.example.com/state: active
              matchExpressions:
                - key: tenancy.example.com/tier
                  operator: In
                  values: [application, platform]
                - key: tenancy.example.com/suspended
                  operator: DoesNotExist
          kinds:
            - group: gateway.networking.k8s.io
              kind: HTTPRoute
            - group: gateway.networking.k8s.io
              kind: GRPCRoute
        clientTrafficPolicy:
          enabled: true
          tls: {minVersion: "1.3", maxVersion: "1.3"}
```

`allowedRoutes` is strict. `namespaces.from` supports `Same`, `All`, and
`Selector`; selectors support multiple `matchLabels` and Kubernetes
`matchExpressions`. Route kinds always render explicitly and default to
`gateway.networking.k8s.io/HTTPRoute`. The chart rejects known incompatible
TCP/TLS/UDP route kinds on HTTP/HTTPS listeners. It cannot validate live
Namespace labels, so GitOps must ensure a Selector admits intended namespaces.

Registration keys and explicit namespace, Gateway, Secret, policy, health
route/filter names are live Kubernetes identities. Change them only with an
adoption plan. A namespaced Issuer must already exist in the listener namespace
before enabling its Certificate.

### Additional exposure Services

`fleets.<class>.additionalServices` renders generic Services selecting the same
fleet pods as the controller-created primary Service. Values provide the name,
type, `loadBalancerClass`, annotations, labels, source ranges, ports, and
standard Service traffic/IP/session options; every port requires an explicit
`targetPort` because Envoy container ports need not equal public Service ports.
The pod selector is chart-owned
and cannot drift. The safe default type is `ClusterIP`; external exposure must
be selected explicitly.

```yaml
fleets:
  internal:
    additionalServices:
      private-network-load-balancer:
        type: LoadBalancer
        loadBalancerClass: example.com/network-load-balancer
        annotations:
          example.com/exposure: private
        loadBalancerSourceRanges: [192.0.2.0/24]
        externalTrafficPolicy: Local
        ports:
          - {name: https, port: 443, protocol: TCP, targetPort: 10443}
```

GitOps supplies real provider classes and annotations. The chart rejects a
Service name colliding with another chart-owned exposure or a fleet's primary
controller-created Service.

### Optional infra health direct response

A named listener can enable `infraHealth`. The chart creates an Envoy Gateway
`HTTPRouteFilter` with an inline direct response and a same-namespace HTTPRoute
attached to that exact Gateway listener through `sectionName`. Path matching is
`Exact`; status, content type, and body are explicit. Business routes remain
outside this chart.

```yaml
fleets:
  internal:
    listeners:
      status:
        protocol: HTTP
        port: 8080
        hostname: status.internal.example.com
        certificate: {enabled: false}
        infraHealth:
          enabled: true
          path: /ready
          statusCode: 200
          contentType: application/json
          body: '{"status":"ok"}'
```

Route and filter names default stably to `<gateway>-health` (deterministically
truncated to 63 characters) and may be overridden for adoption. Enabling infra
health requires `HTTPRoute` in `allowedRoutes.kinds`, `namespaces.from` set to
`Same` so only the chart-controlled listener namespace may attach the
chart-owned route, and the Envoy
Gateway `HTTPRouteFilter` CRD installed by the controller release.

### NetworkPolicy

Ingress and estate-specific egress remain verbatim Kubernetes NetworkPolicy
rules. The chart adds only structural xDS egress to the controller. This keeps
backend and estate policy in values without inventing a second policy language.

## Development

```sh
devbox shell
just check          # lint + strict negatives + golden renders + leak canary
just golden         # regenerate goldens after a reviewed template change
just package        # validate a local chart archive
```

Every `tests/cases/envoy-gateway-fleet/<case>/values.yaml` is rendered and
compared byte-for-byte with its golden. `tests/invalid` contains schema and
semantic rejection cases.

## Releasing

Push a tag `vX.Y.Z`. The shared release workflow stamps the tag version, creates
the GitHub Release, and publishes the OCI chart. GitOps adoption should wait for
that immutable chart release.

## Licence

MIT — see [LICENSE](LICENSE).
