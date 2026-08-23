# envoy-gateway-fleet

The "fleet" half of an [Envoy Gateway](https://gateway.envoyproxy.io)
install, as a Helm chart: per-audience **GatewayClass + EnvoyProxy** with
`mergeGateways` on, an optional **health listener** (with its cert-manager
Certificate), and the fleet's **NetworkPolicy**. Upstream's `gateway-helm`
chart installs the controller; this chart declares what the controller
turns into running proxies.

Published to `oci://ghcr.io/truvity/charts/envoy-gateway-fleet` on every tag.

## The model

```
                         ┌─ GatewayClass internal ──▶ EnvoyProxy internal-config ──▶ ONE Deployment, Service gateway-internal
 tunnel / LB ──▶ ........┤
                         └─ GatewayClass customer ──▶ (EnvoyProxy customer-config) ─▶ ONE Deployment, Service gateway-customer

 per-service Gateway (gatewayClassName: internal, its own listener/hostname/TLS) ─┐
 per-service HTTPRoute (parentRef → that Gateway) ────────────────────────────────┴─ merged into the class's fleet
```

- **One controller, N classes, one fleet per class.** `mergeGateways: true`
  collapses every Gateway that names the class into a single Envoy
  Deployment behind a single, stable Service. Whatever fronts the cluster
  targets that Service and never changes as services come and go.
- **Audience is structural.** Employees and end users get different
  classes — different fleets, different NetworkPolicies, different
  authentication at the edge — and a service may attach to either or both.
- **Per-service Gateways are not here.** They belong with the service that
  owns them: its listener, its hostname, its certificate, its route. This
  chart is the audience-level contract only.

## Usage

```yaml
# values.yaml
commonAnnotations:
  argocd.argoproj.io/sync-wave: "65"   # optional: whatever your GitOps tool needs
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
            - namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: cloudflare-system}}
              podSelector: {matchLabels: {app.kubernetes.io/name: cloudflared}}
          ports: [{port: 10443, protocol: TCP}]
      egress:
        - to: [{namespaceSelector: {matchLabels: {tenancy.example.com/tenant: "true"}}}]
  customer:
    envoyProxy:
      enabled: false   # class declared, fleet later
```

```sh
helm install fleets oci://ghcr.io/truvity/charts/envoy-gateway-fleet --version <tag> -f values.yaml
```

Every field and its default is documented in
[`charts/envoy-gateway-fleet/values.yaml`](charts/envoy-gateway-fleet/values.yaml).
The shape in one paragraph: `fleets.<class>` has a `namespace` (the
controller's, normally), a `gatewayClass`, an `envoyProxy` (service name
and type, replicas, PDB, pod scheduling, `filterOrder`, and `extraSpec`
deep-merged last for anything not modelled), a `healthListener` and a
`networkPolicy`.

### Why a health listener

A merged fleet with zero listeners has zero proxies — Envoy Gateway
provisions the Deployment from the Gateways it merges. The health Gateway
is a catch-all listener so the fleet exists before the first per-service
Gateway arrives, and stays up after the last one leaves. Give it a
**specific** hostname: a wildcard here conflicts with any wildcard listener
a per-service Gateway brings (`HostnameConflict`, and that listener never
programs).

### Why raw NetworkPolicy rules

The fleet's policy is the one place where "who may reach the proxies"
(your tunnel, your tailnet router) and "what the proxies may reach" (every
backend behind the gateway, DNS) are spelled out, and both lists are
entirely the estate's. The chart takes them as verbatim
`networking.k8s.io/v1` rules rather than inventing a schema, and adds only
the one structural rule — xDS egress to the controller — itself.

## Development

```sh
devbox shell        # or direnv
just check          # lint + golden renders + leak canary
just golden         # regenerate tests/golden after a template change — review the diff
```

Every `tests/cases/envoy-gateway-fleet/<case>/values.yaml` is rendered and
compared byte-for-byte with `tests/golden/envoy-gateway-fleet/<case>.yaml`.

## Releasing

Push a tag `vX.Y.Z`. The shared release workflow (truvity/ci-workflows)
creates the GitHub Release and pushes the chart at that version — the
chart's own `version` field is a placeholder that never moves.

## Licence

MIT — see [LICENSE](LICENSE).
