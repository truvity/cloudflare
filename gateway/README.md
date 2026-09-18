# gateway

Envoy Gateway for Kubernetes estates, as reusable mechanism: the plane the
controller manages, split into the half that is vendor-specific and the half
that is not.

| Artifact | What | Status |
|---|---|---|
| `charts/gateway-fleet` | GatewayClass and EnvoyProxy per class; one Gateway per exposure, with its health listener, its `allowedListeners` rule, its baseline ClientTrafficPolicy and its NetworkPolicy | shipped |
| `charts/gateway-groups` | One ListenerSet per project group, a listener and a Certificate per domain, an optional BackendTLSPolicy and the ingress rule that lets the gateway reach the group's workloads | shipped |
| `charts/gateway-policies` | The policies that protect what the other two expose: a TLS floor on every Gateway of a namespace unless it opts out, stricter TLS per listener, an OIDC or JWT SecurityPolicy per protected route with an `authenticated` or `groups` posture and CSRF, and BackendTLSPolicy for private-chain backends | shipped from v1.2.0 |

Charts publish to `oci://ghcr.io/truvity/charts/<chart>` on every tag.

## Who it is for

A platform team running Kubernetes with Envoy Gateway (1.9 or later, from
upstream's `gateway-helm`), cert-manager and an issuer of its own, that
wants its entry points — public, private, client-certificate — declared as
data, each project's hostnames granted rather than self-served, and sign-in,
token checks and TLS floors stated as policy rather than left to each
application. The OIDC issuer and its clients are the estate's too. The
Envoy Gateway **controller** is not here: these charts own what it
reconciles.

## The model

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

**Policies** protect both halves (`gateway-policies`): a TLS floor selects
every Gateway of a namespace unless the Gateway opts out by label, and a
SecurityPolicy attaches to a project's route — or a listener — by name.

Two consequences worth stating, because both are load-bearing:

- **The exposure's listener is a health endpoint, not a route.** A Gateway
  with no listener has no proxies, so without it an exposure would be dark
  until the first group attached — and would go dark again when the last one
  left.
- **`allowedListeners` is the wall.** Its default admits only the exposure's
  own namespace, so a project cannot open a listener by creating an object in
  a namespace it controls.

## Install and a worked example

All three charts come from one tag; pin them at the same version.

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

A project then attaches an HTTPRoute to the ListenerSet `argocd` in the
exposure's namespace, from a namespace carrying the grant label.

```sh
helm install policies oci://ghcr.io/truvity/charts/gateway-policies \
  --namespace envoy-gateway-system \
  --values policies-values.yaml
```

```yaml
# On by default, with no values at all: TLS 1.2 or later and the
# forward-secret AEAD ciphers on every Gateway of the namespace, unless the
# Gateway carries the label `tls-baseline-exempt`.
tlsBaseline:
  namespaces: [envoy-gateway-system]

defaults:
  oidc:
    issuer: https://id.example.com     # nothing signs in until this is set

securityPolicies:
  argocd:
    namespace: argocd
    targetRefs: [{name: argocd}]       # the project's HTTPRoute
    oidc:
      clientID: example-argocd
      clientSecret: {name: example-argocd-client}   # key client-secret; yours to deliver
      hostname: argocd.example.com
    # CSRF is in shadow on a sign-in route by default: counted, not refused.
```

[docs/reference.md](docs/reference.md#gateway-policies) has a worked
example with every kind of policy.

## Documentation

- [docs/adoption.md](docs/adoption.md) — prerequisites, install order, the
  zero-diff gate, and upgrading across breaking releases
- [docs/safety.md](docs/safety.md) — every render-time refusal and the
  failure it prevents; the traps
- [docs/reference.md](docs/reference.md) — every value of every chart
- [docs/doctrine.md](docs/doctrine.md) — the split between the charts, the
  three owners, and the ownership contract
- [CHANGELOG.md](CHANGELOG.md) — what changed for a consumer, per version

## The rule that makes this repository public

**Mechanism only.** Nothing here names an account, a zone, a hostname, a
cluster, an issuer or a secret path. Every such thing is an input with a
neutral default, and the consuming estate supplies it from its own (private)
repository. `hack/leak-canary.sh` enforces this in CI, and public history
cannot be unpublished — so the rule is mechanical, not remembered.

This repository follows the shared
[component contract](https://github.com/truvity/ci-workflows/blob/master/docs/component-contract.md).

## Status

Used in production by its maintainers. Releases are listed on the
[releases page](https://github.com/truvity/gateway/releases).

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

Auto-release is present but not armed (`vars.AUTO_RELEASE` is unset), so
every release today is a manual tag. When armed it cuts **patches only**:
at once for a merged `security`-labelled pull request, weekly for
dependency bumps. Minors and majors are always manual, tagged when the
change merges and after its CHANGELOG heading.

## Licence

MIT — see [LICENSE](LICENSE).
