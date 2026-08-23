# cloudflare

Cloudflare for Kubernetes estates, as reusable mechanism:

| Artifact | What | Status |
| --- | --- | --- |
| `charts/cloudflared` | The in-cluster end of a Cloudflare Tunnel — `cloudflared` as a plain Deployment, token from any Secret | shipped |
| `pkg/tunnel` | Pulumi Go component: tunnel + DNS records + ingress rules from a config struct | planned |

Published to `oci://ghcr.io/truvity/charts/cloudflared` on every tag; the
Go module is `github.com/truvity/cloudflare`.

## The rule that makes this repository public

**Mechanism only.** Nothing here names an account, a zone, a hostname, a
cluster or a secret path. Every such thing is an input with a neutral
default, and the consuming estate supplies it from its own (private)
repository. `hack/leak-canary.sh` enforces this in CI, and public history
cannot be unpublished — so the rule is mechanical, not remembered.

The same rule shapes the planned Go component: credentials come in as a
provider, secrets (the tunnel token) go out as Pulumi `Output`s and the
**caller** decides where they live. No secret store, no cloud SDK, no
zone-level configuration — plenty of Cloudflare plans have none.

## charts/cloudflared

```sh
helm install cloudflared oci://ghcr.io/truvity/charts/cloudflared \
  --version <tag> --namespace cloudflare-system --create-namespace \
  --set secretName=cloudflared-tunnel-token
```

The chart assumes a **remotely-managed** tunnel (`cloudflared tunnel run
--token-file …`): ingress rules live in Cloudflare, the pod only needs the
token. Create the Secret with whatever owns secrets in your estate —
External Secrets, SOPS, `kubectl create secret generic … --from-literal
tunnel-token=…`.

| Value | Default | Notes |
| --- | --- | --- |
| `replicaCount` | `2` | two replicas = two tunnel connections; set `podDisruptionBudget.enabled` for drains |
| `image.repository` / `image.tag` | `cloudflare/cloudflared` / pinned | Renovate bumps the tag here |
| `secretName` / `secretKey` | `cloudflared-tunnel-token` / `tunnel-token` | mounted at `/secrets/<key>`, read with `--token-file` |
| `caSecretName` | `""` | Secret with `ca.pem`; mounted at `/etc/cloudflared/certs/ca.pem` so the tunnel config's `originRequest.caPool` can verify private origins |
| `extraArgs` | `[]` | appended to `cloudflared tunnel … run` |
| `nodeSelector`, `tolerations`, `affinity`, `topologySpreadConstraints`, `priorityClassName`, `podAnnotations`, `podLabels` | empty | scheduling is the estate's |
| `resources` | 50m / 64Mi, limit 256Mi | |

Network policies are deliberately not in the chart: the pod needs egress
to Cloudflare's edge (7844/udp+tcp, 443/tcp) and to the origins the tunnel
routes to, and only the estate knows those.

## Development

```sh
devbox shell        # or direnv
just check          # lint + golden renders + leak canary (+ go build/vuln)
just golden         # regenerate tests/golden after a template change — review the diff
```

Every `tests/cases/<chart>/<case>/values.yaml` is rendered and compared
byte-for-byte with `tests/golden/<chart>/<case>.yaml`; a template change
is reviewed as a diff, with no cluster involved.

## Releasing

Push a tag `vX.Y.Z`. The shared release workflow creates the GitHub
Release and pushes every chart at that version — a chart's own `version`
field is a placeholder that never moves.

## Licence

MIT — see [LICENSE](LICENSE).
