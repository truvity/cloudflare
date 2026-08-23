# cloudflare

Cloudflare for Kubernetes estates, as reusable mechanism:

| Artifact | What | Status |
| --- | --- | --- |
| `charts/cloudflared` | The in-cluster end of a Cloudflare Tunnel — `cloudflared` as a plain Deployment, token from any Secret | shipped |
| `pkg/tunnel` | Pulumi Go component: tunnel + DNS records + ingress rules (+ opt-in certificate packs) from a config struct | shipped |

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

## pkg/tunnel

```go
import (
    "github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
    "github.com/pulumi/pulumi-random/sdk/v4/go/random"
    "github.com/truvity/cloudflare/pkg/tunnel"
)

provider, _ := cloudflare.NewProvider(ctx, "cf", &cloudflare.ProviderArgs{ApiToken: token})
secret, _ := random.NewRandomBytes(ctx, "tunnel-secret", &random.RandomBytesArgs{Length: pulumi.Int(32)})

tun, err := tunnel.New(ctx, "mycluster", tunnel.Args{
    AccountID: accountID,
    Name:      "mycluster",
    Ingress: []tunnel.Ingress{
        // Exact hosts before wildcards; deeper wildcards before broader
        // ones — cloudflared's `*` spans dots and first match wins.
        {Hostname: "app.example.com", Service: "https://gateway-internal.envoy-gateway-system.svc:443",
         CAPool: "/etc/cloudflared/certs/ca.pem"},
    },
    DNS: &tunnel.DNS{ZoneID: zoneID, Names: []string{"app.example.com"}},
    // Certificates: opt-in Advanced Certificate packs — off by default,
    // because plenty of plans have no zone-level features.
}, secret.Base64, pulumi.Provider(provider))

// tun.Token is a secret Output — store it wherever YOUR estate keeps
// secrets (a Kubernetes Secret for charts/cloudflared, SSM, SOPS...).
```

The contract, in one line each: `Args` is plain yaml-taggable data (a
consumer unmarshals its own config file into it, `Validate()` checks it);
the tunnel secret is a caller input, never derived; the token comes back
as a secret Output for the caller to store; no zone settings are ever
touched. Child resources are deterministically named (`tunnel-<name>`,
`ingress-<name>`, `cname-<name>-<slug>`, `acm-<name>-<slug>`) so an
estate migrating existing top-level resources can alias onto them.

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
