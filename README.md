# cloudflare

Cloudflare for Kubernetes estates, as reusable mechanism:

| Artifact | What | Status |
| --- | --- | --- |
| `charts/cloudflared` | The in-cluster end of a Cloudflare Tunnel — `cloudflared` as a plain Deployment, token from any Secret, one install per account | shipped |
| `pkg/account` | One API token bound to one account, as a provider to pass to everything created there | shipped |
| `pkg/zone` | Zone settings an estate decides: origin SSL mode, minimum TLS version, Total TLS | shipped |
| `pkg/tunnel` | Pulumi Go component: tunnel + DNS records + ingress rules (+ opt-in certificate packs) from a config struct | shipped |

Published to `oci://ghcr.io/truvity/charts/cloudflared` on every tag; the
Go module is `github.com/truvity/cloudflare`.

## The rule that makes this repository public

**Mechanism only.** Nothing here names an account, a zone, a hostname, a
cluster or a secret path. Every such thing is an input with a neutral
default, and the consuming estate supplies it from its own (private)
repository. `hack/leak-canary.sh` enforces this in CI, and public history
cannot be unpublished — so the rule is mechanical, not remembered.

The same rule shapes the Go packages: credentials come in as an API token,
secrets (the tunnel token) go out as Pulumi `Output`s and the **caller**
decides where they live. No secret store and no cloud SDK. Zone settings
are their own package, opted into per zone, because plenty of Cloudflare
plans have none and an estate should not acquire them by accident.

## Accounts and zones

A Cloudflare API token is scoped to one account, and a tunnel cannot cross
accounts. So for an estate whose domains live in more than one account,
"which account" is a property of every resource rather than a global:

- **the zone is the unit** — a domain belongs to a zone, and a zone belongs
  to exactly one account;
- **the account is its attribute** — one `pkg/account` per account, and
  every zone, tunnel and DNS record is created with that account's
  provider;
- **one cloudflared per account** — because its tunnel is in that account.
  The chart carries the release name in every object name and in the pod
  selector, so several installs share a namespace.

```go
platform, _ := account.New(ctx, "platform", account.Args{AccountID: acctID}, token)

zone.New(ctx, "example-com", zone.Args{
    ZoneID:        zoneID,
    SSL:           "strict",
    MinTLSVersion: "1.2",
    TotalTLS:      &zone.TotalTLS{Enabled: true},
}, platform.Use())

tunnel.New(ctx, "edge", tunnelArgs, secret, platform.Use())
```

## pkg/account

```go
acct, err := account.New(ctx, "platform", account.Args{
    AccountID: "...",   // from the caller's own registry
}, apiToken)            // a pulumi.StringInput from wherever secrets live
```

The contract, in one line each: the token is a caller input and is marked
secret, so it never reaches plain state; `Use()` is the resource option
that binds a component to this account, so a caller never has to remember
which of several providers a zone or tunnel belongs to; the provider child
is named `provider-<name>`; nothing else is read, created or changed.

## pkg/zone

```go
zone.New(ctx, "example-com", zone.Args{
    ZoneID:        "...",
    SSL:           "strict",           // off | flexible | full | strict
    MinTLSVersion: "1.2",              // 1.0 | 1.1 | 1.2 | 1.3
    TotalTLS:      &zone.TotalTLS{Enabled: true, CertificateAuthority: "google"},
}, acct.Use())
```

**Total TLS is the reason this package exists.** Without it, every proxied
hostname needs its own Advanced Certificate pack, so adding a hostname
means creating a certificate resource and waiting for validation. With it,
the zone issues per-hostname certificates itself and adding a hostname is a
DNS record and nothing else. It needs Advanced Certificate Manager on the
zone's plan, which is why it is opt-in rather than a default.

The contract, in one line each: an unset field is a setting this estate
does not manage, so a zone keeps whatever it has; `Validate()` rejects a
zone that would manage nothing at all; children are named
`setting-<name>-ssl`, `setting-<name>-min-tls-version` and
`total-tls-<name>`. Only three settings are here on purpose — a Cloudflare
zone has scores, and the rest are defaults nobody should be managing from
a deployment tool.

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
        // ones. Enforced, not merely advised — see below.
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

### Ingress order is checked

`Validate` refuses an ingress list in which an earlier rule already
catches a later one. The rule is enforced rather than documented because
the failure is invisible:

- cloudflared takes the **first** matching rule, and
- uses **that rule's** hostname as the origin SNI.

So a shadowed rule does not merely go unused. Its traffic is delivered to
the shadowing rule's origin under the shadowing rule's name, and an
origin that selects its certificate by SNI has no chain for it. Every
host the broad rule swallowed answers 502 — with a configuration that
reads correctly and a tunnel Cloudflare reports as healthy.

Two properties make it easy to get wrong: Cloudflare's `*` **spans
dots**, so `*.example.com` also catches `a.b.example.com`; and order is
significant in a file where nothing else is.

```yaml
# refused: the wildcard swallows the exact host below it
- {hostname: "*.example.com",       service: "https://fleet:443"}
- {hostname: "app.example.com",     service: "https://app:443"}

# refused: the broad wildcard swallows the deeper one
- {hostname: "*.example.com",       service: "https://fleet:443"}
- {hostname: "*.team.example.com",  service: "https://team:443"}

# accepted
- {hostname: "app.example.com",     service: "https://app:443"}
- {hostname: "*.team.example.com",  service: "https://team:443"}
- {hostname: "*.example.com",       service: "https://fleet:443"}
```

An exact rule never shadows a wildcard, and sibling wildcards never
shadow each other, so neither is refused.

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
| `nameOverride` / `fullnameOverride` | `""` | object names and the pod selector carry the release name, so two installs coexist in one namespace |
| `replicaCount` | `2` | two replicas = two tunnel connections; set `podDisruptionBudget.enabled` for drains |
| `image.repository` / `image.tag` | `cloudflare/cloudflared` / pinned | Renovate bumps the tag here |
| `secretName` / `secretKey` | `cloudflared-tunnel-token` / `tunnel-token` | mounted at `/secrets/<key>`, read with `--token-file` |
| `caSecretName` | `""` | Secret with `ca.pem`; mounted at `/etc/cloudflared/certs/ca.pem` so the tunnel config's `originRequest.caPool` can verify private origins |
| `extraArgs` | `[]` | appended to `cloudflared tunnel … run` |
| `nodeSelector`, `tolerations`, `affinity`, `topologySpreadConstraints`, `priorityClassName`, `podAnnotations`, `podLabels` | empty | scheduling is the estate's |
| `resources` | 50m / 64Mi, limit 256Mi | |

Running two installs in one namespace is one `helm install` per account
with different release names:

```sh
helm install cloudflared-platform oci://ghcr.io/truvity/charts/cloudflared \
  --namespace cloudflare-system --set secretName=cloudflared-platform-token
helm install cloudflared-partner  oci://ghcr.io/truvity/charts/cloudflared \
  --namespace cloudflare-system --set secretName=cloudflared-partner-token
```

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
