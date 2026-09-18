# Reference

Every chart value and every Go input and output. For the chart,
`charts/cloudflared/values.yaml` carries the same keys as commented
defaults and `values.schema.json` is the authority on types: an unknown
key fails the render. For the Go packages, the doc comments are the
authority; `Validate()` on each `Args` type returns the first problem, and
[safety.md](safety.md) lists every refusal.

## charts/cloudflared

The in-cluster end of a **remotely managed** tunnel: ingress rules live in
Cloudflare (`pkg/tunnel` writes them), and the pod needs only the tunnel
token. It renders a Deployment, a ServiceAccount and, when enabled, a
PodDisruptionBudget. Nothing else: no Secret, no NetworkPolicy, no
Service.

### Values

| Value | Default | Type | Notes |
| --- | --- | --- | --- |
| `nameOverride` | `""` | string | replaces the chart name in object names and in the `app.kubernetes.io/name` label |
| `fullnameOverride` | `""` | string | replaces the whole object name; two installs in one namespace must not share one |
| `replicaCount` | `2` | integer, at least `0` | each replica is one connector of the same tunnel |
| `image.repository` | `cloudflare/cloudflared` | string, non-empty | |
| `image.tag` | pinned in `values.yaml` | string, non-empty | Renovate bumps it; `--no-autoupdate` is always passed, so the tag is the version that runs |
| `image.pullPolicy` | `IfNotPresent` | `Always`, `IfNotPresent` or `Never` | |
| `secretName` | `cloudflared-tunnel-token` | string, non-empty | the Secret holding the tunnel token; the caller creates it |
| `secretKey` | `tunnel-token` | string, non-empty | the key in that Secret; the Secret is mounted at `/secrets` and read with `--token-file /secrets/<secretKey>`, so the token is never in the pod spec or in `ps` |
| `caSecretName` | `""` | string | a Secret with the CA that signed the origins' certificates, mounted at `/etc/cloudflared/certs`; see [caSecretName](#casecretname-and-capool). Empty: no mount |
| `extraArgs` | `[]` | list of strings | appended after `run --token-file …` |
| `serviceAccount.create` | `true` | boolean | |
| `serviceAccount.name` | `""` | string | empty: named after the release, like every other object; the pod uses this name whether or not the chart creates it |
| `serviceAccount.annotations` | `{}` | map of strings | |
| `terminationGracePeriodSeconds` | `30` | integer, at least `0` | |
| `podAnnotations` | `{}` | map of strings | |
| `podLabels` | `{}` | map of strings | on the pod only, never in the selector |
| `priorityClassName` | `""` | string | |
| `nodeSelector` | `{}` | map of strings | |
| `tolerations` | `[]` | list | passed through |
| `affinity` | `{}` | object | passed through |
| `topologySpreadConstraints` | `[]` | list | passed through |
| `podDisruptionBudget.enabled` | `false` | boolean | renders a PodDisruptionBudget with the pod selector |
| `podDisruptionBudget.minAvailable` | `1` | integer or string | a count or a percentage |
| `resources` | requests `cpu: 50m`, `memory: 64Mi`; limit `memory: 256Mi` | object | passed through |
| `global` | unset | object | accepted so a parent chart's globals do not fail the schema; unused |

### What the chart fixes, not values

- **Command:** `cloudflared tunnel --no-autoupdate --metrics 0.0.0.0:2000
  run --token-file /secrets/<secretKey>`, then `extraArgs`.
- **Probes:** liveness and readiness on `GET /ready` at the `metrics` port
  (2000/TCP).
- **Security context:** non-root, user 65532, `RuntimeDefault` seccomp,
  no privilege escalation, every capability dropped.

### Names and labels

| | Rendered as |
| --- | --- |
| object name (Deployment, ServiceAccount, PodDisruptionBudget) | `fullnameOverride`; otherwise the release name if it contains the chart name (or `nameOverride`), else `<release>-<chart name>`; 63 characters at most |
| pod selector | `app.kubernetes.io/name`, `app.kubernetes.io/instance: <release>`, `app.kubernetes.io/component: tunnel` |
| labels on every object | the selector labels, `app.kubernetes.io/version` (the stamped chart version) and `app.kubernetes.io/managed-by` |

A release named `cloudflared` renders objects named `cloudflared`; a
release named `cloudflared-partner` renders `cloudflared-partner`; a
release named `tunnel` renders `tunnel-cloudflared`.

### caSecretName and caPool

`caPool` is not a chart value. It is a field of each ingress rule in the
**remote** tunnel configuration (`tunnel.Ingress.CAPool` in Go,
`originRequest.caPool` in Cloudflare's terms): a file path inside the
cloudflared container. The chart's part is to put the file there:

- `caSecretName` names a Kubernetes Secret the caller creates and owns.
- The whole Secret is mounted, read-only, at `/etc/cloudflared/certs`;
  each key becomes a file of that name.
- The documented path, `/etc/cloudflared/certs/ca.pem`, therefore assumes
  the key `ca.pem`. A Secret with a different key works when `caPool`
  names that file instead.

With `caPool` set on a rule, cloudflared verifies the origin's
certificate against that CA instead of skipping verification. The mount
has to be in the running pods before any rule points `caPool` at it; see
[safety.md](safety.md#the-ca-mount-comes-before-the-capool).

```sh
kubectl -n cloudflare-system create secret generic cloudflared-origin-ca \
  --from-file=ca.pem=./origin-ca.pem
```

## pkg/account

`github.com/truvity/cloudflare/v2/pkg/account`

```go
func New(ctx *pulumi.Context, name string, args Args, token pulumi.StringInput, opts ...pulumi.ResourceOption) (*Account, error)
func (a *Account) Use() pulumi.ResourceOption
```

### Args

| Field | YAML key | Required | Notes |
| --- | --- | --- | --- |
| `AccountID` | `accountId` | yes | the account the token is scoped to |
| `BaseURL` | `baseUrl` | no | overrides the API endpoint; empty is Cloudflare's own. For a proxy or a test double |

`token` is an argument, not a field: a credential never travels in the
data. It is required and is marked secret before it reaches the provider,
so it never lands in plain state.

### Outputs and names

| | |
| --- | --- |
| `Account.AccountID` | the id as supplied, for resources that take it as an argument (`tunnel.Args.AccountID`) |
| `Account.Provider` | the `cloudflare.Provider` scoped to the token |
| `Use()` | `pulumi.Provider(a.Provider)`: pass it to every zone, tunnel and record in this account; a component's children inherit it |
| child | one provider named `provider-<name>`; `opts` are passed to it, so an existing provider can be aliased onto that name |

An Account is not a component resource and creates nothing but the
provider.

## pkg/zone

`github.com/truvity/cloudflare/v2/pkg/zone`

```go
func New(ctx *pulumi.Context, name string, args Args, opts ...pulumi.ResourceOption) (*Zone, error)
```

A component of type `truvity:cloudflare:Zone`. Every setting is optional,
and an unset one is a setting this estate does not manage: the zone keeps
whatever it has.

```go
z, err := zone.New(ctx, "example-com", zone.Args{
	ZoneID:        "example-com-zone-id",
	SSL:           "strict",
	MinTLSVersion: "1.2",
	TotalTLS:      &zone.TotalTLS{Enabled: true, CertificateAuthority: "google"},
}, acct.Use())
```

### Args

| Field | YAML key | Values | Manages |
| --- | --- | --- | --- |
| `ZoneID` | `zoneId` | required | the zone the settings apply to |
| `SSL` | `ssl` | `off`, `flexible`, `full`, `strict` | the zone setting `ssl`: how Cloudflare connects to the origin. `full` encrypts and accepts any certificate; `strict` also verifies it |
| `MinTLSVersion` | `minTlsVersion` | `1.0`, `1.1`, `1.2`, `1.3` | the zone setting `min_tls_version`: the lowest version a browser may negotiate |
| `TotalTLS` | `totalTls` | see below | Total TLS: a certificate per proxied hostname |

`TotalTLS`:

| Field | YAML key | Notes |
| --- | --- | --- |
| `Enabled` | `enabled` | turns per-hostname issuance on or off |
| `CertificateAuthority` | `certificateAuthority` | `google`, `lets_encrypt` or `ssl_com`; empty leaves Cloudflare's default |

Total TLS issues a certificate for every proxied A, AAAA or CNAME record,
so a new hostname needs no certificate resource of its own. It needs
Advanced Certificate Manager on the zone's plan.

### Outputs and names

| | |
| --- | --- |
| `Zone.ZoneID` | the zone id, as an output |
| children | `setting-<name>-ssl`, `setting-<name>-min-tls-version` (both `cloudflare.ZoneSetting`), `total-tls-<name>` (`cloudflare.TotalTls`), each only when its field is set |

## pkg/tunnel

`github.com/truvity/cloudflare/v2/pkg/tunnel`

```go
func New(ctx *pulumi.Context, name string, args Args, secret pulumi.StringInput, opts ...pulumi.ResourceOption) (*Tunnel, error)
func Slug(host string) string
```

A component of type `truvity:cloudflare:Tunnel`: a remotely managed tunnel
(`config_src: cloudflare`), its ingress configuration, and optionally its
DNS records and Advanced Certificate packs. `secret` is the tunnel secret,
32 random bytes in base64, supplied by the caller (pulumi-random's
`RandomBytes.Base64` is the usual source); it is required, never derived,
and marked secret. Pass the account's provider (`acct.Use()`) and any
transformations in `opts`; children inherit them.

### Args

| Field | YAML key | Required | Notes |
| --- | --- | --- | --- |
| `AccountID` | `accountId` | yes | the account that owns the tunnel; take it from `Account.AccountID` so the two cannot disagree |
| `Name` | `name` | yes | the tunnel's name in Cloudflare |
| `Ingress` | `ingress` | at least one | ordered rules; the library appends the catch-all `http_status:404` itself |
| `DNS` | `dns` | no | nil creates no records |
| `Certificates` | `certificates` | no | nil orders no certificate packs |

`Ingress` (one rule):

| Field | YAML key | Notes |
| --- | --- | --- |
| `Hostname` | `hostname` | required; exact or wildcard. Cloudflare's `*` spans dots |
| `Service` | `service` | required; the origin, for example `https://gateway.example-system.svc:443` |
| `OriginServerName` | `originServerName` | the SNI presented to the origin; set it when the origin's certificate names something other than the rule's hostname |
| `CAPool` | `caPool` | a file path inside the cloudflared container holding the origin's CA; with the chart, `/etc/cloudflared/certs/ca.pem`. Verification on |
| `NoTLSVerify` | `noTLSVerify` | skips origin verification for this rule; prefer `CAPool` |

Order matters and is checked: exact hostnames before wildcards, deeper
wildcards before broader ones. See
[safety.md](safety.md#ingress-order-is-checked).

`DNS`:

| Field | YAML key | Notes |
| --- | --- | --- |
| `ZoneID` | `zoneId` | required when `dns` is set; one zone per tunnel |
| `Names` | `names` | required, non-empty; each becomes a proxied CNAME to `<tunnel-id>.cfargotunnel.com` with automatic TTL, verbatim (exact or wildcard) |

For a tunnel whose hostnames sit in several zones of its account, leave
`DNS` nil and create the records per zone against `Tunnel.CNAMETarget`, as
the README's worked example does.

`Certificates` (opt-in Advanced Certificate packs; needs Advanced
Certificate Manager):

| Field | YAML key | Default | Notes |
| --- | --- | --- | --- |
| `ZoneID` | `zoneId` | required | the zone the packs are ordered in |
| `Zone` | `zone` | required | the zone apex; added to every pack's host list, and `*.<zone>` is skipped because Universal SSL covers it |
| `Hosts` | `hosts` | `DNS.Names` | one pack per host |
| `ValidityDays` | `validityDays` | `90` | |
| `CertificateAuthority` | `certificateAuthority` | `lets_encrypt` | |

Packs are validated by TXT record. A zone with Total TLS (`pkg/zone`)
does not need them.

### Outputs and names

| | |
| --- | --- |
| `Tunnel.ID` | the tunnel id |
| `Tunnel.CNAMETarget` | `<id>.cfargotunnel.com`, what DNS points at |
| `Tunnel.Token` | the token cloudflared runs with (`--token-file`); a secret output, stored by the caller |
| children | `tunnel-<name>`, `ingress-<name>`, `cname-<name>-<slug>` per DNS name, `acm-<name>-<slug>` per certificate host |

`Slug(host)` renders a hostname as a name fragment: `*` becomes `star`
and `.` becomes `-`, so `*.team.example.com` is `star-team-example-com`.

## Child names are a contract

Every child name above is documented because an estate that already has
these resources, created at the top level of its own program, adopts them
by aliasing them onto exactly these names. A release that changed one
would turn an upgrade into a delete and a create, so a change to a child
name is a major version. [adoption.md](adoption.md#adopting-what-already-exists)
has the procedure.
