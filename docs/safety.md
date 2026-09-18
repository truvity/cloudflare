# Safety — what can break, and what this repository does about it

A tunnel fails quietly. Cloudflare reports it healthy while a hostname on
it answers 502, a pod reads a token file that is not there, or a zone
setting nobody meant to manage changes under a plan that has no such
feature. So the mistakes this repository can see are refused before
anything is applied: in the chart at render time, in the Go packages
before a single resource is registered.

## The chart: refused at render time

`charts/cloudflared` has no render-time `fail`. Every refusal is its
`values.schema.json`, which Helm checks on every `lint`, `template`,
`install` and `upgrade`, and so does a GitOps controller that renders the
chart. Each rule has a fixture under `tests/invalid/cloudflared/`, and
`just lint` renders every fixture and fails if one renders. It also
renders the chart with `--set bogusKey=1` and fails if that renders.

| Fixture | Values | What it prevents |
| --- | --- | --- |
| `unknown-key.yaml` | `replicaCont: 3` next to `replicaCount` | a typo read as "use the default": the release runs the default replica count and the values file says otherwise |
| `image-unknown-key.yaml` | `image.version` instead of `image.tag` | the pinned image running while the values file names another version |
| `pdb-unknown-key.yaml` | `podDisruptionBudget.maxUnavailable` | a budget the chart does not render: it takes `minAvailable` only, so the key would be dropped and the budget would be `minAvailable: 1` |
| `service-account-unknown-key.yaml` | `serviceAccount.automount` | a setting the chart has no field for, silently ignored |
| `pull-policy-invalid.yaml` | `image.pullPolicy: Sometimes` | a Deployment the API server rejects after the rest of the release has applied |
| `replicas-negative.yaml` | `replicaCount: -1` | the same, for the replica count |
| `secret-name-empty.yaml` | `secretName: ""` | a token volume that names no Secret, which the API server rejects; the tunnel token has to come from somewhere |
| `secret-key-empty.yaml` | `secretKey: ""` | `--token-file /secrets/`: cloudflared pointed at the mount directory, not at a token |

Strictness stops where Kubernetes' own fields begin: `resources`,
`affinity`, `tolerations` and `topologySpreadConstraints` are passed
through unchecked, and the API server validates them.

## The Go packages: refused before anything is registered

`New` in each package calls `Validate()` first, so a refused config
creates nothing, not even the component. A caller that unmarshals its own
YAML into the `Args` types can call `Validate()` itself and fail before a
Pulumi run. Each rule is covered by the package's tests.

### pkg/account

| Refusal | What it prevents |
| --- | --- |
| no `accountId` | a provider with no account to bind resources to |
| a nil `token` | a credential derived or defaulted by the library; the token is always the caller's input |

### pkg/zone

| Refusal | What it prevents |
| --- | --- |
| no `zoneId` | settings with no zone to apply to |
| an `ssl` other than `off`, `flexible`, `full`, `strict` | a value outside the set Cloudflare accepts, found during the apply instead of before it |
| a `minTlsVersion` other than `1.0`, `1.1`, `1.2`, `1.3` | the same |
| a `totalTls.certificateAuthority` other than `google`, `lets_encrypt`, `ssl_com` | the same |
| a zone with none of `ssl`, `minTlsVersion`, `totalTls` | a declared zone that manages nothing: it reads as managed and is not. Omit the zone instead |

### pkg/tunnel

| Refusal | What it prevents |
| --- | --- |
| no `accountId` or no `name` | a tunnel with no owner or no name |
| no ingress rule, or a rule without `hostname` or `service` | a tunnel that routes nothing; a hand-written catch-all (`service` only) is refused because the library appends it |
| a rule an earlier rule already catches | see [ingress order](#ingress-order-is-checked) |
| the same hostname twice | the second rule is dead, and which origin serves the host depends on which line someone edits |
| `dns` without `zoneId`, or with no `names` | records with no zone; an empty block is refused so that "no records" is written as no block |
| `certificates` without `zoneId` or `zone` | packs with no zone, or no apex to add to each pack |
| `certificates` with no `hosts` and no `dns.names` to default from | an opt-in that orders nothing |
| a nil tunnel `secret` | a secret derived by the library; it is always the caller's input |

### Ingress order is checked

cloudflared takes the **first** matching rule and uses **that rule's**
hostname as the origin SNI. So a shadowed rule does not merely go unused:
its traffic is delivered to the shadowing rule's origin under the
shadowing rule's name, and an origin that selects its certificate by SNI
has no chain for it. Every host the broad rule swallowed answers 502, with
a configuration that reads correctly and a tunnel Cloudflare reports as
healthy. A consuming estate met this more than once before the check
existed.

Two properties make it easy to get wrong: Cloudflare's `*` **spans dots**,
so `*.example.com` also catches `a.b.example.com`; and order is
significant in a file where nothing else is.

```yaml
# refused: the wildcard swallows the exact host below it
- {hostname: "*.example.com",       service: "https://fleet:443"}
- {hostname: "app.example.com",     service: "https://app:443"}

# refused: the broad wildcard swallows the deeper one
- {hostname: "*.example.com",       service: "https://fleet:443"}
- {hostname: "*.team.example.com",  service: "https://team:443"}

# refused: a bare "*" catches everything after it
- {hostname: "*",                   service: "http_status:404"}
- {hostname: "app.example.com",     service: "https://app:443"}

# accepted
- {hostname: "app.example.com",     service: "https://app:443"}
- {hostname: "*.team.example.com",  service: "https://team:443"}
- {hostname: "*.example.com",       service: "https://fleet:443"}
```

An exact rule never shadows a wildcard, and sibling wildcards
(`*.a.example.com`, `*.b.example.com`) never shadow each other, so neither
is refused.

## Defaults chosen because the other one failed

**Zone settings are opt-in, field by field.** An unset field is a setting
the estate does not manage, and `pkg/tunnel` touches no zone setting at
all. Plenty of Cloudflare plans have no zone-level features; an estate
must not acquire a setting, or a failed apply on a plan without it, by
upgrading a library.

**Certificate packs are off by default.** Advanced Certificate packs need
Advanced Certificate Manager, which many plans do not have. The
top-level wildcard (`*.<zone>`) is skipped even when packs are on,
because Universal SSL already covers it.

**The token is read from a file.** The chart passes `--token-file`, never
the token as an argument or an environment variable, so it is in neither
the pod spec nor the process list.

**`--no-autoupdate` is always passed.** The image tag is the version that
runs; a daemon that updated itself would drift from what the release
declares.

**The selector carries the release.** `app.kubernetes.io/instance` is in
the pod selector, so two installs in one namespace (one per account)
never claim each other's pods. The selector carries nothing that might be
retuned later, because it is immutable on a live Deployment. Adding the
instance label was itself the v2.0.0 breaking change; see
[adoption.md](adoption.md#the-chart-selector-v1x-to-v2).

## Traps worth knowing

### The CA mount comes before the caPool

The chart mounts `caSecretName` at `/etc/cloudflared/certs`, and an
ingress rule's `caPool` names a file there. The two are applied by
different tools: the mount by the chart, the rule by a Pulumi run against
Cloudflare. Roll the mount out first and wait for the new pods; only then
point `caPool` at it and drop `noTLSVerify`. A rule whose `caPool` names a
file that is not in the pod has no CA to verify the origin against.

### The whole CA Secret is mounted

The chart mounts every key of `caSecretName`, with no key selection.
Give it a Secret that holds only the CA certificate. A Secret that also
holds a private key, such as one written for a server certificate, puts
that key in the cloudflared pod.

### The file name is the Secret key

The documented path `/etc/cloudflared/certs/ca.pem` exists only if the
Secret's key is `ca.pem`. A Secret keyed `ca.crt` is mounted as
`/etc/cloudflared/certs/ca.crt`, and `caPool` must name that.

### `fullnameOverride` defeats one install per account

Object names carry the release so that a second install in the namespace
does not collide with the first. Two releases given the same
`fullnameOverride` render the same Deployment name again.

### One tunnel, one zone of DNS

`tunnel.Args.DNS` takes one `zoneId`. Hostnames in another zone of the
same account are not refused as ingress rules, but no record is created
for them; create those records against `Tunnel.CNAMETarget` (the README's
worked example does this per zone).

### Network policy is the estate's

The chart renders no NetworkPolicy. The pod needs egress to Cloudflare's
edge (7844 over UDP and TCP, and 443/TCP) and to the origins its tunnel
routes to, and only the estate knows those. A default-deny namespace
without that egress leaves every replica unable to connect.
