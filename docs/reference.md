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
func (a *Account) Invoke() pulumi.InvokeOption
func InvokeOptionsFromResourceOptions(opts ...pulumi.ResourceOption) ([]pulumi.InvokeOption, error)
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
| `Invoke()` | `Use()`'s invoke-side counterpart: pass it to a `Lookup*`/`Get*` data-source call directly. A component RESOURCE inherits its parent's provider automatically; a plain invoke does not, so it needs this (or `InvokeOptionsFromResourceOptions`, below) explicitly — see [safety.md](safety.md#an-invoke-does-not-inherit-a-provider-the-way-a-resource-does) |
| `InvokeOptionsFromResourceOptions(opts...)` | extracts the explicit provider already present in a `New`-style `opts` list (`pulumi.Provider(...)`, or `Account.Use()`) and returns it as an `[]pulumi.InvokeOption`, empty if `opts` carried none. What `pkg/r2` and `pkg/tunnel` call internally so their own `New`'s single `opts` list drives both the resources it registers and any invoke it makes on the side |
| child | one provider named `provider-<name>`; `opts` are passed to it, so an existing provider can be aliased onto that name |

An Account is not a component resource and creates nothing but the
provider.

### NewChildToken

```go
func NewChildToken(ctx *pulumi.Context, name string, acct *Account, cfg ChildTokenConfig, opts ...pulumi.ResourceOption) (*ChildToken, error)
```

Mints one account-owned Cloudflare API token
(`cloudflare.AccountToken`, `/accounts/{account_id}/tokens`) scoped to
exactly `cfg.Policies`, under `acct`'s account and provider — the
generic form of the token `pkg/r2` has minted for its own bucket since
v2.2.0. `name` is the Pulumi resource name the underlying
`AccountToken` is registered under; pass `opts` (`pulumi.Parent(...)`,
in particular) the way you would to any other resource in `acct`'s
account — `acct.Use()` needs no separate mention in `opts`, because
`NewChildToken` binds `acct`'s own provider explicitly on both the
token resource and the permission-group lookup invoke described below.

```go
ct, err := account.NewChildToken(ctx, "ci-token", acct, account.ChildTokenConfig{
	Name: "ci-dns-token",
	Policies: []account.ChildTokenPolicy{
		{
			PermissionGroups: []string{"DNS Write"},
			Scope:            account.ZoneScope{ZoneID: "0123456789abcdef0123456789abcdef"},
		},
	},
})
```

`ChildTokenConfig`:

| Field | Required | Notes |
| --- | --- | --- |
| `Name` | yes | the token's Cloudflare-visible name. When `Rotation` is set, `NewChildToken` embeds it as `"<Name>-<Rotation>"` |
| `Rotation` | no | changing it to any new value forces the token to be REPLACED — a fresh id and value, never an in-place rename. See [safety.md](safety.md#rotation-is-a-replace-not-an-update) |
| `ExpiresOn` | no | an RFC3339 timestamp after which Cloudflare refuses the token; must be in the future when set |
| `Policies` | yes, non-empty | see below |

`ChildTokenPolicy` (one per entry in `Policies`; Cloudflare unions every
`allow` policy on a token, so there is no ordering between them):

| Field | Required | Notes |
| --- | --- | --- |
| `PermissionGroups` | yes, non-empty | permission group names, resolved BY NAME per account at apply time (see below); neither `"Account API Tokens Read"` nor `"Account API Tokens Write"` may appear here — see [safety.md](safety.md#child-tokens-never-hold-account-api-tokens) |
| `Scope` | yes | the one resource `PermissionGroups` applies to: `WholeAccountScope{}`, `ZoneScope{ZoneID: "..."}` or `R2BucketScope{Jurisdiction: "...", Bucket: "..."}` |

The permission groups in one policy are resolved by name through the
provider's ACCOUNT-scoped `getAccountApiTokenPermissionGroupsList` data
source at apply time — the SAME lookup, and the same exact-match-or-refuse
behaviour, `pkg/r2` has always used for its own bucket token (see
[safety.md](safety.md#pkgaccount) for the full refusal table) — with
`acct`'s explicit Cloudflare provider carried into the invoke, never the
default one.

Each `Scope` resolves to Cloudflare's own resource key for a token
policy's `Resources` map
(https://developers.cloudflare.com/fundamentals/api/how-to/create-via-api/,
accessed 2026-09-28):

| Scope | Resource key |
| --- | --- |
| `WholeAccountScope{}` | `com.cloudflare.api.account.<ACCOUNT_ID>` — every zone and account-level resource `acct` owns |
| `ZoneScope{ZoneID}` | `com.cloudflare.api.account.zone.<ZONE_ID>` — exactly one zone. `ZoneID` must be Cloudflare's own 32-character lowercase hex zone id (confirmed against https://developers.cloudflare.com/api/resources/zones/, accessed 2026-09-28: the `zone_id` path parameter is `maxLength: 32`, and every example value on that page is a 32-character lowercase hex string) |
| `R2BucketScope{Jurisdiction, Bucket}` | `com.cloudflare.edge.r2.bucket.<ACCOUNT_ID>_<JURISDICTION>_<BUCKET_NAME>` — the same key `pkg/r2` has always used (see [its own reference section](#pkgr2)); `Jurisdiction` empty (or `"default"`) is an ordinary, non-jurisdictional bucket |

`ChildToken` outputs:

| | |
| --- | --- |
| `ChildToken.Token` | the underlying `*cloudflare.AccountToken`, for a caller that needs more than `ID`/`Value` (`Status`, `IssuedOn`, and so on) |
| `ChildToken.ID` | the child token's id |
| `ChildToken.Value` | the child token's secret value; a secret output |

`ChildToken` is deliberately NOT a Pulumi component resource: `NewChildToken`
registers exactly one resource, and the `AccountToken` is registered
directly under whatever `Parent` (or none) the caller's own `opts` give
it — its type and name in Pulumi's state are exactly what they would be
had the caller registered the `AccountToken` itself. This is what makes
`pkg/r2`'s own use of `NewChildToken` (since v2.4.0) invisible to an
existing deployment: no new parent type joins the resource's URN, so
nothing is replaced.

### NewChildTokenSet

```go
func NewChildTokenSet(ctx *pulumi.Context, name string, acct *Account, cfgs map[string]ChildTokenConfig, opts ...pulumi.ResourceOption) (map[string]*ChildToken, error)
```

Mints one child token per entry of `cfgs`, and returns them keyed by the
same name — "one root token mints N least-privilege children, one stack
per child", made reusable instead of hand-written once per estate (see
[docs/layout.md](layout.md#recommended-layout)).

```go
tokens, err := account.NewChildTokenSet(ctx, "root", acct, map[string]account.ChildTokenConfig{
	"edge": {
		Name:     "cloudflare-edge",
		Policies: account.EdgePolicies("0123456789abcdef0123456789abcdef"),
	},
	"r2-admin": {
		Name:     "cloudflare-r2-admin",
		Policies: account.R2AdminPolicies(),
	},
	"r2-parent-example-bucket": {
		Name:     "cloudflare-r2-parent-example-bucket",
		Policies: account.R2BucketParentPolicies("", "example-bucket"),
	},
})
```

It is a plain iteration convenience over `NewChildToken`, nothing more:
for each key `k` (in **sorted** order — `cfgs`' keys are sorted before
minting, so two runs register resources in the same order regardless of
Go's randomized map iteration), it calls
`NewChildToken(ctx, k, acct, cfgs[k], opts...)` exactly as a caller would
writing out one such call per child by hand.

**This is the naming-preservation contract.** `name` (`NewChildTokenSet`'s
own second argument) plays NO part in any minted resource's own Pulumi
name — every resource's name, type and provider in Pulumi's state come
entirely from `cfgs`' own keys and `acct`, exactly as they would from the
equivalent hand-written `NewChildToken` calls; `name` exists only to
prefix this function's own error messages. An estate migrating N
hand-written `NewChildToken` calls onto one `NewChildTokenSet` call — for
example, four calls named `"edge"`, `"status"`, `"r2-admin"` and
`"r2-parent-<bucket>"` becoming one map with those same four keys — is
therefore a **zero-diff** change in Pulumi's state: nothing is replaced,
nothing is renamed, nothing new joins any URN, as long as the map's keys
are exactly the names the original calls used.

A nil or empty `cfgs` mints nothing and returns an empty, non-nil map.
Every `ChildTokenConfig`'s own `Validate` (refusing `Account API Tokens`
groups, an empty `Policies` list, and so on — see
[`NewChildToken`](#newchildtoken) above) applies per entry, unchanged; the
first entry (in sorted order) that fails stops the whole call before
anything later in that order is registered.

`NewChildTokenSet` knows nothing about where the returned tokens are
stored — exactly like `NewChildToken`, it returns each `ChildToken`'s `ID`
and secret `Value` and stops there. Delivering them to a consumer (a
secret store, a chart, a Pulumi export) is the caller's job.

### Role presets

Three optional functions build a `[]ChildTokenPolicy` for a common child
role, using the exact live Cloudflare permission-group names documented
above — nothing broader, nothing hidden:

```go
func EdgePolicies(zoneIDs ...string) []ChildTokenPolicy
func R2AdminPolicies() []ChildTokenPolicy
func R2BucketParentPolicies(jurisdiction, bucket string) []ChildTokenPolicy
```

| Preset | Grants |
| --- | --- |
| `EdgePolicies(zoneIDs...)` | `Cloudflare Tunnel Write` on the whole account, plus `DNS Write`, `SSL and Certificates Write`, `Zone Settings Write` and `Cache Settings Write` on each zone in `zoneIDs` — a stack that manages zones (`pkg/zone`) and runs a tunnel (`pkg/tunnel`) |
| `R2AdminPolicies()` | `Workers R2 Storage Write` on the whole account — a stack that creates and administers R2 buckets (`pkg/r2`, called with `Config.Token.Enabled: false`) |
| `R2BucketParentPolicies(jurisdiction, bucket)` | `Workers R2 Storage Bucket Item Write` on exactly one bucket (`R2BucketScope{Jurisdiction: jurisdiction, Bucket: bucket}`) — a bucket consumer's own object-level credential, the replacement for `pkg/r2`'s deprecated `Config.Token` (see [pkg/r2](#pkgr2)) |

Each is a plain `[]ChildTokenPolicy` value: use it as `Policies` in a
`ChildTokenConfig` directly, or edit the slice it returns before passing
it on. No preset exists for a "status" or backup-tunnel-only child, since
that grant is closer to an estate-specific trade-off (how much of `edge`'s
own grant a backup token should be handed) than a shape this library can
name once and reuse everywhere; write that one policy by hand.

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
	Cache: &zone.Cache{
		Hosts:                   []string{"app.example", "*.tenants.example"},
		RespectOriginBrowserTTL: true,
	},
	TrustedClients: &zone.TrustedClients{
		Zone:   "example.com",
		Hosts:  []string{"api.example.com"},
		Ranges: []string{"192.0.2.0/24"},
	},
}, acct.Use())
```

### Args

| Field | YAML key | Values | Manages |
| --- | --- | --- | --- |
| `ZoneID` | `zoneId` | required | the zone the settings apply to |
| `SSL` | `ssl` | `off`, `flexible`, `full`, `strict` | the zone setting `ssl`: how Cloudflare connects to the origin. `full` encrypts and accepts any certificate; `strict` also verifies it |
| `MinTLSVersion` | `minTlsVersion` | `1.0`, `1.1`, `1.2`, `1.3` | the zone setting `min_tls_version`: the lowest version a browser may negotiate |
| `TotalTLS` | `totalTls` | see below | Total TLS: a certificate per proxied hostname |
| `Cache` | `cache` | see below | the zone's cache rules: which hostnames may be cached at all |
| `TrustedClients` | `trustedClients` | see below | one rule that skips the security features for known client ranges on named hosts |

`TotalTLS`:

| Field | YAML key | Notes |
| --- | --- | --- |
| `Enabled` | `enabled` | turns per-hostname issuance on or off |
| `CertificateAuthority` | `certificateAuthority` | `google`, `lets_encrypt` or `ssl_com`; empty leaves Cloudflare's default |

Total TLS issues a certificate for every proxied A, AAAA or CNAME record,
so a new hostname needs no certificate resource of its own. It needs
Advanced Certificate Manager on the zone's plan.

`Cache`:

| Field | YAML key | Notes |
| --- | --- | --- |
| `Hosts` | `hosts` | the hostnames that may be cached: an exact name (`app.example`) or one leading wildcard label (`*.app.example`). An empty list is a policy — the zone caches nothing |
| `RespectOriginBrowserTTL` | `respectOriginBrowserTtl` | sets the zone setting `browser_cache_ttl` to `0`, Cloudflare's "Respect Existing Headers". False leaves the setting alone |

Without this block a zone caches by **file extension**: a response under a
name ending in `.js` or `.css` is stored at the edge whether or not its
origin asked for that, and where the origin sent no `Cache-Control` the
zone gives the browser four hours. An application that answers unknown
paths with its own shell then has one page cached under another page's
name.

With it, the phase holds two rules whose expressions partition the zone —
the listed hosts, and everything else — so exactly one matches any request
and the outcome does not depend on how two overlapping cache rules merge.
A listed host is cached only as far as its own `Cache-Control` goes
(`edge_ttl` mode `bypass_by_default`: the origin's header decides, and a
response without one is not cached), and the browser is handed that header
unchanged (`browser_ttl` mode `respect_origin`). So how long anything
lives is decided in the application that serves the bytes and knows
whether they are content-addressed.

**A zone has one ruleset per phase.** A zone that declares `cache` owns
the whole `http_request_cache_settings` phase: cache rules added beside
these in the dashboard are replaced, not merged. If the zone already has
cache rules when this is first applied, adopt them with `pulumi import`
onto the child name below, or delete them first — Cloudflare will
otherwise refuse a second entry point ruleset for the phase.

`TrustedClients`:

| Field | YAML key | Meaning |
| --- | --- | --- |
| `Zone` | `zone` | the zone's lower-case domain (`example.com`); required when hosts are set |
| `Hosts` | `hosts` | exact lower-case hostnames, the zone itself or a name inside it. No wildcards |
| `Ranges` | `ranges` | CIDR blocks, IPv4 or IPv6, no host bits set; shorter than /8 (IPv4) or /16 (IPv6) is refused as too broad |
| `Description` | `description` | the rule's description; empty uses `Trusted clients: skip security features` |

One zone custom-firewall rule with action `skip`, logging on, and the
expression `(http.host in {...}) and (ip.src in {...})` (both sets sorted,
so authoring order never changes the plan). A matching request skips the
remaining custom rules (`ruleset: current`), the phases
`http_ratelimit`, `http_request_firewall_managed` and
`http_request_sbfm` (rate limiting, managed rules, Super Bot Fight Mode),
and the legacy products `bic`, `hot`, `rateLimit`, `securityLevel`,
`uaBlock`, `waf` and `zoneLockdown`.

It exists for a machine-to-machine caller whose egress is known and
published (for example the address range a connector platform calls from):
the caller then never meets a challenge a later rule might introduce. It is
insurance for a known caller, not a way around a rule that blocks it. Both
lists empty manages no ruleset at all; one empty and the other not is
refused, because the rule would match nothing.

**Token permission.** Writing the ruleset needs `Zone WAF Write` on the
zone. `EdgePolicies` does not include it; add it to the policies of the
token that applies the zone.

**A zone has one entry point ruleset per phase.** A zone that declares
`trustedClients` owns the whole `http_request_firewall_custom` phase: custom
rules added in the dashboard are replaced, not merged. This library manages
no other rule in that phase, so it composes with `cache` (a different
phase). A zone that already has custom firewall rules must adopt them with
`pulumi import` onto the child name below, or delete them first, because
Cloudflare refuses a second entry point ruleset for the phase.

### Outputs and names

| | |
| --- | --- |
| `Zone.ZoneID` | the zone id, as an output |
| children | `setting-<name>-ssl`, `setting-<name>-min-tls-version`, `setting-<name>-browser-cache-ttl` (all `cloudflare.ZoneSetting`), `total-tls-<name>` (`cloudflare.TotalTls`), `cache-rules-<name>` and `firewall-custom-<name>` (`cloudflare.Ruleset`), each only when its field is set |

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
transformations in `opts`; children inherit them, and the tunnel-token
lookup (a plain invoke, not a child resource) carries the same explicit
provider explicitly rather than relying on that inheritance — see
[safety.md](safety.md#an-invoke-does-not-inherit-a-provider-the-way-a-resource-does).

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

## pkg/r2

`github.com/truvity/cloudflare/v2/pkg/r2`

```go
func New(ctx *pulumi.Context, name string, cfg Config, opts ...pulumi.ResourceOption) (*R2, error)
```

A component of type `truvity:cloudflare:R2`: one R2 bucket, an opt-in
expiry lifecycle, and an opt-in **account-owned** API token
(`cloudflare.AccountToken`, `/accounts/{account_id}/tokens` — not a user
token, which is tied to a person who might leave) scoped to exactly that
bucket, plus the S3-compatible credential pair Cloudflare derives from it,
so a caller never re-implements the derivation.

**Provisioning permissions.** The Cloudflare API token the Pulumi program
itself runs as needs, on the account being managed: `Account API Tokens
Write` to create and manage the account-owned token, and `Workers R2
Storage Write` to create the bucket and its lifecycle and to read the
account's own permission-group list — both the account's own
`getAccountApiTokenPermissionGroupsList` names, confirmed live, never the
dashboard's own (differently worded) labels for the same grants.

```go
r, err := r2.New(ctx, "cache", r2.Config{
	AccountID: acct.AccountID,
	Bucket:    "example-cache-bucket",
	Lifecycle: &r2.Lifecycle{ExpireAfterDays: 14},
	Token: r2.TokenConfig{
		Enabled:    true,
		Permission: r2.PermissionObjectReadWrite,
	},
}, acct.Use())
```

### Config

| Field | YAML key | Required | Notes |
| --- | --- | --- | --- |
| `AccountID` | `accountId` | yes | the account owning the bucket; take it from `Account.AccountID` |
| `Bucket` | `bucket` | yes | the R2 bucket name; refused if it does not follow Cloudflare's own naming rules (3-63 characters, lowercase letters, digits and hyphens, no leading or trailing hyphen) |
| `Jurisdiction` | `jurisdiction` | no | `""`/`"default"`, `"eu"`, `"fedramp"` or `"us"`; sets the bucket's data-residency jurisdiction AND the segment used when scoping the token's policy to this bucket, so the two can never disagree |
| `Lifecycle` | `lifecycle` | no | see below; nil expires nothing |
| `Token` | `token` | yes (block always present; `Enabled` decides) | **deprecated since v2.6.0** — see below |

`Lifecycle`:

| Field | YAML key | Notes |
| --- | --- | --- |
| `ExpireAfterDays` | `expireAfterDays` | required when `lifecycle` is set; must be greater than zero |
| `Prefix` | `prefix` | restricts the rule to objects whose key starts with it; empty is every object |

`TokenConfig`:

| Field | YAML key | Notes |
| --- | --- | --- |
| `Enabled` | `enabled` | false creates the bucket (and its lifecycle) only; every `Token*`/`S3*` output resolves to `""` |
| `Permission` | `permission` | `object-read-write` (`r2.PermissionObjectReadWrite`) or `object-read-only` (`r2.PermissionObjectReadOnly`); required when `Enabled` |
| `ExpiresOn` | `expiresOn` | an RFC3339 timestamp after which Cloudflare refuses the token; optional, must be in the future when set — for a scratch or test token that should not outlive its errand |
| `Rotation` | `rotation` | changing it to any new value forces the token to be replaced — a fresh id and value, never an in-place rename. See [safety.md](safety.md#rotation-is-a-replace-not-an-update) |
| `PermissionGroupName` | `permissionGroupName` | overrides the permission group name looked up for `Permission` (see below); empty uses the documented default |

### `Token` is deprecated

Since v2.6.0, minting a bucket's parent token inline (`Config.Token`) is
deprecated in favour of minting it separately with
[`account.NewChildToken`](#newchildtoken) or
[`account.NewChildTokenSet`](#newchildtokenset) and
`account.R2BucketParentPolicies(cfg.Jurisdiction, cfg.Bucket)` — the exact
same permission group and resource key `Config.Token` has always used —
then calling `New` with `Token.Enabled: false`. See
[docs/layout.md](layout.md#recommended-layout) for why: a bucket's own
admin token (`account.R2AdminPolicies`, account-wide) and a bucket
consumer's object-level token are two different blast radii and two
different rotation schedules, and minting the second inside the component
that creates the bucket makes that separation harder to see. `Config.Token`
itself is unchanged and keeps working — removing it would be a major
version (see [Child names are a contract](#child-names-are-a-contract)).

### The token's permission group

Since v2.4.0 the token itself is minted by
[`account.NewChildToken`](#newchildtoken); this package supplies only the
permission group name and the bucket's own scope (`account.R2BucketScope`).
The mechanics below are unchanged, just relocated.

The policy naming the token's one permission group is resolved **by
name**, through the provider's **account-scoped**
`getAccountApiTokenPermissionGroupsList` data source, at apply time — never
a hard-coded id, which is per-account, and never the global (user-token)
`getApiTokenPermissionGroupsList` list, which is the wrong lookup for an
account-owned token's own permission groups. The two names this package
knows, confirmed against
[developers.cloudflare.com/r2/api/tokens/](https://developers.cloudflare.com/r2/api/tokens/)
(accessed 2026-09-27; R2 is listed as compatible with account-owned tokens
on
[developers.cloudflare.com/fundamentals/api/get-started/account-owned-tokens/](https://developers.cloudflare.com/fundamentals/api/get-started/account-owned-tokens/),
same date):

| `Permission` | Permission group name | Grants |
| --- | --- | --- |
| `object-read-write` | `Workers R2 Storage Bucket Item Write` | read, write and list on objects in the named bucket |
| `object-read-only` | `Workers R2 Storage Bucket Item Read` | read and list on objects in the named bucket |

These are distinct from `Workers R2 Storage Bucket Write`/`…Bucket Read`,
names that do not appear on that page as of the date above. If Cloudflare
renames a group before this package catches up, set
`Token.PermissionGroupName` rather than waiting for a release.

The lookup itself carries whatever explicit Cloudflare provider `opts`
gave `New` (`acct.Use()`, typically) — not just the bucket and token
resources: this package rebuilds an `account.Account` from `opts`'
provider and hands it to `account.NewChildToken`, which binds it onto both
the token resource and the lookup invoke explicitly. See
[safety.md](safety.md#an-invoke-does-not-inherit-a-provider-the-way-a-resource-does)
for why that needs saying: an invoke does not inherit a provider from its
component the way a resource does, and v2.2.0 shipped this one without
either.

### The token's scope

The policy's `Resources` map names exactly one resource, Cloudflare's own
name for "this one bucket":
`com.cloudflare.edge.r2.bucket.<ACCOUNT_ID>_<JURISDICTION>_<BUCKET_NAME>`,
jurisdiction `default` for a non-jurisdictional bucket — confirmed on the
same page. A token this package creates can therefore never reach a
second bucket, however `Config` changes. This is `account.R2BucketScope`'s
own resource key (see [`NewChildToken`](#newchildtoken)); this package
builds one from `Config.AccountID`, `Config.Jurisdiction` and
`Config.Bucket` and passes it as the one policy's `Scope`.

### Outputs and names

| | |
| --- | --- |
| `R2.BucketName` | the bucket name, as created |
| `R2.TokenID` | the parent token's id; `""` when `Token.Enabled` is false |
| `R2.TokenValue` | the parent token's secret value; a secret output; `""` when `Token.Enabled` is false |
| `R2.S3AccessKeyID` | equals `TokenID` — Cloudflare's R2-to-S3 mapping uses the token id as the access key id ([developers.cloudflare.com/r2/api/s3/tokens/](https://developers.cloudflare.com/r2/api/s3/tokens/), accessed 2026-09-27; the same page names account-owned tokens as a token type in their own right, without restricting the mapping to user tokens, and an account-owned token has the same id/value shape) |
| `R2.S3SecretAccessKey` | the SHA-256 hash of `TokenValue`, hex encoded, per the same page; a secret output; `""` when `Token.Enabled` is false |
| `R2.S3Endpoint` | `https://<accountId>.r2.cloudflarestorage.com`, this account's R2 S3-compatible endpoint |
| children | `bucket-<name>` (`cloudflare.R2Bucket`), `lifecycle-<name>` (`cloudflare.R2BucketLifecycle`, only when `Lifecycle` is set), `token-<name>` (`cloudflare.AccountToken`, only when `Token.Enabled`) |

This package creates no secret store entry and no chart Secret; where the
token value and its derived S3 credentials are stored (a Pulumi config
secret today, OpenBAO KV tomorrow) is the caller's decision, matching
`pkg/tunnel`'s existing precedent for `Tunnel.Token`.

## cmd/r2broker and charts/r2-broker

`r2broker` is one binary, two modes, sharing `internal/mint`,
`internal/decide` and `internal/verify` so the two can never drift from
each other:

- `r2broker serve --config <path> [--addr :8080] [--audit-receiver-url <url>] [--audit-token-file <path>]`
  runs the HTTP service: `POST /v1/credentials` (bearer OIDC token in), a
  group -> grant decision, a minted credential out; `GET /healthz`. Every
  mint and refusal is recorded to its own audit catalogue
  (`catalogue/r2broker.yaml`, source `r2broker`) — with neither audit flag
  set (or the matching `$R2BROKER_AUDIT_RECEIVER_URL` /
  `$R2BROKER_AUDIT_TOKEN_FILE`), records are validated against the
  catalogue and logged, and kept nowhere else.
- `r2broker credentials (--config <path> | --service-url <url>) [--token-file <path>] [--bucket <name>] [--prefix <prefix>]... [--permission <object-read-only|object-read-write>]`
  either calls a running `serve` over HTTP, or (with `--config`) mints
  in-process — no central broker at all. Either way it prints an AWS
  `credential_process` document (`Version` 1) to stdout and nothing else.
  The bearer token comes from `--token-file`, or `$R2BROKER_TOKEN_FILE`,
  or the raw value in `$R2BROKER_TOKEN` — never an argv value. A file-
  locked, per-scope cache under `$R2BROKER_CACHE_DIR` (default
  `os.UserCacheDir()/r2broker`) makes several concurrent callers in one
  build (BuildKit, `GOCACHEPROG`, bazel-remote) mint once, not once each.

### Config (`internal/config.Config`, YAML)

| Field | Required | Notes |
| --- | --- | --- |
| `issuer` | yes | the OIDC issuer this broker trusts; no default |
| `audience` | yes | required in a token's `aud` claim |
| `groupsClaim` | yes | the claim carrying the token's group list |
| `account.id` / `account.idFile` | exactly one | the Cloudflare account id, or a path to a file holding it |
| `account.parentTokenId` / `account.parentTokenIdFile` | exactly one | the parent API token's own id (`developers.cloudflare.com/r2/api/s3/tokens/`'s "Access Key ID"), or a path to a file holding it; not sensitive |
| `account.parentTokenFile` / `account.parentTokenEnv` | exactly one | where the parent token's *value* comes from; never an inline value |

`idFile` and `parentTokenIdFile` are trimmed of exactly one trailing
newline; any other whitespace (leading, embedded, or a second trailing
newline) fails the load rather than being silently stripped.
| `minting.mode` | no (`local`) | `local` signs credentials itself with an automatic `api` fallback on error; `api` calls Cloudflare's temporary-credentials endpoint for every mint |
| `grants` | no (`[]`) | group-only rows: `group`, `bucket`, `prefixes` (a list), `permission`, `ttlSeconds` — never a repository, ref or event field |

Loading is strict: an unknown key, in the file or in a grant row, fails
the load. Empty `grants` is valid — a broker that verifies tokens and
refuses every request, not a load error.

### Service API

```
POST /v1/credentials
Authorization: Bearer <OIDC JWT, aud matches config's audience>
Content-Type: application/json

{"bucket": "…", "prefixes": ["…"], "permission": "…"}   // every field optional
```

| Outcome | Status | Body |
| --- | --- | --- |
| minted | 200 | `{"accessKeyId","secretAccessKey","sessionToken","expiration","bucket","prefixes"}` |
| no/invalid/expired token | 401 | `{"error": "…"}` |
| no grant covers the request | 403 | `{"error": "…"}` — decide's own sentence, e.g. `"no group in the token maps to a grant"` |
| minting itself failed (local AND its API fallback) | 502 | `{"error": "…"}` |

### charts/r2-broker values

| Value | Default | Notes |
| --- | --- | --- |
| `replicas` | `2` | |
| `image.repository` | `ghcr.io/truvity/cloudflare/r2broker` | ko names the image after `cmd/r2broker`'s directory — one word, unlike the chart's own hyphenated name |
| `issuer`, `audience`, `groupsClaim` | placeholders | every real install overrides `issuer`; `hack/leak-canary.sh` is why the default is `https://issuer.example.com`, not empty |
| `account.id`, `account.parentTokenId` | placeholders | plain config, not secret; each has a `*SecretKey` alternative below |
| `account.idSecretKey` / `account.parentTokenIdSecretKey` | `""` / `""` | set instead of `account.id` / `account.parentTokenId` (blank that one out) to read it from the SAME Secret as the parent token's value — a key name, mounted read-only and passed to the broker as `idFile` / `parentTokenIdFile`; `values.schema.json` refuses a values file where both or neither of a pair is set |
| `account.parentTokenSecretName` / `parentTokenSecretKey` | `r2-broker-parent-token` / `token` | the Secret holding the parent token's *value* — created by whatever already owns secrets in your estate, mounted read-only, never created by this chart; also the Secret `idSecretKey` / `parentTokenIdSecretKey` read from, when set |
| `minting.mode` | `local` | |
| `grants` | `[]` | safe default: verifies and refuses everything |
| `service.port` | `8080` | |
| `audit.receiverUrl` | `""` | the shared audit platform's receiver; empty means log-only (design §2.8) |
| `audit.tokenExpirationSeconds` | `3600` | the broker's own projected ServiceAccount token (audience `audit`), mounted only when `receiverUrl` is set — no Secret, no audit credential of its own |
| `podDisruptionBudget.enabled` | `true` | a centrally-deployed broker is meant to stay up across drains |

### Audit

Its own catalogue and installation (design decision R4), independent of
access-roster's `roster.*` actions:

| Action | Outcome | Data |
| --- | --- | --- |
| `r2broker.credential.minted` | success | `group`, `bucket`, `prefixes`, `permission`, `ttl_seconds`, `mint_mode` (`local`/`api`) — never the credential |
| `r2broker.credential.refused` | denied, with a reason | whatever of `group`/`bucket`/`prefixes`/`permission` was known before the refusal |

The actor is `anonymous` when a token could not be verified at all, or
`workload`/`ci` from the verified token's subject otherwise
(`internal/audit.Identified`). `just audit-catalogue` (`audit validate` +
`audit check-emitters`) holds `catalogue/r2broker.yaml` and
`internal/audit/events.go`'s two constructors to each other in CI.

## Child names are a contract

Every child name above is documented because an estate that already has
these resources, created at the top level of its own program, adopts them
by aliasing them onto exactly these names. A release that changed one
would turn an upgrade into a delete and a create, so a change to a child
name is a major version. [adoption.md](adoption.md#adopting-what-already-exists)
has the procedure.
