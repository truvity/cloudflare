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

`NewChildToken`'s `ChildTokenConfig`:

| Refusal | What it prevents |
| --- | --- |
| a nil `acct`, or an `acct` with no `AccountID` | a token with no account to belong to |
| no `Name` | a token Cloudflare's own API would refuse for an empty `name` |
| an empty `Policies` list | a token minted holding nothing, which is never what a caller means to ask for |
| a policy with an empty `PermissionGroups` list, or an empty group name in it | the same, one policy at a time |
| `"Account API Tokens Read"` or `"Account API Tokens Write"` named in any `PermissionGroups` | a child token that could itself create, read or manage other tokens — see [Child tokens never hold Account API Tokens](#child-tokens-never-hold-account-api-tokens) |
| a nil, or otherwise unrecognized, `Scope` | a policy with no resource to be scoped to. `ChildTokenScope`'s own methods are unexported, so only `WholeAccountScope`, `ZoneScope` and `R2BucketScope` — the types this package has reviewed — can ever implement it from outside the package; a nil interface is therefore the only "unknown" scope reachable at all |
| a `ZoneScope.ZoneID` that is not a 32-character lowercase hex string | a zone id the API would refuse, or a resource key that matches no zone at all |
| an `R2BucketScope.Bucket`/`Jurisdiction` outside pkg/r2's own bucket-naming and jurisdiction rules | the same "a bucket name the API would refuse" refusal pkg/r2's own `Config.Bucket` has always made, now made identically wherever a bucket is named as a scope |
| `ExpiresOn` not RFC3339, or not in the future | a token that is already expired, or a value the API rejects |
| `Rotation` containing anything but letters, digits, `.`, `_` or `-` | an arbitrary string reaching Cloudflare's token `Name` field unescaped |
| an unknown permission group name | `NewChildToken` refuses at apply time with the name it looked up, rather than creating a token with no permission group at all |

`NewChildTokenSet` adds no refusal of its own: it calls `NewChildToken`
once per entry, in sorted key order, so every row above applies per entry
exactly as it would to a hand-written `NewChildToken` call, and the first
entry (in that sorted order) that fails stops the whole set before
anything later in the order is registered.

#### Child tokens never hold Account API Tokens

Only the root, account-owned token an estate's Pulumi program itself runs
as should ever hold `Account API Tokens Read` or `Account API Tokens
Write` — the permissions that let a token create, read or manage other
tokens on the account. A child token minted by `NewChildToken` never
holds either: `ChildTokenConfig.Validate` refuses a `PermissionGroups`
entry naming either one outright, rather than minting a token that could
mint its own siblings, or its own replacement once this program stops
managing it. This is a refusal, not a sanitization — a caller that
genuinely needs to manage tokens should mint that token as the estate's
root token, outside this package, not ask `NewChildToken` to make an
exception.

### pkg/zone

| Refusal | What it prevents |
| --- | --- |
| no `zoneId` | settings with no zone to apply to |
| an `ssl` other than `off`, `flexible`, `full`, `strict` | a value outside the set Cloudflare accepts, found during the apply instead of before it |
| a `minTlsVersion` other than `1.0`, `1.1`, `1.2`, `1.3` | the same |
| a `totalTls.certificateAuthority` other than `google`, `lets_encrypt`, `ssl_com` | the same |
| a zone with none of `ssl`, `minTlsVersion`, `totalTls`, `cache` | a declared zone that manages nothing: it reads as managed and is not. Omit the zone instead |
| a `cache.hosts` entry that is empty | a filter expression matching the empty name, which is no host |
| a `cache.hosts` entry with an upper-case letter | a rule that is applied, reported healthy and matches nothing: Cloudflare compares a lower-cased host |
| a `cache.hosts` entry containing `/`, `:`, `"`, `\` or a space | a URL or a quoted fragment pasted where a hostname goes, which would either match nothing or end the expression early |
| a `cache.hosts` wildcard that is not one leading label (`app.*.example`, `*.`) | a wildcard Cloudflare's set literal cannot express, silently matching nothing |
| a `cache.hosts` entry listed twice | a second rule term for a host already covered, which reads as two policies for one name |

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

### pkg/r2

The parent token is account-owned (`cloudflare.AccountToken`,
`/accounts/{account_id}/tokens`), not a user token: it is not tied to a
person who might leave, and its permission group is looked up through the
**account-scoped** `getAccountApiTokenPermissionGroupsList` data source —
never the global, user-token-scoped list, which would look up the right
name in the wrong catalog. Since v2.4.0 the token itself is minted by
`account.NewChildToken` (see [pkg/account](#pkgaccount)); the rows below
that are genuinely `account.ChildTokenConfig`'s own refusals (jurisdiction,
`expiresOn`, `rotation`) are enforced twice — once by `Config.Validate`
below, before anything is registered, and again inside `NewChildToken` —
so they can never drift apart.

| Refusal | What it prevents |
| --- | --- |
| no `accountId` or no `bucket` | a bucket, and a token, with nothing to be scoped to |
| a `bucket` outside Cloudflare's own naming rules (3-63 characters; lowercase letters, digits, hyphens; no leading or trailing hyphen) | a bucket name the API would refuse at apply time instead of before it |
| a `jurisdiction` other than `""`, `default`, `eu`, `fedramp`, `us` | a value outside the set Cloudflare accepts |
| `lifecycle.expireAfterDays` not greater than zero | a rule that expires everything immediately or nothing at all; omit `lifecycle` instead |
| `token.permission` other than `object-read-write` or `object-read-only` | a permission the two known permission groups do not name, found during the apply instead of before it |
| `token.expiresOn` not RFC3339, or not in the future | a token that is already expired, or a value the API rejects |
| `token.rotation` containing anything but letters, digits, `.`, `_` or `-` | an arbitrary string reaching Cloudflare's token `Name` field unescaped |
| an unknown `token.permissionGroupName` (or the default name, if Cloudflare has renamed it) | New refuses at apply time with the name it looked up, rather than creating a token with no permission group at all |

### Rotation is a REPLACE, not an update

`Rotation` (`ChildTokenConfig.Rotation`; `pkg/r2`'s own `TokenConfig.
Rotation` is the same field, one level up) is not a Cloudflare field. It
is embedded in the account-owned token's Cloudflare-visible `Name` — a
real, mutable field: Cloudflare's account-token update endpoint, like its
user-token one, changes name, policies, status and dates in place, never
the secret value, which only a fresh create produces. Left alone, a `Name`
change would therefore not be a rotation at all: a caller asking for a
fresh credential would get the same one back, relabeled.

`account.NewChildToken` calls `pulumi.ReplaceOnChanges([]string{"name"})`
on the token resource, so any change to that field — in practice, any
change to `Rotation` — is treated as a replacement regardless of what the
provider's own diff would have done: the old token is deleted and a new
one created, with a genuinely new id and value. This does not depend on
how the generated `AccountToken` resource's own diff treats `Name` — the
vendored `pulumi-cloudflare` Go SDK ships no ForceNew/replace metadata to
inspect either way, so `NewChildToken` forces the behavior itself rather
than assuming it. Nothing else changes `Name`, so nothing else triggers a
rotation by accident. The value of `Rotation` itself has no meaning here
beyond "different from before" — a date, a counter, or a reason all work
equally well as the estate's own audit trail for why a rotation happened.
`pkg/r2` (since v2.2.0) and any other caller of `NewChildToken` get this
for free — it is `NewChildToken` that sets `ReplaceOnChanges`, never the
caller.

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

### An invoke does not inherit a provider the way a resource does

A child RESOURCE registered with `pulumi.Parent(comp)` picks up `comp`'s
own provider automatically if it names none of its own — that is the
whole reason `Account.Use()` in `opts` is enough for every bucket, token,
tunnel or DNS record `pkg/r2` and `pkg/tunnel` register. A plain data-
source lookup (`ctx.Invoke`, or a generated `Lookup*`/`Get*` call) is
different: with no explicit `pulumi.Provider(...)` of its own, it falls
back to the caller's DEFAULT Cloudflare provider, `Parent` or no `Parent`.

`pkg/r2` shipped exactly this gap in v2.2.0: `lookupPermissionGroupID`
called `cloudflare.LookupAccountApiTokenPermissionGroupsList` with no
invoke option at all. Every estate that keeps the default Cloudflare
provider enabled never saw it — the invoke fell back to a provider that
existed and worked. An estate that DISABLES the default provider (so
every Cloudflare call is accountable to a named account, rather than to
whichever one Pulumi picks) saw its whole Cloudflare stack fail at
preview the moment `Token.Enabled` was turned on: `Default provider for
'cloudflare' disabled ... must use an explicit provider`, with no
resource yet touched.

Fixed in v2.3.0: `pkg/r2`'s permission-group lookup and `pkg/tunnel`'s
token lookup now both thread the SAME explicit provider their sibling
resources use — via `account.InvokeOptionsFromResourceOptions(opts...)`
— into the invoke as well. A caller who already passes `acct.Use()` needs
no code change to pick up the fix. A caller building a `Lookup*`/`Get*`
call of its own, anywhere, should pass `acct.Invoke()` rather than assume
`pulumi.Parent(...)` alone is enough.

Since v2.4.0, `account.NewChildToken` closes this class of bug
structurally for its own permission-group lookup: it takes `acct
*Account` as a required argument, not just an `opts` list a caller might
forget to populate, and binds `acct.Provider` onto the lookup invoke
itself — there is no `opts`-shaped way to call `NewChildToken` and get the
v2.2.0 gap back. `pkg/r2` rebuilds the `*Account` its own `New` never
received directly (its own public signature still takes `AccountID` and
`opts`, unchanged) from `opts`' provider, once, right where the old
`InvokeOptionsFromResourceOptions` call used to sit.
