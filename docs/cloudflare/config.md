# The Cloudflare config model (`cloudflare/config`)

`cloudflare/config` is the typed form of an estate's Cloudflare registry: the
accounts it uses, the zones inside them and the settings each zone carries, the
fleet Service every tunnel delivers to, the R2 buckets, and the rotation knobs
of the token split. It is one YAML file, `cloudflare.yaml`, and the schema is
this package's: an estate loads the file and calls the package, it does not
redefine the types.

The package links no Pulumi and no Cloudflare SDK. Its dependencies are the
standard library, the YAML decoder, and this module's SDK-free packages
(`catalog`, `cloudflare/edgespec`, `cloudflare/zonespec`, `cloudflare/rules`,
`cloudflare/cfnames`); `TestNoSDKImports` fails if that changes. A tool that
only validates the file, or renders from it, does not pull the provider in.

```go
cat, err := catalog.Load(fsys)               // gateways.yaml
err = cat.WithProjects(projects)             // generated groups, if any
cfg, err := config.Load(fsys, cat, projects) // cloudflare.yaml + derived tunnels
```

`Load` reads `cloudflare.yaml` (`config.FileName`), validates the registry,
derives the tunnels and each cache zone's hosts from the catalog, and validates
both together. `Parse(data)` is the first half alone: it decodes and validates
what the file says and derives nothing. Decoding is strict: an unknown key at
any depth fails, so a misspelled setting cannot silently do nothing.

`projects` is the project list the catalog was generated from. A zone that
declares `cache` caches the exact hosts of the business projects among them
(a group is a business project's when every namespace it admits routes from is
a project), so `Load` refuses a nil list when any zone declares `cache`; an
empty, non-nil list means no business project.

## Schema

```yaml
accounts:
  <name>:                    # lowercase, becomes part of tunnel, release and Secret names
    account_id: <id>         # required
    legacy_names: true       # at most one account; keeps the unsuffixed names
    breakglass_item: <name>  # the password-manager item holding the account's root token; a name, not a secret
    company: <label>         # optional, lowercase label; the library does not interpret it
    root: {edge: {rotation: "1"}, ...}   # per-account rotations; not on the legacy_names account
zones:
  <domain>:                  # lowercase, no wildcard
    account: <name>
    zone_id: <id>            # or zone_id_pending: true, never both
    ssl_mode: full | strict  # the zone's default toward its origins
    min_tls_version: "1.2"
    total_tls: {enabled: true, certificate_authority: lets_encrypt}
    always_use_https: true
    hsts: {enabled, max_age, include_subdomains, nosniff}   # preload is refused; needs always_use_https
    bot_management: {ai_bots: block, managed_robots_txt: true}   # ai_bots: block | disabled | only_on_ad_pages; only these two fields
    cache: {respect_origin_browser_ttl: true}               # hosts are derived, never written
    public_cache: {host: <name>, ttl: 5m}                   # needs cache
    trusted_clients: {hosts: [...], ranges: [...], skip: [...]}   # skip default: bot and rate-limit checks only
    rate_limits: {plan: pro, rules: [{name, endpoints: [{host, path | path_prefix, methods}], characteristics, period, requests, mitigation_timeout, action}]}
    managed_waf: {hosts: [...]} | {whole_zone: true}
    ssl_mode_rules: {<host>: full | strict}
    ssl_mode_rule_refs: {<host>: <32 hex>}
    config_rules_import_id: <32 hex>
    origin_cnames: {<host>: "" | d-<id>.execute-api.<region>.amazonaws.com}
    records: [{name, type: A | AAAA | CNAME, content, proxied, ttl, comment}]
    security_txt: {contact: [mailto: | https:], expires: <RFC 3339>, preferred_languages}
fleets:
  internal: {service: <name>, namespace: <ns>}   # required
r2:
  <name>: {enabled, account, bucket, jurisdiction, lifecycle: {expire_after_days}, token: {permission, expires_on, rotation}}
root:                         # the legacy_names account's rotations; a child left out is "1"
  edge: {rotation: "1"}
  status: {rotation: "1"}
  r2_admin: {rotation: "1"}
  r2_parent: {rotation: "1"}
```

Every hostname a zone block names must be a lowercase exact name inside that
zone (and trusted clients, rate limit endpoints, managed WAF hosts and records
are held to the zone component's own checks, so a bad row fails at load and not
at apply). Trusted-client ranges must have no host bits and may not be the
whole address space; HSTS is never preloaded and is refused until
`always_use_https` is on.

## Tunnels are derived

There is no `tunnels` key. Every domain on a `cloudflare-tunnel` exposure of
the catalog resolves to a zone by longest suffix, and so to that zone's
account; each cluster gets one `Tunnel` per account its names live in, sorted
by cluster then account, hosts in ingress order (exact names first, then
wildcards deeper-first). The exposure's `cloudflare_accounts` lists the
accounts its tunnels may use; a name in a zone of another account, or in no
zone, is refused where the exposure is still known. `Validate` holds any
tunnel set, derived or hand-built, to the same routing invariants: a hostname
declared once across all tunnels, no rule shadowed by an earlier one, every
host inside a zone of the tunnel's account.

A `Tunnel` names its objects: `Name()` (the cluster for the `legacy_names`
account, `<cluster>-<account>` otherwise), `Release()` (`cloudflared` or
`cloudflared-<account>`) and `SecretName()` (`...-tunnel-token`). `Zones` is
every zone its hosts lie in, so each host's CNAME lands in its own zone.

### dns_elsewhere

A catalog domain written as `{host: x.example.com, dns_elsewhere: true}` keeps
its ingress rule on the tunnel but is left out of the tunnel's DNS names:
`Tunnel.DNSElsewhere` lists it, `Tunnel.DNSNames()` is `Hosts` without it, and
`cloudflare/edge` creates no CNAME for it (a tunnel whose every record is
written elsewhere gets no DNS block). It is for a name whose record something
else writes, and it is refused on any arrival but `cloudflare-tunnel`. Two
consequences in this model: a `records` entry may name such a host (the zone is
then its one writer), and an `origin_cnames` key may not (there is no tunnel
record to move).

## Contributions

`Zone.Contributions()` returns the rules a zone's blocks ask for as
`[]rules.Contribution`, built with the `cloudflare/rules` builders, so a caller
hands them to the zone component (`zonespec.Args.Contributions`) and builds
none by hand:

| Block | Contribution |
|---|---|
| `public_cache` | `rules.PublicPathsCache(host, ttl).Contribution()` |
| `ssl_mode_rules` | one `rules.SSLMode` per host, sorted; the rule ref is `ssl_mode_rule_refs[host]` or `ssl-mode-<host>` (`Zone.SSLModeRef`) |
| `rate_limits` | `rules.RateLimits` |
| `trusted_clients` | `rules.TrustedClients` |
| `managed_waf` | `rules.ManagedWAF` |

Not included: the cacheable hosts (`cache` with the derived `Zone.CacheHosts`,
which the zone component takes as `zonespec.Args.Cache`) and the settings that
are not rules (`always_use_https`, `hsts`, `total_tls`, `min_tls_version`,
`records`). A caller that passes these contributions must not also pass the
same blocks as `zonespec.Args.RateLimits`, `TrustedClients` or `ManagedWAF`.
The `Library` methods (`RateLimitsCfg`, `TrustedClientsCfg`, `HSTSCfg`,
`ManagedWAFCfg`, `Zone.RecordsLibrary`) convert one block to the zone
component's input.

## Per-account view and stack names

`ForAccount(account)` is the registry as one account's stacks see it: that
account alone, its zones, tunnels and R2 buckets, the fleet, and its own
rotations as `Root` (`RootFor`). It refuses while one of the account's zones is
`zone_id_pending`. Stack names follow one convention: `cloudflare-<kind>` for
the `legacy_names` account and `cloudflare-<kind>-<account>` for any other
(`StackName`, and `StackAccount` back from a name), for the kinds `StackRoot`,
`StackEdge` and `StackR2`.

`ValidateForeignHosts(map[env][]hosts)` holds every environment's foreign
hosts (legacy names the estate adopts) to a zone the registry declares.

## What stays with the estate

The library owns the schema, the validation that needs only the file and the
catalog, the derivation, and the conversion into the library's own inputs. The
estate keeps what names its own layout:

- where a tunnel token is stored: the OpenBao KV key, the SSM path, the
  residue stores of a cluster that predates the secret store;
- where a child token's root lives (the key prefix and root-token key of each
  account);
- the check that those keys are rows of the estate's secret layout, and the
  rule that an account may not be named so that its token key collides with
  the legacy account's;
- stacks of another kind than `root`, `edge` and `r2` (the prototypes stack of
  a sluis preset, for instance), and the Pulumi program that turns the model
  into resources;
- the file's contents: accounts, zones and ids are the estate's.
