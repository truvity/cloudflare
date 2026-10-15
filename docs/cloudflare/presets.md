# cloudflare/presets

The sluis Cloudflare presets, built from plain data rows. An estate states a
preset as a row (name, kind, account, zones, grants, lifetime); the kind
decides the rest: which permission groups, over which resources, in which
order. The estate keeps its rows and its registry of accounts and zones; this
package keeps the mechanism, so a second estate states rows, not code.

```go
reg := presets.Registry{
	Accounts: []presets.Account{{Name: "example", ID: accountID}},
	Zones:    []presets.Zone{{Name: "example.com", ID: zoneID, Account: "example"}},
}

rows := presets.StandardRows("example", []string{"example:deploy"}, []string{"example.com"})

table, err := presets.Build(reg, rows) // edge, status, r2-admin (use presets.SplitRows to add zone and services)
```

The package reads no file and no environment and registers no resource. Rows
and registry are values; load them from your own YAML.

## Why a table

A preset's rights are used in three places that must agree: the disabled
prototype token sluis clones (`cloudflare/prototypes`), the sluis installation
(the preset's lifetime, store and grants), and break-glass, which mints a child
with the same policies when sluis cannot (`cloudflare/presettoken`). All three
read one `presets.Preset`.

## Kinds

| Kind | Rights, in this order |
|---|---|
| `zone` | the per-company zone stack (`cloudflare-<company>-zone`): every group of `edge` except Cloudflare Tunnel Write, so no account-wide grant. DNS, SSL and certificates, zone settings, cache settings and config settings write on each zone (`account.ZonePolicies`); Zone WAF Write on `WAFZones`; Bot Management Write on `BotManagementZones`; Cloud Connector Write on `CloudConnectorZones`; DNS Write on `DNSOnlyZones`; Zone Settings Write alone on each `SecurityTxtOnly` zone. DNS Write is the zone's own `records:` |
| `services` | the per-company services stack (`cloudflare-<company>-services`): tunnel write on the account; DNS write on each managed zone. The same policies as `status` (`tokensplit.StatusPolicies`), differing in name and description only; a `SecurityTxtOnly` zone is refused as for `status` |
| `edge` | **DEPRECATED, kept for one release; use `zone` and `services`.** tunnel write on the account; DNS, SSL and certificates, zone settings, cache settings and config settings write on each zone; Zone WAF Write on `WAFZones`; Bot Management Write on `BotManagementZones`; Cloud Connector Write on `CloudConnectorZones`; DNS Write on `DNSOnlyZones`. A zone with `Zone.SecurityTxtOnly` (config `manage: security_txt`) gets none of these: one extra policy per such zone, last, granting only Zone Settings Write (`account.SecurityTxtPolicies`), which is what writing its security.txt takes. No R2. |
| `status` | tunnel write on the account; DNS write on each zone |
| `dns` | DNS write on each zone |
| `insights` | read only: Account Security Center Insights Read on the account; Zone Security Center Insights Read, Bot Management Read, Analytics Read and Zone WAF Read on each zone. Nothing writable |
| `insights-admin` | Account Security Center Insights Write and Read on the account; Zone Security Center Insights Write and Read on each zone. The one kind that can dismiss insights (`edge-insights dismiss`); Read sits beside Write because dismissing starts from a listing and Write is not assumed to imply Read. Nothing else writable |
| `r2-admin` | **DEPRECATED, kept for one release.** Workers R2 Storage Write on the account (every bucket) |
| `bucket-rw` | R2 object read and write on one bucket (`Bucket`, `Jurisdiction`); an R2 credential |
| `bucket-write` | R2 object write on one bucket; an R2 credential |

### Moving from `edge` to `zone` and `services`

The split replaces one `edge` token per account with two: `zone` for the zone
stack and `services` for the services stack. `TestZonePlusServicesCoverEdge`
pins that together they hold exactly the `(permission group, resource)` pairs
`edge` holds for the same row inputs: no group lost, none gained. Only two
things differ, and both are the point of the split: `zone` has no tunnel write
and `services` has it, and `services` repeats DNS Write on each managed zone
(already inside `edge`'s zone policy). A `services` row cannot list a
`SecurityTxtOnly` zone, so for an account whose only zones are such, there is
no `services` row and the tunnel write has no counterpart. `edge` and
`r2-admin` stay for one release, then go.

A zone-scoped kind with no `Zones` covers every zone of its account, by zone
name, so a further zone picks the grant up with no row change. With `Zones`
the order is yours. `WAFZones` and `BotManagementZones` must be among the zones of the row;
`DNSOnlyZones` must not be (that would grant the same twice).

No kind grants Account API Tokens, Billing, Account Settings, Memberships or
Access identity providers. sluis refuses a prototype that holds one, and a row
has no way to ask.

## Row

| Field | Meaning |
|---|---|
| `Name` | the sluis preset name; `<account>-<kind>` by convention (`PresetName`) |
| `Kind`, `Account` | a kind above; a registry account |
| `Description` | empty: the kind's generic sentence (`Description(account, kind)`). It is listed wherever sluis lists the preset; it is not part of the prototype token |
| `Zones`, `WAFZones`, `BotManagementZones`, `CloudConnectorZones`, `DNSOnlyZones` | zone names of `Account` (a `SecurityTxtOnly` zone may be in `Zones` only; the `dns` and `status` kinds never cover one, the insights kinds cover it like any zone); all but `Zones` are `edge` only. `BotManagementZones` is for the zones that set `bot_management`; `StandardRows` leaves it empty, so set it on the returned row |
| `Bucket`, `Jurisdiction` | bucket kinds only |
| `Grants` | the policy groups that may ask |
| `Lifetime` | zero: one hour |
| `Store`, `Rotation` | `none` (default, no rotation) or `external` (rotation positive and under the lifetime) |

`Validate(reg, rows)` reports every problem at once; `Build` calls it.

## Building

| Function | Result |
|---|---|
| `Build(reg, rows)` | every row's `Preset`, in row order; fails on any problem and on an account with a pending zone |
| `BuildReady(reg, rows)` | the same, leaving out the rows of an account with a pending zone (`zone_id_pending`): its prototypes would be narrower than its children, and the other accounts are unaffected |
| `ForAccount(reg, rows, account)` | one account's presets; fails only for that account's own problems and names the pending zone |
| `Named(table, name)`, `AccountOf(reg, preset)` | lookups |
| `StandardRows(account, grants, wafZones)` | the three rows `<account>-edge`, `-status`, `-r2-admin` (`edge` and `r2-admin` are deprecated). Its output does not change |
| `SplitRows(account, grants, wafZones, botZones)` | the same three rows, then `<account>-zone` (WAF on `wafZones`, Bot Management on `botZones`) and `<account>-services`; `botZones` is also set on `edge` so the pair stays comparable |

A `Preset` carries `Name`, `Kind`, `Account`, `AccountID`, `Description`,
`Policies` (the `account.ChildTokenPolicy` list, in its fixed order), `R2`,
`Lifetime`, `Rotation`, `Store` and `Grants`. `Preset.Documents()` renders the
policies as Cloudflare receives them (group names and resource keys), and
`Preset.Request()` is the `presettoken.Request` break-glass needs.

## The builders that use it

- **`presettoken.Estate`** is what an estate decides once for all accounts
  (sluisctl floor, binary prefixes, lifetime, grant hint, runbook, the
  break-glass 1Password account, vault and field, the environment variables).
  `Estate.Config(account, item, issuer, getenv)` is one account's `Config`;
  `Estate.Credential(ctx, src, account, preset.Request(), item, issuer, getenv)`
  is the credential of one preset. This replaces an estate's own
  `TokenConfig` and `ProviderToken`.
- **`prototypes.DeployTable(ctx, Table)`** is the prototypes stack of one
  account: it checks the estate names the account's root item, converts the
  account's presets (`prototypes.FromPresets`) and calls `prototypes.Deploy`.
  The Pulumi names (`prototype-<preset>`), the token names (`NamePrefix` plus
  the preset) and the policy order are `Deploy`'s, so an existing stack plans
  no change. `Table.Options` adds resource options per preset (an alias).

## Names, URNs and order stay

Nothing here renames a resource. The prototype of a preset keeps the Pulumi
name `prototype-<preset>`; its policies keep the order the kind gives, which is
the order of the policy list the token is registered with. A change of kind
order is a change of every prototype of that kind, so the equality test below
pins it.

## The golden test

`cloudflare/presets/testdata` holds a synthetic registry (two accounts, four
zones, one account whose edge preset has a WAF zone) and six rows, and
`golden.json`, the table they build, dumped as the documents Cloudflare
receives. `TestGolden` builds the table and requires the bytes to match: names,
descriptions, grants, lifetimes, store, every group, scope and order. A change
to a kind is therefore a visible diff; regenerate with
`go test ./cloudflare/presets -update` and read it, because every consumer's
prototypes change with it. `prototypes` runs the same rows through
`DeployTable` under Pulumi mocks and compares the registered token names,
protection, account and policies.

A consumer that moves its own rows here proves parity in its own repository:
it asserts the table built from its rows equals the policy documents it
produced before the move.

## What stays with the estate

The registry (loaded from its YAML), the rows and which grants and WAF zones
each account has, the estate's `Estate` values, the sluis installation's
document, the break-glass wrapper that puts the root in the environment, and
the check that asks Cloudflare for each prototype's status.
