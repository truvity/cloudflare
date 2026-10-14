# cloudflare/insights

Read-only checks for a WAF rollout: are the Security Center warnings clearing,
and which hosts would the managed WAF hurt before it widens. Nothing here
writes.

## Credential

The preset kind `insights` (see [presets](presets.md)): Account Security
Center Insights on the account, Analytics Read, Zone WAF Read and Bot
Management Read on each zone. It is read only; the `edge` kind is not needed.

## Security Center insights

```
GET /accounts/{account_id}/security-center/insights
GET /zones/{zone_id}/security-center/insights
```

```go
c := insights.NewClient(token)
items, err := c.List(ctx, insights.Scope{ZoneID: zoneID},
	insights.Filter{Severity: []string{"Critical", "Moderate"}, Dismissed: insights.Active})
```

Filters: severity (`Low`, `Moderate`, `Critical`), issue type, issue class and
dismissed (`Active` by default, `OnlyDismissed`, `AnyState`). Pages are
followed (100 per page, at most 50 pages).

## Security Events per host

```
POST /graphql      dataset: viewer.zones.firewallEventsAdaptiveGroups
```

Dimensions `clientRequestHTTPHost`, `ruleId`, `description`, `source` and
`action`, counted over a time window and ordered by count. `Events` returns a
`Summary`: hosts by total, each with the part that blocked or challenged and
its rows by count. A host that blocks on a managed rule before the rule is
enforced is a false positive to look at; run the rule with `log` first and
read this.

```go
s, err := c.Events(ctx, insights.EventsQuery{
	ZoneID: zoneID, Window: insights.Window{From: from, To: to}, Host: "api.example.com",
})
```

The dataset is adaptive (sampled) and Cloudflare limits how far back a plan
may query; a query over the limit comes back as a GraphQL error, which is
returned. `Summary.Truncated` is set when the 10000 group limit was reached:
the counts are then a lower bound, so narrow the window or the filter.

## Command

```
edge-insights list   -account ID | -zone ID [-severity Critical,Moderate] [-type T] [-class C] [-dismissed no|yes|any]
edge-insights events -zone ID [-since 24h | -from T -to T] [-host H] [-rule R] [-action A] [-source S]
```

Both take `-format table|json`, `-token-env` (default `CLOUDFLARE_API_TOKEN`)
and `-token-cmd` (a command, no shell, whose output is the token). The token
is never printed.
