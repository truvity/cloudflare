# cloudflare/insights

Checks for a WAF rollout: are the Security Center warnings clearing, and which
hosts would the managed WAF hurt before it widens. Listing and events only
read; the one write is dismissing an insight.

## Credential

The preset kind `insights` (see [presets](presets.md)): Account Security
Center Insights Read on the account; Zone Security Center Insights Read,
Analytics Read, Zone WAF Read and Bot Management Read on each zone. It is read only; the `edge` kind is not needed.

Dismissing needs the write-capable kind `insights-admin`: Account Security
Center Insights Write and Read on the account, Zone Security Center Insights
Write and Read on each zone, nothing else. The read-only kind is refused by
Cloudflare when it tries to dismiss. Keep that credential short-lived (the
kind defaults to one hour and no store).

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

## Dismissing insights

```
PUT /accounts/{account_id}/security-center/insights/{issue_id}/dismiss
PUT /zones/{zone_id}/security-center/insights/{issue_id}/dismiss     body {"dismiss": true|false}
```

Source: Cloudflare API reference, "Archives Security Center Insight"
(`security_center` insights `dismiss`). `dismiss: false` brings an insight back.

```go
err := c.Dismiss(ctx, insights.Scope{ZoneID: zoneID}, issueID, true)

c.Apply = true // the zero value is a dry run
done, err := c.DismissMatching(ctx, insights.Scope{AccountID: acct},
	insights.Filter{Class: []string{"always_use_https_not_enabled"}}, "accepted risk")
```

`Dismiss` checks the id (letters, digits, `-`, `_`). `DismissMatching` lists
the insights that pass the filter (only active ones, or with `Client.Undo` only
dismissed ones), then dismisses each; without `Client.Apply` it writes nothing
and returns what it would dismiss. On a failure it returns those already done
with the error. The endpoint takes no reason, so `reason` is checked and not
sent.

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
edge-insights dismiss -account ID | -zone ID (-id ID ... | -class C -type T -severity S) [-apply] [-undo]
```

`dismiss` is a dry run that prints what it would dismiss; `-apply` does it and
`-undo` sends `dismiss: false`. Name insights with `-id` (repeat or comma
separate) or with filters, not both. A filter that matches nothing says so and
exits 0. It needs the `insights-admin` kind. All three take `-format table|json`, `-token-env` (default `CLOUDFLARE_API_TOKEN`)
and `-token-cmd` (a command, no shell, whose output is the token). The token
is never printed.
