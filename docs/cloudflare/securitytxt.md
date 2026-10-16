# cloudflare/securitytxt

A zone's `/.well-known/security.txt` (RFC 9116), planned and applied through
Cloudflare's Security Center API. The Pulumi Cloudflare provider has no
resource for it, so the edge stack ignores the `security_txt` block of a
[config](config.md) zone and this package applies it.

```
GET|PUT /zones/{zone_id}/security-center/securitytxt
```

## Credential

Reading needs read access to the zone. Writing needs Zone Settings Write: the
zone settings of the preset kind `zone` (see [presets](presets.md)). The
other kinds, `insights` included, cannot write it. A zone declared with
`manage: security_txt` ([config](config.md)) gets exactly that one group in
the `zone` kind and no other zone group.

## Library

```go
cfg, _ := config.Parse(data)                          // or config.Load
targets := securitytxt.Targets(cfg, "", "")           // zone filter, account filter
c := securitytxt.NewClient(token)

changes, err := c.Plan(ctx, targets, time.Now())      // reads only
err = c.Apply(ctx, changes)                           // writes what differs
```

`Plan` checks every expiry before it reads anything, then returns one
`Change{Zone, ZoneID, Live, Want, Differs, Warnings}` per zone.
`securitytxt.Diff(live, want)` lists the fields that differ. `Apply` writes
only the changes that differ. A zone with no security.txt reads back as the
zero `Doc`.

## RFC 9116 checks

- `expires` is required, an RFC 3339 timestamp, in the future, and less than a
  year ahead (a day of slack: "today plus one year" is accepted the day it is
  written).
- Within 60 days of expiry a warning is returned; it does not stop an apply.
- The config already holds `contact` to `mailto:` and `https://` URIs.

Compared as instants, so the API spelling the same time in another offset is
not a change.

## Command

```
edge-securitytxt -config cloudflare.yaml                     # report the difference
edge-securitytxt -config cloudflare.yaml -zone example.com -apply
edge-securitytxt -config cloudflare.yaml -format json
```

Flags: `-zone`, `-account` (filters), `-apply`, `-format text|json`,
`-token-env` (default `CLOUDFLARE_API_TOKEN`), `-token-cmd` (a command, run
without a shell, whose output is the token, for a credential helper). The
token is never printed, and is removed from any error that echoes it.

The command reads the file with `config.Parse`, not `config.Load`: `Load`
derives the tunnels from the edge catalog, which this command has no use for.
`Parse` holds each zone, `security_txt` included, to the same validation.

An estate that mints short-lived tokens wraps the command (or the library)
with `presettoken.Estate.Credential` for its `zone` preset and passes the
token through the environment variable.
