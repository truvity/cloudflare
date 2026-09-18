# cloudflare

Cloudflare for Kubernetes estates, as reusable mechanism: accounts, zone
settings and tunnels as Pulumi Go components, and the in-cluster end of a
tunnel as a Helm chart.

| Artifact | What | Status |
| --- | --- | --- |
| `pkg/account` | One API token bound to one account, as the resource option everything in that account is created with | shipped |
| `pkg/zone` | The zone settings an estate decides: origin SSL mode, minimum TLS version, Total TLS | shipped |
| `pkg/tunnel` | A remotely managed tunnel, its ordered ingress rules, proxied DNS records and opt-in Advanced Certificate packs, from one config struct | shipped |
| `charts/cloudflared` | `cloudflared` as a plain Deployment: token from a Secret, optional origin CA from a Secret, one install per account | shipped |

The chart publishes to `oci://ghcr.io/truvity/charts/cloudflared` on every
tag. The Go module is `github.com/truvity/cloudflare/v2`; **use v2.0.1 or
later**, because v2.0.0 cannot be fetched as a module (see
[docs/adoption.md](docs/adoption.md#the-go-module-moves-to-v2)).

## Who it is for

A platform team that runs Kubernetes behind Cloudflare Tunnel and manages
its Cloudflare side with Pulumi in Go (the `pulumi-cloudflare` v6
provider). The estate's domains may live in more than one Cloudflare
account. The API tokens, the tunnel secrets, where the tunnel token is
stored, the origin CA and the network policy around the daemon are the
estate's. Nothing here installs a secret manager, a certificate issuer or
a gateway: the tunnel routes to an origin the estate already runs.

## The model

A Cloudflare API token is scoped to one account, and a tunnel cannot cross
accounts. So "which account" is a property of every resource, not a
global. **The zone is the unit and the account is its attribute**: a
domain belongs to a zone, a zone belongs to exactly one account, and an
account owns its zones and its tunnel.

```
account "example-platform"  (pkg/account: one token, one provider)
├── zone example.com        (pkg/zone, with acct.Use())
├── zone example.net        (pkg/zone, with acct.Use())
└── tunnel                  (pkg/tunnel, with acct.Use())
      ingress: app.example.com, app.example.net → the estate's origin
      token ──► Secret ──► cloudflared release "cloudflared-platform"

account "example-partner"
├── zone example.org
└── tunnel ──► Secret ──► cloudflared release "cloudflared-partner"
```

In Go, an estate writes the account as data: one `account.New` per
account, and `acct.Use()` passed to every zone, tunnel and record created
in it, so nothing can pick up another account's provider by accident.
Several zones in one account share that account's `Use()`, and one tunnel
serves hostnames from all of them. In the cluster, **one cloudflared per
account**, because its tunnel is in that account: the chart carries the
release name in every object name and in the pod selector, so the
installs share a namespace.

## Install and a worked example

```sh
go get github.com/truvity/cloudflare/v2@latest
```

A Pulumi program for the two accounts above. Every value is a
placeholder; an estate usually unmarshals the rows from its own YAML,
because every `Args` type is plain yaml-taggable data.

```go
package main

import (
	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi/config"

	"github.com/truvity/cloudflare/v2/pkg/account"
	"github.com/truvity/cloudflare/v2/pkg/tunnel"
	"github.com/truvity/cloudflare/v2/pkg/zone"
)

// One row per account: the account owns its zones and its tunnel.
type accountRow struct {
	Name    string
	Account account.Args
	Zones   []zoneRow
	Tunnel  tunnel.Args
}

type zoneRow struct {
	Name     string
	Settings zone.Args
	// Hostnames in this zone that point at the account's tunnel.
	Hostnames []string
}

var accounts = []accountRow{
	{
		Name:    "example-platform",
		Account: account.Args{AccountID: "example-platform-account-id"},
		Zones: []zoneRow{
			{
				Name: "example-com",
				Settings: zone.Args{
					ZoneID:        "example-com-zone-id",
					SSL:           "strict",
					MinTLSVersion: "1.2",
					TotalTLS:      &zone.TotalTLS{Enabled: true},
				},
				Hostnames: []string{"app.example.com"},
			},
			{
				Name:      "example-net",
				Settings:  zone.Args{ZoneID: "example-net-zone-id", SSL: "strict"},
				Hostnames: []string{"app.example.net"},
			},
		},
		Tunnel: tunnel.Args{
			Name: "example-platform",
			Ingress: []tunnel.Ingress{
				{Hostname: "app.example.com", Service: "https://gateway.example-system.svc:443",
					CAPool: "/etc/cloudflared/certs/ca.pem"},
				{Hostname: "app.example.net", Service: "https://gateway.example-system.svc:443",
					CAPool: "/etc/cloudflared/certs/ca.pem"},
			},
		},
	},
	{
		Name:    "example-partner",
		Account: account.Args{AccountID: "example-partner-account-id"},
		Zones: []zoneRow{
			{
				Name:      "example-org",
				Settings:  zone.Args{ZoneID: "example-org-zone-id", MinTLSVersion: "1.2"},
				Hostnames: []string{"portal.example.org"},
			},
		},
		Tunnel: tunnel.Args{
			Name: "example-partner",
			Ingress: []tunnel.Ingress{
				{Hostname: "portal.example.org", Service: "https://gateway.example-system.svc:443"},
			},
		},
	},
}

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		cfg := config.New(ctx, "")

		for _, row := range accounts {
			// The token is scoped to this account. It comes from wherever
			// the estate keeps secrets; here, a Pulumi config secret.
			acct, err := account.New(ctx, row.Name, row.Account, cfg.RequireSecret(row.Name+"-api-token"))
			if err != nil {
				return err
			}

			// A tunnel cannot cross accounts: take the id from the account.
			args := row.Tunnel
			args.AccountID = acct.AccountID

			tun, err := tunnel.New(ctx, row.Name, args, cfg.RequireSecret(row.Name+"-tunnel-secret"), acct.Use())
			if err != nil {
				return err
			}

			for _, z := range row.Zones {
				if _, err := zone.New(ctx, z.Name, z.Settings, acct.Use()); err != nil {
					return err
				}

				// One proxied CNAME per hostname, in its own zone, at the
				// account's tunnel.
				for _, host := range z.Hostnames {
					if _, err := cloudflare.NewDnsRecord(ctx, "cname-"+tunnel.Slug(host), &cloudflare.DnsRecordArgs{
						ZoneId:  pulumi.String(z.Settings.ZoneID),
						Name:    pulumi.String(host),
						Type:    pulumi.String("CNAME"),
						Content: tun.CNAMETarget,
						Proxied: pulumi.Bool(true),
						Ttl:     pulumi.Float64(1),
					}, acct.Use()); err != nil {
						return err
					}
				}
			}

			// The token is a secret output. Store it where the estate
			// keeps secrets; charts/cloudflared reads it from a Secret.
			ctx.Export(row.Name+"-tunnel-token", tun.Token)
		}

		return nil
	})
}
```

`tunnel.Args.DNS` creates the same records for a tunnel whose hostnames
all sit in one zone. The example creates them per zone instead, which is
how one tunnel serves several zones of its account.

Then one cloudflared per account, each reading its own tunnel's token
from a Secret the estate created (External Secrets, SOPS, or
`kubectl create secret generic … --from-literal tunnel-token=…`):

```sh
helm install cloudflared-platform oci://ghcr.io/truvity/charts/cloudflared \
  --version <version> --namespace cloudflare-system --create-namespace \
  --values platform-values.yaml
```

```yaml
# platform-values.yaml
secretName: cloudflared-platform-token   # key tunnel-token (secretKey)
# The CA that signed the origin's certificate, as a Secret key ca.pem;
# the ingress rules above point caPool at the mounted file.
caSecretName: cloudflared-platform-origin-ca
podDisruptionBudget:
  enabled: true
```

The second account is a second release, `cloudflared-partner`, with its
own `secretName`. [docs/reference.md](docs/reference.md) has every value
and every Go field.

## Documentation

- [docs/adoption.md](docs/adoption.md): prerequisites, install order, the
  zero-diff gate, adopting existing objects, and upgrading across the
  v2.0.0 breaking changes
- [docs/safety.md](docs/safety.md): every refusal, in the chart and in the
  Go packages, and the failure it prevents; the traps
- [docs/reference.md](docs/reference.md): every chart value, every Go
  input and output, and the child names that are a contract
- [docs/doctrine.md](docs/doctrine.md): what this repository owns and what
  the consuming estate owns, and why it is shaped this way
- [CHANGELOG.md](CHANGELOG.md): what changed for a consumer, per version

## The rule that makes this repository public

**Mechanism only.** Nothing here names an account, a zone, a hostname, a
cluster or a secret path. Every such thing is an input with a neutral
default, and the consuming estate supplies it from its own (private)
repository. `hack/leak-canary.sh` enforces this in CI, and public history
cannot be unpublished — so the rule is mechanical, not remembered.

This repository follows the shared
[component contract](https://github.com/truvity/ci-workflows/blob/master/docs/component-contract.md).

## Status

Used in production by its maintainers. Releases are listed on the
[releases page](https://github.com/truvity/cloudflare/releases), and
[CHANGELOG.md](CHANGELOG.md) says what changed for a consumer in each.

## Development

```sh
devbox shell        # or direnv
just check          # build + lint + golden renders and go test + leak canary + govulncheck
just golden         # regenerate tests/golden after a template change — review the diff
```

CI runs `build`, `lint`, `test` and `leak-canary`, each as its own job;
`vuln` runs daily. Every `tests/cases/<chart>/<case>/values.yaml` is
rendered and compared byte-for-byte with `tests/golden/<chart>/<case>.yaml`
(a case may pin its release name in a `release` file next to its values);
a template change is reviewed as a diff, with no cluster involved.

`tests/invalid/<chart>/` holds one fixture per refusal. Each must fail to
render; `just lint` proves it. A rule without a fixture is a rule that
will quietly stop working.

## Releasing

Push a tag `vX.Y.Z`. The shared release workflow creates the GitHub
Release and pushes every chart at that version — a chart's own `version`
field is a placeholder that never moves — and the same tag is the Go
module's version.

Auto-release is present but not armed (`vars.AUTO_RELEASE` is unset), so
every release today is a manual tag. When armed it cuts **patches only**:
at once for a merged `security`-labelled pull request, weekly for
dependency bumps. Minors and majors are always manual, tagged when the
change merges and after its CHANGELOG heading.

## Licence

MIT — see [LICENSE](LICENSE).
