# Doctrine — the design rules

## The zone is the unit, the account is its attribute

A Cloudflare API token is scoped to one account, and a tunnel cannot
cross accounts. An estate whose domains live in more than one account
therefore cannot treat "which account" as a global, as if one provider
arriving ambiently were enough. So:

- **`pkg/account` binds one token to one account** and hands back
  `Use()`, the resource option every zone, tunnel and record in that
  account is created with. A caller never has to remember which of
  several providers a resource belongs to; it passes the account's.
- **A zone belongs to exactly one account,** and `pkg/zone` is created
  with that account's `Use()`. Several zones of one account share it.
- **One tunnel, and one cloudflared, per cluster and account.** The
  tunnel is in one account, so a cluster serving two accounts runs two.
  A second cluster serving the same account gets its own tunnel, not
  extra connectors on the first cluster's: connectors of one tunnel are
  load-balanced as equals, so sharing one across clusters would send a
  cluster's hostnames to another cluster's origins, and one token would
  open both. The chart carries the release name in every object name
  and in the pod selector so that one cluster's installs share a
  namespace without claiming each other's pods.

Accounts are data, not code: every `Args` type is a plain yaml-taggable
struct, so an estate keeps its accounts, zones and tunnels as rows in its
own configuration and loops over them.

## Credentials come in, secrets go out

- The API token is an **input** to `account.New`, marked secret before it
  reaches the provider.
- The tunnel secret is an **input** to `tunnel.New`; the library never
  derives one.
- The tunnel token is an **output**, `Tunnel.Token`, marked secret. Where
  it is stored is the caller's decision.
- The chart takes the **name** of a Secret for the token (`secretName`,
  `secretKey`) and for the origin CA (`caSecretName`), mounts it, and
  creates neither. It does not know which tool wrote the Secret: an
  external-secrets controller, SOPS, a certificate controller or
  `kubectl`. The origin CA is therefore a plain Secret the caller owns,
  keyed by the file name `caPool` points at, and not an object of any one
  certificate tool.

No secret store, no cloud SDK and no secret manager is a dependency of
this repository.

## Only what an estate decides

`pkg/zone` manages three settings: origin SSL mode, minimum TLS version
and Total TLS. A zone has scores of settings, and the rest are defaults
nobody should manage from a deployment tool; these three change what
traffic is accepted, so they belong in the same review as the routes that
depend on them. Every one is opt-in, and an unset field is a setting the
estate does not manage.

**Total TLS is the reason `pkg/zone` exists.** Without it, every proxied
hostname deeper than one label under the apex needs its own Advanced
Certificate pack, so adding a hostname means creating a certificate
resource and waiting for validation. With it, the zone issues
per-hostname certificates itself and adding a hostname is a DNS record and
nothing else.

`pkg/tunnel` touches no zone setting. Its certificate packs are an opt-in
block for zones that manage certificates per host instead.

## Remotely managed tunnels

The ingress rules are the tunnel's configuration in Cloudflare, written by
`pkg/tunnel`; cloudflared runs with nothing but the token. The chart
therefore carries no ingress, no config file and no per-host value, and a
routing change is a Pulumi change that never restarts a pod.

## What the invisible failure earns

A rule is **enforced** rather than documented when the failure it
prevents does not show. Ingress order is the example: a shadowed rule
produces 502s behind a configuration that reads correctly and a tunnel
reported healthy, so `Validate` refuses it. A render-time refusal in the
chart, likewise, is a schema rule with a fixture that must fail.

## Ownership contract

| This repository | The consuming estate |
| --- | --- |
| the provider per account, the zone settings, the tunnel, its ingress configuration, its DNS records and certificate packs | which accounts, zones and hostnames exist; the API tokens; the tunnel secrets |
| the cloudflared Deployment, ServiceAccount and PodDisruptionBudget | the token Secret and the origin CA Secret; the namespace |
| that an ingress list never shadows a rule, and a zone never manages nothing by accident | where the tunnel token is stored; the origins the tunnel routes to |
| child resource names and object names, stable across releases | network policy, scheduling, and the plan features a zone has |

## Rules a change must keep

- **A particular is an input.** An account id, a zone, a hostname or a
  secret path in a default is a leak; `hack/leak-canary.sh` catches the
  shapes it can.
- **A new capability renders and creates nothing until asked for.** An
  existing values file renders byte-for-byte the same, and an existing
  program previews no change, unless the release says otherwise (see
  [adoption.md](adoption.md#the-zero-diff-gate)).
- **Names are a contract.** A changed child resource name, object name or
  selector is a major version.
- **A new refusal comes with its fixture** in `tests/invalid/<chart>/`,
  or with its test case in the package.
