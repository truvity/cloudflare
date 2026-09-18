# Safety — what can break, and what the charts do about it

The mistakes that take an edge down are relational: two things claiming
one name, one hostname or one Secret, a grant that grants everything, a
proxy that is silently dropped. None of them is visible in a single
object, and most are not visible until they are live. So both charts
check them at render time, and every check has a fixture under
`tests/invalid/<chart>/` that must fail — `just lint` renders each one and
refuses a fixture that renders.

## Refused at render time

| Refusal | What it prevents |
|---|---|
| two exposures, or two groups, claiming one Gateway, Service, ListenerSet, Certificate or Secret name | the second object silently overwriting the first; the diff looks like an edit |
| two groups claiming one hostname on one exposure and port | a listener conflict that takes **both** groups down, invisible until it is live |
| a per-exposure `proxy` on a merged class | the settings being silently ignored: a merged class has one proxy for every exposure |
| a merged class with its proxy disabled | a class with no proxy at all |
| an exposure naming a class that does not exist or is disabled | a Gateway no controller will ever program |
| a wildcard `health.hostname` | the health listener shadowing a group's listener |
| a missing `health.hostname` | a Gateway with no listener, which has no proxies |
| a `Selector` grant with an empty selector (`allowedListeners`, `allowedRoutes`) | an empty selector matches every namespace — the opposite of a grant |
| a `directResponse` health route the exposure's own namespace may not attach | a health endpoint that never answers |
| a `clusterIP` that is not an IPv4 address or `None` | a Service patch the API server rejects after the rest has applied |
| a certificate with no `issuerRef.name` | a chart that picks an issuer; the issuer is always the estate's |
| a group with no parent, or no domains | a ListenerSet that attaches to nothing, or serves nothing |
| a domain that is not a hostname | a listener the controller rejects |
| `backendTLS` enabled with no `targetRefs` or no `validation` | a policy that re-encrypts nothing, or TLS that is never verified |
| a `networkPolicy` with no namespaces, no ports, no source namespace or no source pod labels | an allow-everything rule written by omission |
| any unknown key (`values.schema.json`) | a typo read as "use the default" |

## Defaults chosen because the other one failed

**The exposure's own listener is a health endpoint.** A Gateway with no
listener has no proxies. Without the health listener an exposure is dark
until the first group attaches, and goes dark again when the last one
leaves — which is exactly when nobody is looking.

**`allowedListeners` admits only the exposure's own namespace.** A
ListenerSet is a claim on hostnames. If a project could create one in a
namespace it controls and have it attach, the grant would be whatever the
project chose.

**One Certificate per domain, never one with every domain as a SAN.** A
group's domains are added, renamed and retired one at a time. A SAN list
has to be reissued as a whole for each change, and a failed reissue takes
every domain on it down together.

**A split class by default.** With `mergeGateways: false` every exposure
has its own Deployment, Service and address, so a private exposure does not
share a failure domain, a load balancer or a pinned address with a public
one.

## Traps worth knowing

### Adding one access-log field does not drop the others

A JSON access-log format in `EnvoyProxy.spec.telemetry` **replaces** the
controller's default line rather than extending it, so adding one field by
hand silently drops the other two dozen. `proxy.accessLog.extraFields`
therefore renders the controller's default fields too and merges the
extra ones over them. The defaults are copied from the controller: re-check
them when upgrading the controller. With no extra fields nothing is
rendered and the controller's own default stays in charge.

Log URL-valued headers with `%REQ_WITHOUT_QUERY(...)%`, or a Referer puts
its query string — tokens included — in the log.

### A pinned address goes through the controller's patch hook

The controller owns the proxy's Service, so a `clusterIP` or load-balancer
field set on it directly is reverted. The chart sets them through the
EnvoyProxy's service patch, which the controller applies on every
reconcile.

### Drain before the balancer notices

A load balancer keeps sending to an endpoint until its own health check
fails. `shutdown.healthCheckFailureDelay` fails the proxy's readiness that
long **before** it starts draining, so the endpoint is removed first and
in-flight connections are not cut.
