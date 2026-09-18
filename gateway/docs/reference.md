# Reference

Every value of both charts. `charts/<chart>/values.yaml` carries the same
keys as commented defaults, and `values.schema.json` is the authority on
types: an unknown key fails the render.

## gateway-fleet

### Top level

| Value | Default | Notes |
|---|---|---|
| `controllerName` | `gateway.envoyproxy.io/gatewayclass-controller` | as installed by upstream's `gateway-helm` |
| `commonAnnotations` | `{}` | on every rendered object; an object's own annotations override matching keys |
| `classes` | `{}` | one GatewayClass and one EnvoyProxy per entry |
| `exposures` | `{}` | one Gateway per entry |

### `classes.<name>`

| Value | Default | Notes |
|---|---|---|
| `enabled` | `true` | |
| `namespace` | `envoy-gateway-system` | where the class's EnvoyProxy and, by default, its exposures live |
| `annotations` | `{}` | |
| `mergeGateways` | `false` | `true` shares one proxy across every Gateway of the class; no exposure may then bring its own. `false` gives each exposure its own Deployment and Service |
| `proxy.enabled` | follows `mergeGateways` | a merged class needs its class proxy; a split one does not, because each exposure brings its own |
| `proxy.name` | `<class>-config` | the EnvoyProxy's name |
| `proxy.annotations` | `{}` | |
| `proxy.filterOrder` | `[]` | verbatim `EnvoyProxy.spec.filterOrder` |
| `proxy.replicas` | `2` | |
| `proxy.podDisruptionBudget.minAvailable` | `1` | `0` or `null`: no PodDisruptionBudget |
| `proxy.pod.tolerations`, `.nodeSelector`, `.affinity`, `.topologySpreadConstraints` | empty | scheduling is the estate's |
| `proxy.service.name` | `gateway-<class>` | |
| `proxy.service.type` | `ClusterIP` | |
| `proxy.service.clusterIP` | `""` | a pinned IPv4 address, or `None` for headless; reaches the Service through the controller's patch hook |
| `proxy.service.annotations`, `.labels` | `{}` | cloud annotations belong here |
| `proxy.service.loadBalancerClass` | `""` | |
| `proxy.service.loadBalancerSourceRanges` | `[]` | |
| `proxy.service.externalTrafficPolicy` | `""` | |
| `proxy.service.patch` | `{}` | `{type, value}`, merged over the fields above |
| `proxy.useListenerPortAsContainerPort` | `false` | |
| `proxy.shutdown.drainTimeout` | `""` | |
| `proxy.shutdown.minDrainDuration` | `""` | |
| `proxy.shutdown.healthCheckFailureDelay` | `""` | fail readiness this long before draining, so a load balancer removes the endpoint first |
| `proxy.backendTLS.clientCertificateRef` | unset | `{name, namespace}`: the certificate Envoy presents to a backend that asks for one |
| `proxy.accessLog.extraFields` | `{}` | fields added to the controller's default JSON access log (`name: command operator`); see [safety.md](safety.md#adding-one-access-log-field-does-not-drop-the-others) |
| `proxy.extraSpec` | `{}` | deep-merged over the generated EnvoyProxy spec, last |

### `exposures.<name>`

| Value | Default | Notes |
|---|---|---|
| `enabled` | `true` | |
| `class` | *required* | must name an enabled class |
| `namespace` | the class namespace | |
| `gatewayName` | the map key | a DNS label |
| `annotations`, `labels` | `{}` | |
| `allowedListeners.namespaces.from` | `Same` | `None`, `Same`, `All` or `Selector`; which ListenerSets may attach |
| `allowedListeners.namespaces.selector` | unset | required, and non-empty, with `Selector` |
| `health.listenerName` | `https` or `http`, from `protocol` | |
| `health.hostname` | *required* | exact, never a wildcard |
| `health.port` | `443` | |
| `health.protocol` | `HTTPS` | |
| `health.tls.secretName` | `<gateway>-health-tls` | |
| `health.certificate.enabled` | `true` | |
| `health.certificate.issuerRef` | *required* when enabled | `{name, kind, group}`; the issuer is the estate's |
| `health.certificate.name`, `.annotations`, `.labels`, `.duration`, `.renewBefore`, `.privateKey`, `.usages` | cert-manager defaults | passed through to the Certificate |
| `health.allowedRoutes.namespaces.from` | `Same` | |
| `health.allowedRoutes.kinds` | `HTTPRoute` | must be a kind the listener's protocol accepts |
| `health.directResponse.enabled` | `false` | answers without a backend, so the exposure can be probed when everything behind it is down; needs `health.allowedRoutes.namespaces.from` `Same` or `All` |
| `health.directResponse.routeName`, `.filterName` | `<gateway>-health` | |
| `health.directResponse.path` | `/healthz` | |
| `health.directResponse.statusCode` | `200` | |
| `health.directResponse.contentType` | `text/plain` | |
| `health.directResponse.body` | `ok` | |
| `clientTrafficPolicy.enabled` | `false` | the TLS floor for everything the exposure terminates; attached ListenerSets inherit it |
| `clientTrafficPolicy.name` | `<gateway>-tls` | |
| `clientTrafficPolicy.tls.minVersion` / `.maxVersion` | `"1.3"` / `"1.3"` | |
| `clientTrafficPolicy.tls.clientValidation.enabled` | `false` | turns the exposure into one only a certificate holder can reach |
| `clientTrafficPolicy.tls.clientValidation.optional`, `.allowExpiredCertificate` | `false` | |
| `clientTrafficPolicy.tls.clientValidation.caCertificateRefs` | `[]` | `[{kind: ConfigMap\|Secret, name}]` |
| `proxy` | `{}` | this exposure's own proxy, same shape as `classes.<name>.proxy`; only on a split class |
| `networkPolicy.enabled` | `false` | |
| `networkPolicy.name` | `envoy-<exposure>` | |
| `networkPolicy.ingress`, `.egress` | `[]` | the rules are the estate's |
| `networkPolicy.xds.enabled` | `true` | the egress to the controller's xDS port; structural, because without it the proxies never get a configuration |
| `networkPolicy.xds.controllerPodLabels` | `control-plane: envoy-gateway` | |
| `networkPolicy.xds.port` | `18000` | |

## gateway-groups

### Top level

| Value | Default | Notes |
|---|---|---|
| `commonAnnotations` | `{}` | |
| `defaults` | see below | merged under every group, so a shared issuer or exposure is stated once |
| `groups` | `{}` | one ListenerSet per entry |

### `defaults` and `groups.<name>`

`defaults` takes `namespace`, `parent`, `port`, `protocol`, `certificate`
and `allowedRoutes`; a group may set any of them, and the group's value
wins. The other keys are per group only.

| Value | Default | Notes |
|---|---|---|
| `enabled` | `true` | per group only |
| `namespace` | `envoy-gateway-system` | where the ListenerSet and Certificates live: the exposure's namespace, not the project's |
| `listenerSetName` | the map key | per group only |
| `parent.name` | *required* | the exposure's Gateway |
| `parent.namespace` | the group's namespace | |
| `annotations`, `labels` | `{}` | per group only |
| `domains` | *required*, non-empty | a hostname string, or `{host, listenerName, secretName, certificateName, certificate}` to give one domain its own names or issuer; one leading `*.` is allowed |
| `port` | `443` | |
| `protocol` | `HTTPS` | |
| `certificate.enabled` | `true` | |
| `certificate.issuerRef` | *required* when enabled | once in `defaults`, per group, or per domain |
| `certificate.annotations`, `.labels`, `.duration`, `.renewBefore`, `.privateKey`, `.usages` | cert-manager defaults | |
| `allowedRoutes.namespaces.from` | `Same` | `All`, `Same` or `Selector`; a selector naming a label the platform writes is how a grant is expressed |
| `allowedRoutes.namespaces.selector` | unset | required, and non-empty, with `Selector` |
| `allowedRoutes.kinds` | `HTTPRoute` | |
| `backendTLS.enabled` | `false` | re-encrypt to the group's backend |
| `backendTLS.name` | the ListenerSet name | |
| `backendTLS.targetRefs` | *required* when enabled | `[{group, kind: Service, name, sectionName}]` |
| `backendTLS.validation` | *required* when enabled | `{caCertificateRefs, hostname}`; TLS that is never verified is not re-encryption |
| `networkPolicy.enabled` | `false` | the other half of the grant: the namespace label lets the route attach, this lets the packet arrive |
| `networkPolicy.name` | `allow-gateway-<group>` | |
| `networkPolicy.namespaces` | *required* when enabled | where to render, usually the namespaces whose routes attach |
| `networkPolicy.podSelector` | `{}` | every pod of the namespace |
| `networkPolicy.from.namespace` | *required* when enabled | the namespace the gateway's pods run in |
| `networkPolicy.from.podLabels` | *required* when enabled | the gateway's pod labels |
| `networkPolicy.ports` | *required* when enabled | `[{port, protocol}]` |
