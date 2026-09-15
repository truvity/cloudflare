{{/*
gateway-fleet helpers.

Two objects, two scopes:

  classes.<name>    a GatewayClass and, when the class is merged, the one
                    EnvoyProxy every Gateway of that class shares.
  exposures.<name>  a Gateway (one entry point: public, private, …) with its
                    health listener, its allowedListeners rule, its baseline
                    ClientTrafficPolicy and — when the class is NOT merged —
                    its own EnvoyProxy, which is what gives one exposure its
                    own Service, its own address and its own failure domain.

Every default lives here and is merged UNDER the caller's values, so no
template ever tests for a missing key.
*/}}

{{/* ------------------------------------------------------------------ */}}
{{/* Annotations for one object: commonAnnotations ← the object's own.   */}}
{{/* Empty map → callers skip the key entirely.                          */}}
{{/* ------------------------------------------------------------------ */}}
{{- define "gateway.annotations" -}}
{{- mergeOverwrite (deepCopy (.root.Values.commonAnnotations | default dict)) (.extra | default dict) | toYaml -}}
{{- end -}}

{{/* ------------------------------------------------------------------ */}}
{{/* EnvoyProxy defaults, shared by the class-level and exposure-level   */}}
{{/* proxy blocks — they are the same object in two places.              */}}
{{/* ------------------------------------------------------------------ */}}
{{- define "gateway.proxy.defaults" -}}
enabled: true
name: ""
annotations: {}
filterOrder: []
replicas: 2
podDisruptionBudget:
  minAvailable: 1
pod:
  tolerations: []
  nodeSelector: {}
  affinity: {}
  topologySpreadConstraints: []
service:
  name: ""
  type: ClusterIP
  clusterIP: ""
  annotations: {}
  labels: {}
  loadBalancerClass: ""
  loadBalancerSourceRanges: []
  externalTrafficPolicy: ""
  patch: {}
useListenerPortAsContainerPort: false
shutdown:
  drainTimeout: ""
  minDrainDuration: ""
  healthCheckFailureDelay: ""
backendTLS:
  clientCertificateRef:
    name: ""
    namespace: ""
extraSpec: {}
{{- end -}}

{{/*
Resolve one proxy block. `defaultName` and `defaultServiceName` supply the
deterministic names a consumer can alias onto.
  {{- $p := include "gateway.proxy.resolve" (dict "spec" $x.proxy "defaultName" "a" "defaultServiceName" "b") | fromYaml }}
*/}}
{{- define "gateway.proxy.resolve" -}}
{{- $d := include "gateway.proxy.defaults" . | fromYaml -}}
{{- $p := mergeOverwrite $d (.spec | default dict) -}}
{{- if not $p.name }}{{- $_ := set $p "name" .defaultName }}{{- end -}}
{{- if not $p.service.name }}{{- $_ := set $p.service "name" .defaultServiceName }}{{- end -}}
{{- toYaml $p -}}
{{- end -}}

{{/*
Build EnvoyProxy .spec from a resolved proxy block. `merge` is the class's
mergeGateways flag and is rendered only on a class-level proxy: a merged
class has exactly one proxy, so the flag has no meaning per exposure.
  {{- include "gateway.proxy.spec" (dict "proxy" $p "merge" true "renderMerge" true) }}
*/}}
{{- define "gateway.proxy.spec" -}}
{{- $p := .proxy -}}
{{- $svc := dict "name" $p.service.name "type" $p.service.type -}}
{{- with $p.service.annotations }}{{- $_ := set $svc "annotations" . }}{{- end -}}
{{- with $p.service.labels }}{{- $_ := set $svc "labels" . }}{{- end -}}
{{- with $p.service.loadBalancerClass }}{{- $_ := set $svc "loadBalancerClass" . }}{{- end -}}
{{- with $p.service.loadBalancerSourceRanges }}{{- $_ := set $svc "loadBalancerSourceRanges" . }}{{- end -}}
{{- with $p.service.externalTrafficPolicy }}{{- $_ := set $svc "externalTrafficPolicy" . }}{{- end -}}
{{- /* A pinned ClusterIP is not an envoyService field: it reaches the
       Service through the controller's own patch hook. A caller-supplied
       patch merges over it, so both can be used together. */ -}}
{{- $patch := dict -}}
{{- with $p.service.clusterIP }}
{{- $patch = dict "type" "StrategicMerge" "value" (dict "spec" (dict "clusterIP" .)) -}}
{{- end -}}
{{- $patch = mergeOverwrite $patch ($p.service.patch | default dict) -}}
{{- with $patch }}{{- $_ := set $svc "patch" . }}{{- end -}}
{{- $pod := dict -}}
{{- with $p.pod.tolerations }}{{- $_ := set $pod "tolerations" . }}{{- end -}}
{{- with $p.pod.nodeSelector }}{{- $_ := set $pod "nodeSelector" . }}{{- end -}}
{{- with $p.pod.affinity }}{{- $_ := set $pod "affinity" . }}{{- end -}}
{{- with $p.pod.topologySpreadConstraints }}{{- $_ := set $pod "topologySpreadConstraints" . }}{{- end -}}
{{- $deploy := dict "replicas" $p.replicas -}}
{{- with $pod }}{{- $_ := set $deploy "pod" . }}{{- end -}}
{{- $k8s := dict "envoyService" $svc "envoyDeployment" $deploy -}}
{{- if $p.podDisruptionBudget.minAvailable }}{{- $_ := set $k8s "envoyPDB" (dict "minAvailable" $p.podDisruptionBudget.minAvailable) }}{{- end -}}
{{- if $p.useListenerPortAsContainerPort }}{{- $_ := set $k8s "useListenerPortAsContainerPort" true }}{{- end -}}
{{- $s := dict "provider" (dict "type" "Kubernetes" "kubernetes" $k8s) -}}
{{- if .renderMerge }}{{- $_ := set $s "mergeGateways" .merge }}{{- end -}}
{{- with $p.filterOrder }}{{- $_ := set $s "filterOrder" . }}{{- end -}}
{{- $shutdown := dict -}}
{{- with $p.shutdown.drainTimeout }}{{- $_ := set $shutdown "drainTimeout" . }}{{- end -}}
{{- with $p.shutdown.minDrainDuration }}{{- $_ := set $shutdown "minDrainDuration" . }}{{- end -}}
{{- with $p.shutdown.healthCheckFailureDelay }}{{- $_ := set $shutdown "healthCheckFailureDelay" . }}{{- end -}}
{{- with $shutdown }}{{- $_ := set $s "shutdown" . }}{{- end -}}
{{- with $p.backendTLS.clientCertificateRef.name }}
{{- $ref := dict "kind" "Secret" "name" . -}}
{{- with $p.backendTLS.clientCertificateRef.namespace }}{{- $_ := set $ref "namespace" . }}{{- end -}}
{{- $_ := set $s "backendTLS" (dict "clientCertificateRef" $ref) -}}
{{- end -}}
{{- $s = mergeOverwrite $s ($p.extraSpec | default dict) -}}
{{- toYaml $s -}}
{{- end -}}

{{/* ------------------------------------------------------------------ */}}
{{/* Class                                                               */}}
{{/* ------------------------------------------------------------------ */}}
{{- define "gateway.class.defaults" -}}
enabled: true
namespace: envoy-gateway-system
annotations: {}
mergeGateways: false
proxy: {}
{{- end -}}

{{- define "gateway.class.resolve" -}}
{{- $d := include "gateway.class.defaults" . | fromYaml -}}
{{- $c := mergeOverwrite $d (.spec | default dict) -}}
{{- $_ := set $c "name" .name -}}
{{- /* A merged class needs its class proxy: it is the only one. A split
       class does not, because every exposure brings its own — so the class
       proxy defaults to the merge flag, and an explicit `enabled` still
       wins if an estate wants a fallback for Gateways it does not own. */ -}}
{{- $rawProxy := (.spec | default dict).proxy | default dict -}}
{{- if not (hasKey $rawProxy "enabled") }}{{- $_ := set $c.proxy "enabled" $c.mergeGateways }}{{- end -}}
{{- $_ := set $c "proxy" (include "gateway.proxy.resolve" (dict
      "spec" $c.proxy
      "defaultName" (printf "%s-config" .name)
      "defaultServiceName" (printf "gateway-%s" .name)) | fromYaml) -}}
{{- toYaml $c -}}
{{- end -}}

{{/* ------------------------------------------------------------------ */}}
{{/* Exposure                                                            */}}
{{/* ------------------------------------------------------------------ */}}
{{- define "gateway.exposure.defaults" -}}
enabled: true
class: ""
namespace: ""
gatewayName: ""
annotations: {}
labels: {}
allowedListeners:
  namespaces:
    from: Same
health:
  listenerName: ""
  hostname: ""
  port: 443
  protocol: HTTPS
  tls:
    secretName: ""
  certificate:
    enabled: true
    name: ""
    annotations: {}
    labels: {}
    duration: ""
    renewBefore: ""
    privateKey: {}
    usages: []
    issuerRef: {}
  allowedRoutes:
    namespaces:
      from: Same
    kinds:
      - group: gateway.networking.k8s.io
        kind: HTTPRoute
  directResponse:
    enabled: false
    routeName: ""
    filterName: ""
    annotations: {}
    labels: {}
    path: /healthz
    statusCode: 200
    contentType: text/plain
    body: ok
clientTrafficPolicy:
  enabled: false
  name: ""
  annotations: {}
  labels: {}
  tls:
    minVersion: "1.3"
    maxVersion: "1.3"
    clientValidation:
      enabled: false
      optional: false
      allowExpiredCertificate: false
      caCertificateRefs: []
proxy: {}
networkPolicy:
  enabled: false
  name: ""
  annotations: {}
  ingress: []
  xds:
    enabled: true
    controllerPodLabels:
      control-plane: envoy-gateway
    port: 18000
  egress: []
{{- end -}}

{{/*
Resolve one exposure against its class.
  {{- $e := include "gateway.exposure.resolve" (dict "name" $n "spec" $s "class" $c) | fromYaml }}
*/}}
{{- define "gateway.exposure.resolve" -}}
{{- $d := include "gateway.exposure.defaults" . | fromYaml -}}
{{- $e := mergeOverwrite $d (.spec | default dict) -}}
{{- $_ := set $e "name" .name -}}
{{- if not $e.namespace }}{{- $_ := set $e "namespace" .class.namespace }}{{- end -}}
{{- if not $e.gatewayName }}{{- $_ := set $e "gatewayName" .name }}{{- end -}}
{{- if not $e.health.listenerName }}{{- $_ := set $e.health "listenerName" (lower $e.health.protocol) }}{{- end -}}
{{- if not $e.health.tls.secretName }}{{- $_ := set $e.health.tls "secretName" (printf "%s-health-tls" $e.gatewayName) }}{{- end -}}
{{- if not $e.health.certificate.name }}{{- $_ := set $e.health.certificate "name" $e.health.tls.secretName }}{{- end -}}
{{- $healthName := printf "%s-health" $e.gatewayName | trunc 63 | trimSuffix "-" -}}
{{- if not $e.health.directResponse.routeName }}{{- $_ := set $e.health.directResponse "routeName" $healthName }}{{- end -}}
{{- if not $e.health.directResponse.filterName }}{{- $_ := set $e.health.directResponse "filterName" $healthName }}{{- end -}}
{{- if not $e.clientTrafficPolicy.name }}{{- $_ := set $e.clientTrafficPolicy "name" (printf "%s-tls" $e.gatewayName) }}{{- end -}}
{{- if not $e.networkPolicy.name }}{{- $_ := set $e.networkPolicy "name" (printf "envoy-%s" $e.name) }}{{- end -}}
{{- $_ := set $e "proxy" (include "gateway.proxy.resolve" (dict
      "spec" $e.proxy
      "defaultName" (printf "%s-proxy" $e.name)
      "defaultServiceName" (printf "gateway-%s" $e.name)) | fromYaml) -}}
{{- toYaml $e -}}
{{- end -}}

{{/*
Does this exposure render its own EnvoyProxy? Only a non-merged class can
have one: a merged class collapses every Gateway onto the class proxy, and
`spec.infrastructure` is not honoured there.
Returns "true" or "".
*/}}
{{- define "gateway.exposure.ownProxy" -}}
{{- if and (not .class.mergeGateways) .exposure.proxy.enabled -}}true{{- end -}}
{{- end -}}

{{/*
The pod labels that select this exposure's proxies. Envoy Gateway stamps
owning-gatewayclass on a MERGED fleet and owning-gateway-name/-namespace on
a per-Gateway one, so a NetworkPolicy must follow the mode.
*/}}
{{- define "gateway.podSelector" -}}
app.kubernetes.io/name: envoy
{{- if .class.mergeGateways }}
gateway.envoyproxy.io/owning-gatewayclass: {{ .class.name }}
{{- else }}
gateway.envoyproxy.io/owning-gateway-name: {{ .exposure.gatewayName }}
gateway.envoyproxy.io/owning-gateway-namespace: {{ .exposure.namespace }}
{{- end }}
{{- end -}}

{{/*
Normalize RouteGroupKind entries so an accepted short form renders
explicitly — a GitOps controller diffs forever against a server default.
*/}}
{{- define "gateway.allowedRoutes.resolve" -}}
{{- $routes := deepCopy . -}}
{{- $kinds := list -}}
{{- range $kind := $routes.kinds -}}
{{- $normalized := deepCopy $kind -}}
{{- if not (hasKey $normalized "group") }}{{- $_ := set $normalized "group" "gateway.networking.k8s.io" }}{{- end -}}
{{- $kinds = append $kinds $normalized -}}
{{- end -}}
{{- $_ := set $routes "kinds" $kinds -}}
{{- toYaml $routes -}}
{{- end -}}

{{/*
Claim one object identity in a registry, failing when two entries collide.
A dict is a reference, so the registry accumulates across one render.
  {{- include "gateway.claim" (dict "registry" $r "kind" "Gateway" "namespace" $ns "name" $n "by" "exposures.public") }}
*/}}
{{- define "gateway.claim" -}}
{{- $key := printf "%s/%s/%s" .kind .namespace .name -}}
{{- if hasKey .registry $key -}}
{{- fail (printf "%s %s/%s is claimed by both %s and %s — two objects cannot share one name" .kind .namespace .name (get .registry $key) .by) -}}
{{- end -}}
{{- $_ := set .registry $key .by -}}
{{- end -}}
