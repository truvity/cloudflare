{{/*
Fleet defaults — every per-fleet value merged over this, so templates
never test for missing keys. Render-time only; values.yaml documents the
same shape as comments.
*/}}
{{- define "fleet.defaults" -}}
namespace: envoy-gateway-system
gatewayClass:
  enabled: true
  annotations: {}
envoyProxy:
  enabled: true
  name: ""
  annotations: {}
  mergeGateways: true
  filterOrder: []
  service:
    name: ""
    type: ClusterIP
    annotations: {}
  replicas: 2
  podDisruptionBudget:
    minAvailable: 1
  pod:
    tolerations: []
    nodeSelector: {}
    affinity: {}
    topologySpreadConstraints: []
  extraSpec: {}
healthListener:
  enabled: false
  name: ""
  annotations: {}
  listenerName: http
  hostname: ""
  port: 443
  protocol: HTTPS
  tls:
    secretName: ""
  certificate:
    enabled: true
    annotations: {}
    issuerRef:
      name: internal-ca
      kind: ClusterIssuer
      group: cert-manager.io
  allowedRoutes:
    namespaces:
      from: All
    kinds:
      - group: gateway.networking.k8s.io
        kind: HTTPRoute
listeners: {}
additionalServices: {}
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

{{/* Normalize RouteGroupKind defaults so accepted legacy input renders explicitly. */}}
{{- define "fleet.allowedRoutes.resolve" -}}
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
Resolve one fleet: defaults ← values. Usage:
  {{- $f := include "fleet.resolve" (dict "name" $name "spec" $spec) | fromYaml }}
*/}}
{{- define "fleet.resolve" -}}
{{- $d := include "fleet.defaults" . | fromYaml -}}
{{- $f := mergeOverwrite $d (.spec | default dict) -}}
{{- $_ := set $f.healthListener "allowedRoutes" (include "fleet.allowedRoutes.resolve" $f.healthListener.allowedRoutes | fromYaml) -}}
{{- $_ := set $f "name" .name -}}
{{- if not $f.envoyProxy.name }}{{- $_ := set $f.envoyProxy "name" (printf "%s-config" .name) }}{{- end -}}
{{- if not $f.envoyProxy.service.name }}{{- $_ := set $f.envoyProxy.service "name" (printf "gateway-%s" .name) }}{{- end -}}
{{- if not $f.healthListener.name }}{{- $_ := set $f.healthListener "name" .name }}{{- end -}}
{{- if not $f.healthListener.tls.secretName }}{{- $_ := set $f.healthListener.tls "secretName" (printf "%s-health-tls" $f.healthListener.name) }}{{- end -}}
{{- if not $f.networkPolicy.name }}{{- $_ := set $f.networkPolicy "name" (printf "envoy-%s" .name) }}{{- end -}}
{{- toYaml $f -}}
{{- end -}}

{{/*
Resolve one named listener registration. The map key is the stable join key
shared with the consumer registry and supplies deterministic object names.
*/}}
{{- define "fleet.listener.resolve" -}}
{{- $d := dict
  "enabled" true
  "namespace" ""
  "gatewayName" ""
  "annotations" dict
  "labels" dict
  "listenerName" ""
  "hostname" ""
  "allowWildcard" false
  "port" 443
  "protocol" "HTTPS"
  "tls" (dict "secretName" "")
  "certificate" (dict
    "enabled" true
    "annotations" dict
    "labels" dict
    "duration" ""
    "renewBefore" ""
    "privateKey" dict
    "usages" list
    "issuerRef" dict)
  "allowedRoutes" (dict
    "namespaces" (dict "from" "Same")
    "kinds" (list (dict "group" "gateway.networking.k8s.io" "kind" "HTTPRoute")))
  "clientTrafficPolicy" (dict
    "enabled" false
    "name" ""
    "annotations" dict
    "labels" dict
    "tls" (dict "minVersion" "1.3" "maxVersion" "1.3"))
  "infraHealth" (dict
    "enabled" false
    "routeName" ""
    "filterName" ""
    "annotations" dict
    "labels" dict
    "path" "/healthz"
    "statusCode" 200
    "contentType" "text/plain"
    "body" "ok") -}}
{{- $l := mergeOverwrite $d (.spec | default dict) -}}
{{- $_ := set $l "allowedRoutes" (include "fleet.allowedRoutes.resolve" $l.allowedRoutes | fromYaml) -}}
{{- if not $l.namespace }}{{- $_ := set $l "namespace" .fleet.namespace }}{{- end -}}
{{- if not $l.gatewayName }}{{- $_ := set $l "gatewayName" (printf "%s-%s" .fleet.name .name) }}{{- end -}}
{{- if not $l.listenerName }}{{- $_ := set $l "listenerName" (lower $l.protocol) }}{{- end -}}
{{- if not $l.tls.secretName }}{{- $_ := set $l.tls "secretName" (printf "%s-tls" $l.gatewayName) }}{{- end -}}
{{- if not $l.clientTrafficPolicy.name }}{{- $_ := set $l.clientTrafficPolicy "name" (printf "%s-tls" $l.gatewayName) }}{{- end -}}
{{- $healthName := printf "%s-health" $l.gatewayName | trunc 63 | trimSuffix "-" -}}
{{- if not $l.infraHealth.routeName }}{{- $_ := set $l.infraHealth "routeName" $healthName }}{{- end -}}
{{- if not $l.infraHealth.filterName }}{{- $_ := set $l.infraHealth "filterName" $healthName }}{{- end -}}
{{- toYaml $l -}}
{{- end -}}

{{/*
Resolve one chart-owned additional exposure Service. The map key supplies the
stable default name; the selector is intentionally not configurable.
*/}}
{{- define "fleet.additionalService.resolve" -}}
{{- $d := dict
  "enabled" true
  "name" ""
  "type" "ClusterIP"
  "loadBalancerClass" ""
  "annotations" dict
  "labels" dict
  "loadBalancerSourceRanges" list
  "ports" list
  "externalTrafficPolicy" ""
  "internalTrafficPolicy" ""
  "sessionAffinity" ""
  "sessionAffinityConfig" dict
  "ipFamilyPolicy" ""
  "ipFamilies" list
  "externalIPs" list
  "loadBalancerIP" ""
  "healthCheckNodePort" 0
  "trafficDistribution" "" -}}
{{- $s := mergeOverwrite $d (.spec | default dict) -}}
{{- if not $s.name }}{{- $_ := set $s "name" .name }}{{- end -}}
{{- toYaml $s -}}
{{- end -}}

{{/*
Annotations for one object as a YAML map: commonAnnotations ← object
annotations. Empty map → callers skip the key. Usage:
  {{- with include "fleet.annotations" (dict "root" $ "extra" $x.annotations) | fromYaml }}
  annotations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
*/}}
{{- define "fleet.annotations" -}}
{{- mergeOverwrite (deepCopy (.root.Values.commonAnnotations | default dict)) (.extra | default dict) | toYaml -}}
{{- end -}}

{{/*
Pod selector shared by the fleet's proxies — the labels Envoy Gateway stamps.
*/}}
{{- define "fleet.podLabels" -}}
app.kubernetes.io/name: envoy
gateway.envoyproxy.io/owning-gatewayclass: {{ .name }}
{{- end -}}
