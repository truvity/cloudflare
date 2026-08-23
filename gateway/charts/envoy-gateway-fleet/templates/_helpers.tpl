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
Resolve one fleet: defaults ← values. Usage:
  {{- $f := include "fleet.resolve" (dict "name" $name "spec" $spec) | fromYaml }}
*/}}
{{- define "fleet.resolve" -}}
{{- $d := include "fleet.defaults" . | fromYaml -}}
{{- $f := mergeOverwrite $d (.spec | default dict) -}}
{{- $_ := set $f "name" .name -}}
{{- if not $f.envoyProxy.name }}{{- $_ := set $f.envoyProxy "name" (printf "%s-config" .name) }}{{- end -}}
{{- if not $f.envoyProxy.service.name }}{{- $_ := set $f.envoyProxy.service "name" (printf "gateway-%s" .name) }}{{- end -}}
{{- if not $f.healthListener.name }}{{- $_ := set $f.healthListener "name" .name }}{{- end -}}
{{- if not $f.healthListener.tls.secretName }}{{- $_ := set $f.healthListener.tls "secretName" (printf "%s-health-tls" $f.healthListener.name) }}{{- end -}}
{{- if not $f.networkPolicy.name }}{{- $_ := set $f.networkPolicy "name" (printf "envoy-%s" .name) }}{{- end -}}
{{- toYaml $f -}}
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
