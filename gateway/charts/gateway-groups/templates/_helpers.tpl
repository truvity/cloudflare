{{/*
gateway-groups helpers.

A group is one project's claim on an exposure: the hostnames it serves and
the namespaces whose routes may attach to them. It renders as a ListenerSet
parented to the exposure's Gateway, one listener and one Certificate per
domain, and optionally a BackendTLSPolicy and the ingress rule that lets the
fleet reach the group's workloads.

Only standard Gateway API, cert-manager and core Kubernetes objects are
rendered here. Everything vendor-specific belongs to the fleet chart, so a
change of gateway implementation leaves this half untouched.
*/}}

{{- define "groups.annotations" -}}
{{- mergeOverwrite (deepCopy (.root.Values.commonAnnotations | default dict)) (.extra | default dict) | toYaml -}}
{{- end -}}

{{/*
A DNS name as a Kubernetes object-name fragment. The wildcard label becomes
a word, because "*" is not a name character and dropping it would make
*.example.com and example.com collide.
*/}}
{{- define "groups.slug" -}}
{{- . | replace "*." "wildcard-" | replace "*" "wildcard" | replace "." "-" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "groups.defaults" -}}
namespace: envoy-gateway-system
parent:
  name: ""
  namespace: ""
port: 443
protocol: HTTPS
certificate:
  enabled: true
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
{{- end -}}

{{- define "groups.group.defaults" -}}
enabled: true
listenerSetName: ""
annotations: {}
labels: {}
domains: []
backendTLS:
  enabled: false
  name: ""
  annotations: {}
  labels: {}
  targetRefs: []
  validation: {}
networkPolicy:
  enabled: false
  name: ""
  annotations: {}
  namespaces: []
  podSelector: {}
  from:
    namespace: ""
    podLabels: {}
  ports: []
{{- end -}}

{{/*
Resolve one group: chart defaults ← values.defaults ← the group's own.
  {{- $g := include "groups.resolve" (dict "name" $n "spec" $s "root" $) | fromYaml }}
*/}}
{{- define "groups.resolve" -}}
{{- $d := mergeOverwrite (include "groups.defaults" . | fromYaml) (include "groups.group.defaults" . | fromYaml) -}}
{{- $d = mergeOverwrite $d (deepCopy (.root.Values.defaults | default dict)) -}}
{{- $g := mergeOverwrite $d (.spec | default dict) -}}
{{- $_ := set $g "name" .name -}}
{{- if not $g.listenerSetName }}{{- $_ := set $g "listenerSetName" .name }}{{- end -}}
{{- if not $g.parent.namespace }}{{- $_ := set $g.parent "namespace" $g.namespace }}{{- end -}}
{{- if not $g.backendTLS.name }}{{- $_ := set $g.backendTLS "name" $g.listenerSetName }}{{- end -}}
{{- if not $g.networkPolicy.name }}{{- $_ := set $g.networkPolicy "name" (printf "allow-gateway-%s" .name | trunc 63 | trimSuffix "-") }}{{- end -}}
{{- toYaml $g -}}
{{- end -}}

{{/*
Resolve one entry of a group's `domains` into {host, listenerName,
secretName, certificate}. A plain string is the common case; an object lets
one domain of a group carry its own names — which is what a rename needs,
where the old and the new host live in one group through the overlap.
  {{- $d := include "groups.domain.resolve" (dict "entry" $x "group" $g) | fromYaml }}
*/}}
{{- define "groups.domain.resolve" -}}
{{- $entry := .entry -}}
{{- if kindIs "string" $entry }}{{- $entry = dict "host" $entry }}{{- end -}}
{{- $host := $entry.host | default "" -}}
{{- $slug := include "groups.slug" $host -}}
{{- $d := dict
  "host" $host
  "listenerName" ($entry.listenerName | default $slug)
  "secretName" ($entry.secretName | default (printf "%s-tls" $slug | trunc 63 | trimSuffix "-"))
  "certificateName" ($entry.certificateName | default "") -}}
{{- $_ := set $d "certificate" (mergeOverwrite (deepCopy .group.certificate) ($entry.certificate | default dict)) -}}
{{- if not $d.certificateName }}{{- $_ := set $d "certificateName" $d.secretName }}{{- end -}}
{{- toYaml $d -}}
{{- end -}}

{{/* Normalize RouteGroupKind entries so a short form renders explicitly. */}}
{{- define "groups.allowedRoutes.resolve" -}}
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
Claim one object identity, failing when two groups collide. Two groups
sharing a Secret is the mistake that matters: cert-manager would have two
Certificates reconciling one object, and the survivor is a race.
*/}}
{{- define "groups.claim" -}}
{{- $key := printf "%s/%s/%s" .kind .namespace .name -}}
{{- if hasKey .registry $key -}}
{{- fail (printf "%s %s/%s is claimed by both %s and %s — two objects cannot share one name" .kind .namespace .name (get .registry $key) .by) -}}
{{- end -}}
{{- $_ := set .registry $key .by -}}
{{- end -}}
