{{/*
gateway-routes — one HTTPRoute whose rules are NAMED.

An application that people sign in to is two surfaces on one hostname: a
gated one (the shell, the API) and, usually, a public one (the
content-hashed assets the shell loads). Splitting them into two HTTPRoutes
works, but then the split lives in the application's chart and the platform
has to know both route names to protect one of them. Naming the rules keeps
the split in one object: a SecurityPolicy targets the route with
`sectionName: app`, and every rule it does not name is served anonymously.

The rule names `app` and `static` are a CONTRACT, not a label. Whatever
generates the policies targets `app` by that name; renaming a rule here
silently drops the gate, because a policy whose sectionName matches nothing
is rejected by the controller and the route keeps serving. Extra rules a
caller adds are public for the same reason: nothing targets them.

Envoy matches the MOST SPECIFIC path prefix, not the first one written, so
`static`'s `/app/assets` wins over `app`'s `/` with no ordering tricks and
no per-rule priority. The rules are rendered in the order app, static,
extras because that is the order they are worth reading in.

Every define here is prefixed with the chart name. A library chart's
templates are compiled into the CONSUMING chart's namespace, where a short
name would collide with the application's own helpers.
*/}}

{{/*
Deep merge where every key the override HAS wins, including an empty value.
Sprig's mergeOverwrite skips "", false and [] in the override, so a rule
could never turn a default off. Maps are merged key by key; everything else
replaces.
*/}}
{{- define "gateway-routes.merge" -}}
{{- $out := deepCopy (.base | default dict) -}}
{{- range $k, $v := (.over | default dict) -}}
{{- $cur := get $out $k -}}
{{- if and (kindIs "map" $v) (kindIs "map" $cur) -}}
{{- $_ := set $out $k (include "gateway-routes.merge" (dict "base" $cur "over" $v) | fromYaml) -}}
{{- else -}}
{{- $_ := set $out $k $v -}}
{{- end -}}
{{- end -}}
{{- toYaml $out -}}
{{- end -}}

{{/*
Refuse a key nobody reads. A library template takes a dict, so it has no
values.schema.json to catch a misspelling for it — and a misspelt
`hostnames` or `static` would render a route that quietly serves something
other than what the caller wrote.
  {{- include "gateway-routes.knownKeys" (dict "in" $x "known" (list ...) "where" "route") }}
*/}}
{{- define "gateway-routes.knownKeys" -}}
{{- range $k, $v := .in -}}
{{- if not (has $k $.known) -}}
{{- fail (printf "%s.%s is not a key this template reads — known keys: %s" $.where $k (join ", " $.known)) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* The built-in inputs, before the caller's. */}}
{{- define "gateway-routes.productRoute.defaults" -}}
enabled: true
name: ""
namespace: ""
annotations: {}
labels: {}
hostnames: []
parentRefs: []
backend: {}
app:
  paths:
    - /
  backend: {}
  filters: []
  extra: {}
static:
  paths: []
  backend: {}
  filters: []
  extra: {}
extraRules: []
{{- end -}}

{{/*
One resolved rule: the caller's rule input over the route's shared backend,
with the fields the API server would default written out — an undeclared
default inside a list item is a permanent GitOps diff.
  {{- $r := include "gateway-routes.rule" (dict "name" "app" "in" $x "backend" $b "where" "route.app") | fromYaml }}
*/}}
{{- define "gateway-routes.rule" -}}
{{- $in := .in | default dict -}}
{{- $b := include "gateway-routes.merge" (dict "base" (dict "group" "" "kind" "Service" "name" "" "port" 0 "weight" 1) "over" (include "gateway-routes.merge" (dict "base" .backend "over" ($in.backend | default dict)) | fromYaml)) | fromYaml -}}
{{- include "gateway-routes.knownKeys" (dict "in" $b "known" (list "group" "kind" "name" "port" "weight") "where" (printf "%s.backend" .where)) -}}
{{- if not $b.name -}}
{{- fail (printf "%s.backend.name is required (or route.backend.name) — a rule with no backend routes nothing" .where) -}}
{{- end -}}
{{- if or (le (int $b.port) 0) (gt (int $b.port) 65535) -}}
{{- fail (printf "%s.backend.port %v is not a port (or route.backend.port) — the Service port the rule sends to" .where $b.port) -}}
{{- end -}}
{{- $matches := list -}}
{{- range $p := ($in.paths | default list) -}}
{{- $matches = append $matches (dict "path" (dict "type" "PathPrefix" "value" $p)) -}}
{{- end -}}
{{- $rule := dict
      "name" .name
      "matches" $matches
      "backendRefs" (list (dict "group" $b.group "kind" $b.kind "name" $b.name "port" (int $b.port) "weight" (int $b.weight))) -}}
{{- with $in.filters }}{{- $_ := set $rule "filters" . }}{{- end -}}
{{- toYaml (include "gateway-routes.merge" (dict "base" $rule "over" ($in.extra | default dict)) | fromYaml) -}}
{{- end -}}

{{/* Paths are prefixes: absolute, and for a public rule never the whole site. */}}
{{- define "gateway-routes.checkPaths" -}}
{{- if eq (len .paths) 0 -}}
{{- fail (printf "%s.paths is empty — a rule with no path matches" .where) -}}
{{- end -}}
{{- range $p := .paths -}}
{{- if not (hasPrefix "/" $p) -}}
{{- fail (printf "%s.paths has %q — a path prefix starts with /" $.where $p) -}}
{{- end -}}
{{- if and $.public (eq $p "/") -}}
{{- fail (printf "%s.paths has \"/\" — this rule carries no policy, so a prefix of / would serve the whole application, shell and API included, to anyone; put the gated surface on the app rule" $.where) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
One HTTPRoute for one application: rule `app` gated, rule `static` public.

  {{ include "gateway-routes.productRoute" (dict "root" $ "route" .Values.route) }}

`root` is the consuming chart's context ($), used for the release namespace
alone; `route` is the input described in this chart's values.yaml and
README.
*/}}
{{- define "gateway-routes.productRoute" -}}
{{- $root := .root -}}
{{- if not $root -}}
{{- fail "gateway-routes.productRoute needs root: the consuming chart's context, as (dict \"root\" $ \"route\" .Values.route)" -}}
{{- end -}}
{{- $in := .route | default dict -}}
{{- include "gateway-routes.knownKeys" (dict "in" $in "known" (list "enabled" "name" "namespace" "annotations" "labels" "hostnames" "parentRefs" "backend" "app" "static" "extraRules") "where" "route") -}}
{{- $r := include "gateway-routes.merge" (dict "base" (include "gateway-routes.productRoute.defaults" . | fromYaml) "over" $in) | fromYaml -}}
{{- if $r.enabled -}}
{{- if not $r.name -}}
{{- fail "route.name is required — the HTTPRoute's object name" -}}
{{- end -}}
{{- if not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?([.][a-z0-9]([-a-z0-9]*[a-z0-9])?)*$" $r.name) -}}
{{- fail (printf "route.name %q is not a DNS subdomain — it is an object name" $r.name) -}}
{{- end -}}
{{- if eq (len $r.hostnames) 0 -}}
{{- fail "route.hostnames is empty — a route with no hostname is attached to everything its parent serves, which is never what an application means" -}}
{{- end -}}
{{- range $h := $r.hostnames -}}
{{- if not (regexMatch "^([*][.])?[a-z0-9]([-a-z0-9]*[a-z0-9])?([.][a-z0-9]([-a-z0-9]*[a-z0-9])?)*$" $h) -}}
{{- fail (printf "route.hostnames has %q, which is not a hostname (one leading \"*.\" is allowed)" $h) -}}
{{- end -}}
{{- end -}}
{{- if eq (len $r.parentRefs) 0 -}}
{{- fail "route.parentRefs is empty — name the Gateway or ListenerSet the route attaches to; the platform decides which hostnames exist there" -}}
{{- end -}}
{{- $parents := list -}}
{{- range $p := $r.parentRefs -}}
{{- include "gateway-routes.knownKeys" (dict "in" $p "known" (list "group" "kind" "name" "namespace" "sectionName" "port") "where" "route.parentRefs[]") -}}
{{- if not $p.name -}}
{{- fail "route.parentRefs has an entry with no name" -}}
{{- end -}}
{{- $out := dict "group" (hasKey $p "group" | ternary $p.group "gateway.networking.k8s.io") "kind" ($p.kind | default "Gateway") "name" $p.name -}}
{{- with $p.namespace }}{{- $_ := set $out "namespace" . }}{{- end -}}
{{- with $p.sectionName }}{{- $_ := set $out "sectionName" . }}{{- end -}}
{{- with $p.port }}{{- $_ := set $out "port" (int .) }}{{- end -}}
{{- $parents = append $parents $out -}}
{{- end -}}
{{- include "gateway-routes.knownKeys" (dict "in" $r.backend "known" (list "group" "kind" "name" "port" "weight") "where" "route.backend") -}}
{{- /* The gated surface. Its default prefix is "/": everything the more
       specific rules below do not claim belongs to the application, so a
       new endpoint is gated by default rather than exposed by omission. */ -}}
{{- include "gateway-routes.knownKeys" (dict "in" ($in.app | default dict) "known" (list "paths" "backend" "filters" "extra") "where" "route.app") -}}
{{- include "gateway-routes.checkPaths" (dict "paths" $r.app.paths "public" false "where" "route.app") -}}
{{- $rules := list (include "gateway-routes.rule" (dict "name" "app" "in" $r.app "backend" $r.backend "where" "route.app") | fromYaml) -}}
{{- /* The public surface. Rendered only when the caller gives it prefixes:
       an application whose assets are served from the gated surface is
       slower, not broken, and an empty public rule would be a rule that
       matches nothing. */ -}}
{{- include "gateway-routes.knownKeys" (dict "in" ($in.static | default dict) "known" (list "paths" "backend" "filters" "extra") "where" "route.static") -}}
{{- if and (not $r.static.paths) (gt (len (omit ($in.static | default dict) "paths")) 0) -}}
{{- fail "route.static carries settings but no paths — the rule is not rendered at all, so a backend or a filter there is a public surface someone believes exists" -}}
{{- end -}}
{{- if $r.static.paths -}}
{{- include "gateway-routes.checkPaths" (dict "paths" $r.static.paths "public" true "where" "route.static") -}}
{{- $rules = append $rules (include "gateway-routes.rule" (dict "name" "static" "in" $r.static "backend" $r.backend "where" "route.static") | fromYaml) -}}
{{- end -}}
{{- /* Further anonymous surfaces of the same application on the same
       hostname — a redirect, a well-known document. They are public for
       the same reason `static` is: no policy names them. */ -}}
{{- $names := dict "app" true "static" true -}}
{{- range $i, $extra := $r.extraRules -}}
{{- $where := printf "route.extraRules[%d]" $i -}}
{{- include "gateway-routes.knownKeys" (dict "in" $extra "known" (list "name" "paths" "backend" "filters" "extra") "where" $where) -}}
{{- if not $extra.name -}}
{{- fail (printf "%s.name is required — an unnamed rule cannot be targeted, and cannot be told apart in a status condition" $where) -}}
{{- end -}}
{{- if hasKey $names $extra.name -}}
{{- fail (printf "%s.name %q is already used — rule names are unique within a route, and `app` and `static` are this template's own" $where $extra.name) -}}
{{- end -}}
{{- if not (regexMatch "^[A-Za-z0-9]([-A-Za-z0-9_.]{0,251}[A-Za-z0-9])?$" $extra.name) -}}
{{- fail (printf "%s.name %q is not a section name — a policy targets a rule by this string" $where $extra.name) -}}
{{- end -}}
{{- $_ := set $names $extra.name true -}}
{{- include "gateway-routes.checkPaths" (dict "paths" ($extra.paths | default list) "public" true "where" $where) -}}
{{- $rules = append $rules (include "gateway-routes.rule" (dict "name" $extra.name "in" $extra "backend" $r.backend "where" $where) | fromYaml) -}}
{{- end -}}
{{- $spec := dict "parentRefs" $parents "hostnames" $r.hostnames "rules" $rules -}}
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: {{ $r.name }}
  namespace: {{ $r.namespace | default $root.Release.Namespace }}
  {{- with $r.annotations }}
  annotations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with $r.labels }}
  labels:
    {{- toYaml . | nindent 4 }}
  {{- end }}
spec:
  {{- toYaml $spec | nindent 2 }}
{{- end -}}
{{- end -}}
