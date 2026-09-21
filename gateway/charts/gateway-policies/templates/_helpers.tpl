{{/*
gateway-policies helpers.

Every entry is resolved once, here, into a complete object: defaults first,
then the entry's own values. Templates never test for a missing key, and the
validation template reads exactly what the object templates render.
*/}}

{{/* Annotations for one object: commonAnnotations <- the object's own. */}}
{{- define "policies.annotations" -}}
{{- mergeOverwrite (deepCopy (.root.Values.commonAnnotations | default dict)) (.extra | default dict) | toYaml -}}
{{- end -}}

{{/*
Deep merge where every key the override HAS wins, including an empty value.
Sprig's mergeOverwrite skips "", false and [] in the override, so an entry
could never turn a default off (cookieSameSite: "", forwardAccessToken:
false, ciphers: []). Maps are merged key by key; everything else replaces.
  {{- $x := include "policies.merge" (dict "base" $a "over" $b) | fromYaml }}
*/}}
{{- define "policies.merge" -}}
{{- $out := deepCopy (.base | default dict) -}}
{{- range $k, $v := (.over | default dict) -}}
{{- $cur := get $out $k -}}
{{- if and (kindIs "map" $v) (kindIs "map" $cur) -}}
{{- $_ := set $out $k (include "policies.merge" (dict "base" $cur "over" $v) | fromYaml) -}}
{{- else -}}
{{- $_ := set $out $k $v -}}
{{- end -}}
{{- end -}}
{{- toYaml $out -}}
{{- end -}}

{{/*
The TLS block of a ClientTrafficPolicy. Ciphers apply to TLS 1.2 and older
only, and the API refuses them beside a 1.3 floor, so they are dropped there.

ecdhCurves is NOT dropped at a 1.3 floor: it names the key-exchange groups,
which 1.3 negotiates too. It is also the one TLS value whose default can
refuse a certificate the rest of this chart accepts — see policies.curves.
*/}}
{{- define "policies.tls" -}}
{{- $t := . -}}
{{- $out := dict -}}
{{- with $t.minVersion }}{{- $_ := set $out "minVersion" (toString .) }}{{- end -}}
{{- with $t.maxVersion }}{{- $_ := set $out "maxVersion" (toString .) }}{{- end -}}
{{- if and $t.ciphers (ne (toString ($t.minVersion | default "")) "1.3") }}{{- $_ := set $out "ciphers" $t.ciphers }}{{- end -}}
{{- with $t.ecdhCurves }}{{- $_ := set $out "ecdhCurves" . }}{{- end -}}
{{- toYaml $out -}}
{{- end -}}

{{/*
The curve names this chart will render. Envoy's default list is
X25519:P-256, and a name it does not know is a configuration the proxy
rejects — so a typo would not loosen TLS, it would leave the policy
un-Accepted and the floor unapplied. Refusing the typo here says so at
render time instead.
*/}}
{{- define "policies.curves" -}}
X25519 P-256 P-384 P-521
{{- end -}}

{{/*
Refuse a TLS block whose floor is above its ceiling: no client could connect.
"Auto" is the lowest floor and the highest ceiling, as the API ranks it.
  {{- include "policies.tlsCheck" (dict "tls" $t "where" "tlsBaseline.tls") }}
*/}}
{{- define "policies.tlsCheck" -}}
{{- $t := .tls -}}
{{- $known := splitList " " (include "policies.curves" .) -}}
{{- range $c := ($t.ecdhCurves | default list) -}}
{{- if not (has (toString $c) $known) -}}
{{- fail (printf "%s.ecdhCurves %q is not a curve Envoy names (%s) — the proxy refuses the whole policy, so the floor it carries never applies" $.where (toString $c) (join ", " $known)) -}}
{{- end -}}
{{- end -}}
{{- if and $t.minVersion $t.maxVersion -}}
{{- $min := get (dict "Auto" 0 "1.0" 1 "1.1" 2 "1.2" 3 "1.3" 4) (toString $t.minVersion) -}}
{{- $max := get (dict "1.0" 1 "1.1" 2 "1.2" 3 "1.3" 4 "Auto" 5) (toString $t.maxVersion) -}}
{{- if gt (int $min) (int $max) -}}
{{- fail (printf "%s.minVersion %s is above maxVersion %s — no client could connect" .where (toString $t.minVersion) (toString $t.maxVersion)) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Policy target references with the defaulted fields written out, so a GitOps
controller never diffs its render against the API server's defaults.
  {{- $refs := include "policies.targetRefs" (dict "refs" $x "kind" "HTTPRoute" "group" "gateway.networking.k8s.io") | fromYamlArray }}
*/}}
{{- define "policies.targetRefs" -}}
{{- $out := list -}}
{{- range $ref := .refs -}}
{{- $r := dict "group" (hasKey $ref "group" | ternary $ref.group $.group) "kind" ($ref.kind | default $.kind) "name" ($ref.name | default "") -}}
{{- with $ref.sectionName }}{{- $_ := set $r "sectionName" . }}{{- end -}}
{{- $out = append $out $r -}}
{{- end -}}
{{- toYaml $out -}}
{{- end -}}

{{/* Service references (JWKS backends), with group and kind written out. */}}
{{- define "policies.backendRefs" -}}
{{- $out := list -}}
{{- range $ref := . -}}
{{- $r := dict "group" (hasKey $ref "group" | ternary $ref.group "") "kind" ($ref.kind | default "Service") "name" ($ref.name | default "") -}}
{{- with $ref.namespace }}{{- $_ := set $r "namespace" . }}{{- end -}}
{{- with $ref.port }}{{- $_ := set $r "port" (int .) }}{{- end -}}
{{- $out = append $out $r -}}
{{- end -}}
{{- toYaml $out -}}
{{- end -}}

{{/* remoteJWKS, with only the fields that are set. */}}
{{- define "policies.remoteJWKS" -}}
{{- $out := dict "uri" .uri -}}
{{- with .cacheDuration }}{{- $_ := set $out "cacheDuration" . }}{{- end -}}
{{- with .backendRefs }}{{- $_ := set $out "backendRefs" (include "policies.backendRefs" . | fromYamlArray) }}{{- end -}}
{{- toYaml $out -}}
{{- end -}}

{{/* ------------------------------------------------------------------ */}}
{{/* tlsPolicies                                                          */}}
{{/* ------------------------------------------------------------------ */}}
{{- define "policies.tlsPolicy.defaults" -}}
enabled: true
name: ""
namespace: ""
annotations: {}
labels: {}
targetRefs: []
tls:
  minVersion: "1.3"
  maxVersion: ""
  ciphers: []
{{- end -}}

{{- define "policies.tlsPolicy.resolve" -}}
{{- $p := include "policies.merge" (dict "base" (include "policies.tlsPolicy.defaults" . | fromYaml) "over" .spec) | fromYaml -}}
{{- if not $p.name }}{{- $_ := set $p "name" .key }}{{- end -}}
{{- $_ := set $p "targetRefs" (include "policies.targetRefs" (dict "refs" $p.targetRefs "kind" "Gateway" "group" "gateway.networking.k8s.io") | fromYamlArray) -}}
{{- toYaml $p -}}
{{- end -}}

{{/* ------------------------------------------------------------------ */}}
{{/* securityPolicies                                                     */}}
{{/* ------------------------------------------------------------------ */}}
{{- define "policies.security.defaults" -}}
enabled: true
type: oidc
name: ""
targetRefs: []
extraSpec: {}
{{- end -}}

{{/*
Resolve one securityPolicies entry: built-in <- values.defaults <- the
entry's own. The CSRF mode "" becomes the type's default here, so every
consumer sees the mode that is actually rendered.
  {{- $p := include "policies.security.resolve" (dict "key" $k "spec" $s "root" $) | fromYaml }}
*/}}
{{- define "policies.security.resolve" -}}
{{- $base := include "policies.merge" (dict "base" (include "policies.security.defaults" . | fromYaml) "over" (deepCopy (.root.Values.defaults | default dict))) | fromYaml -}}
{{- $p := include "policies.merge" (dict "base" $base "over" (.spec | default dict)) | fromYaml -}}
{{- if not $p.name }}{{- $_ := set $p "name" .key }}{{- end -}}
{{- if not $p.csrf.mode }}{{- $_ := set $p.csrf "mode" (eq $p.type "oidc" | ternary "shadow" "off") }}{{- end -}}
{{- $_ := set $p "targetRefs" (include "policies.targetRefs" (dict "refs" $p.targetRefs "kind" "HTTPRoute" "group" "gateway.networking.k8s.io") | fromYamlArray) -}}
{{- if eq $p.type "oidc" -}}
{{- $o := $p.oidc -}}
{{- if not $o.redirectURL }}{{- if $o.hostname }}{{- $_ := set $o "redirectURL" (printf "https://%s%s/callback" $o.hostname $o.pathPrefix) }}{{- end }}{{- end -}}
{{- if not $o.logoutPath }}{{- $_ := set $o "logoutPath" (printf "%s/logout" $o.pathPrefix) }}{{- end -}}
{{- if not $o.idToken.audiences }}{{- $_ := set $o.idToken "audiences" (list $o.clientID) }}{{- end -}}
{{- end -}}
{{- toYaml $p -}}
{{- end -}}

{{/*
The SecurityPolicy spec for one resolved entry.
*/}}
{{- define "policies.security.spec" -}}
{{- $p := . -}}
{{- $spec := dict "targetRefs" $p.targetRefs -}}
{{- $providers := list -}}
{{- $authzProvider := "" -}}
{{- if eq $p.type "oidc" -}}
{{- $o := $p.oidc -}}
{{- $provider := dict "issuer" $o.issuer -}}
{{- with $o.authorizationEndpoint }}{{- $_ := set $provider "authorizationEndpoint" . }}{{- end -}}
{{- with $o.tokenEndpoint }}{{- $_ := set $provider "tokenEndpoint" . }}{{- end -}}
{{- with $o.endSessionEndpoint }}{{- $_ := set $provider "endSessionEndpoint" . }}{{- end -}}
{{- /* group and kind are written out: an undeclared API-server default is
       a permanent GitOps diff. */ -}}
{{- $oidc := dict
      "provider" $provider
      "clientID" (toString $o.clientID)
      "clientSecret" (dict "group" "" "kind" "Secret" "name" $o.clientSecret.name)
      "redirectURL" $o.redirectURL
      "logoutPath" $o.logoutPath
      "scopes" $o.scopes
      "refreshToken" $o.refreshToken -}}
{{- with $o.cookieSameSite }}{{- $_ := set $oidc "cookieConfig" (dict "sameSite" .) }}{{- end -}}
{{- if $o.forwardAccessToken }}{{- $_ := set $oidc "forwardAccessToken" true }}{{- end -}}
{{- if $o.idToken.enabled -}}
{{- $_ := set $oidc "forwardIDToken" (dict "header" $o.idToken.header) -}}
{{- $jp := dict
      "name" $o.idToken.providerName
      "issuer" $o.issuer
      "audiences" (include "policies.stringList" $o.idToken.audiences | fromYamlArray)
      "remoteJWKS" (include "policies.remoteJWKS" $o.idToken.remoteJWKS | fromYaml)
      "extractFrom" (dict "headers" (list (dict "name" $o.idToken.header))) -}}
{{- with $o.idToken.claimToHeaders }}{{- $_ := set $jp "claimToHeaders" . }}{{- end -}}
{{- $providers = append $providers $jp -}}
{{- $authzProvider = $o.idToken.providerName -}}
{{- end -}}
{{- $_ := set $spec "oidc" $oidc -}}
{{- else -}}
{{- $j := $p.jwt -}}
{{- $jp := dict
      "name" $j.providerName
      "issuer" $j.issuer
      "audiences" (include "policies.stringList" $j.audiences | fromYamlArray)
      "remoteJWKS" (include "policies.remoteJWKS" $j.remoteJWKS | fromYaml) -}}
{{- with $j.extractFrom }}{{- $_ := set $jp "extractFrom" . }}{{- end -}}
{{- with $j.claimToHeaders }}{{- $_ := set $jp "claimToHeaders" . }}{{- end -}}
{{- $providers = append $providers $jp -}}
{{- $authzProvider = $j.providerName -}}
{{- end -}}
{{- with $providers }}{{- $_ := set $spec "jwt" (dict "providers" .) }}{{- end -}}
{{- $c := $p.csrf -}}
{{- if ne $c.mode "off" -}}
{{- $csrf := dict -}}
{{- if eq $c.mode "shadow" -}}
{{- $_ := set $csrf "shadowFraction" (dict "numerator" (int $c.shadowFraction.numerator) "denominator" (int $c.shadowFraction.denominator)) -}}
{{- end -}}
{{- with $c.additionalOrigins }}{{- $_ := set $csrf "additionalOrigins" (include "policies.stringList" . | fromYamlArray) }}{{- end -}}
{{- $_ := set $spec "csrf" $csrf -}}
{{- end -}}
{{- $a := $p.authorization -}}
{{- if eq $a.posture "groups" -}}
{{- $claim := dict "name" $a.claim "valueType" "StringArray" "values" (include "policies.stringList" $a.groups | fromYamlArray) -}}
{{- $rule := dict "name" $a.ruleName "action" "Allow" "principal" (dict "jwt" (dict "provider" $authzProvider "claims" (list $claim))) -}}
{{- $_ := set $spec "authorization" (dict "defaultAction" "Deny" "rules" (list $rule)) -}}
{{- end -}}
{{- $spec = include "policies.merge" (dict "base" $spec "over" $p.extraSpec) | fromYaml -}}
{{- toYaml $spec -}}
{{- end -}}

{{/* A list of strings, each forced to a string (a numeric client id stays text). */}}
{{- define "policies.stringList" -}}
{{- $out := list -}}
{{- range . }}{{- $out = append $out (toString .) }}{{- end -}}
{{- toYaml $out -}}
{{- end -}}

{{/* ------------------------------------------------------------------ */}}
{{/* backendTLSPolicies                                                   */}}
{{/* ------------------------------------------------------------------ */}}
{{- define "policies.backendTLS.defaults" -}}
enabled: true
name: ""
namespace: ""
annotations: {}
labels: {}
targetRefs: []
hostname: ""
caCertificateRefs: []
wellKnownCACertificates: ""
subjectAltNames: []
{{- end -}}

{{- define "policies.backendTLS.resolve" -}}
{{- $p := include "policies.merge" (dict "base" (include "policies.backendTLS.defaults" . | fromYaml) "over" .spec) | fromYaml -}}
{{- if not $p.name }}{{- $_ := set $p "name" .key }}{{- end -}}
{{- $_ := set $p "targetRefs" (include "policies.targetRefs" (dict "refs" $p.targetRefs "kind" "Service" "group" "") | fromYamlArray) -}}
{{- $refs := list -}}
{{- range $ref := $p.caCertificateRefs -}}
{{- $refs = append $refs (dict "group" "" "kind" ($ref.kind | default "ConfigMap") "name" ($ref.name | default "")) -}}
{{- end -}}
{{- $_ := set $p "caCertificateRefs" $refs -}}
{{- toYaml $p -}}
{{- end -}}

{{/*
Claim one object identity in a registry, failing when two entries collide.
A dict is a reference, so the registry accumulates across one render.
*/}}
{{- define "policies.claim" -}}
{{- $key := printf "%s/%s/%s" .kind .namespace .name -}}
{{- if hasKey .registry $key -}}
{{- fail (printf "%s %s/%s is claimed by both %s and %s — two objects cannot share one name" .kind .namespace .name (get .registry $key) .by) -}}
{{- end -}}
{{- $_ := set .registry $key .by -}}
{{- end -}}
