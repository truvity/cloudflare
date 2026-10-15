{{- define "static-site.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "static-site.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "static-site.serviceAccountName" -}}
{{- default (include "static-site.fullname" .) .Values.serviceAccount.name -}}
{{- end -}}

{{/* The selector is immutable on a live Deployment: identity only. */}}
{{- define "static-site.selectorLabels" -}}
app.kubernetes.io/name: {{ include "static-site.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "static-site.labels" -}}
{{ include "static-site.selectorLabels" . }}
{{- with .Chart.AppVersion }}
app.kubernetes.io/version: {{ . | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "static-site.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- if .Values.image.digest -}}
{{- printf "%s:%s@%s" .Values.image.repository $tag .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}
{{- end -}}

{{/* The placeholder file; its checksum rolls the pods when a value changes. */}}
{{- define "static-site.placeholders" -}}
{{- toPrettyJson (include "static-site.inlinePlaceholders" . | fromJson) -}}
{{- end -}}

{{/* The inline name -> value placeholders: placeholders minus the Secret keys. */}}
{{- define "static-site.inlinePlaceholders" -}}
{{- toJson (omit (default dict .Values.placeholders) "secretName" "secretKeys" "optionalKeys") -}}
{{- end -}}

{{/* Refuse a Secret source that declares no names. */}}
{{- define "static-site.validatePlaceholders" -}}
{{- if .Values.placeholders.secretName -}}
{{- if not (or .Values.placeholders.secretKeys .Values.placeholders.optionalKeys) -}}
{{- fail "placeholders.secretName needs placeholders.secretKeys or placeholders.optionalKeys: the names the Secret provides" -}}
{{- end -}}
{{- end -}}
{{- if or .Values.placeholders.secretKeys .Values.placeholders.optionalKeys -}}
{{- if not .Values.placeholders.secretName -}}
{{- fail "placeholders.secretKeys and placeholders.optionalKeys need placeholders.secretName" -}}
{{- end -}}
{{- end -}}
{{- end -}}
