{{/*
One cluster can need more than one cloudflared: a tunnel cannot cross
Cloudflare accounts, so an estate whose zones live in several accounts runs
one install per account. Every name and the pod selector therefore carry
the release, and two installs can share a namespace without fighting over
each other's pods.
*/}}

{{- define "cloudflared.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "cloudflared.fullname" -}}
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

{{- define "cloudflared.serviceAccountName" -}}
{{- default (include "cloudflared.fullname" .) .Values.serviceAccount.name -}}
{{- end -}}

{{/*
The selector. It is immutable on a live Deployment, so it carries only what
identifies THIS install and never anything that might be retuned later.
*/}}
{{- define "cloudflared.selectorLabels" -}}
app.kubernetes.io/name: {{ include "cloudflared.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: tunnel
{{- end -}}

{{- define "cloudflared.labels" -}}
{{ include "cloudflared.selectorLabels" . }}
{{- with .Chart.AppVersion }}
app.kubernetes.io/version: {{ . | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
