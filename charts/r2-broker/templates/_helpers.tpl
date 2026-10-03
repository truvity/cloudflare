{{- define "r2-broker.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "r2-broker.fullname" -}}
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

{{- define "r2-broker.serviceAccountName" -}}
{{- default (include "r2-broker.fullname" .) .Values.serviceAccount.name -}}
{{- end -}}

{{- define "r2-broker.selectorLabels" -}}
app.kubernetes.io/name: {{ include "r2-broker.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: broker
{{- end -}}

{{- define "r2-broker.labels" -}}
{{ include "r2-broker.selectorLabels" . }}
{{- with .Chart.AppVersion }}
app.kubernetes.io/version: {{ . | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "r2-broker.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}

{{/* telemetry.otlp: an http(s) URL naming the collector, and OTEL_* variables
only. The endpoint has a value of its own so that one place sets it, and a
secret reaches a pod through a Secret, never through a value rendered into the
manifest. values.schema.json refuses the same; this keeps the message plain for
a caller that renders with --skip-schema-validation. */}}
{{- define "r2-broker.telemetryChecks" -}}
{{- $otlp := (.Values.telemetry | default dict).otlp | default dict -}}
{{- $endpoint := $otlp.endpoint | default "" -}}
{{- if and $endpoint (not (regexMatch "^https?://[^/?#[:space:]]+" $endpoint)) -}}
{{- fail (printf "r2-broker: telemetry.otlp.endpoint must be an http(s) URL naming the collector or gateway, such as http://gateway.observability.svc:4318 (got %q)." $endpoint) -}}
{{- end -}}
{{- range $name, $_ := ($otlp.extraEnv | default dict) -}}
{{- if eq $name "OTEL_EXPORTER_OTLP_ENDPOINT" -}}
{{- fail "r2-broker: telemetry.otlp.extraEnv must not carry OTEL_EXPORTER_OTLP_ENDPOINT: set telemetry.otlp.endpoint, which is where the chart takes it from." -}}
{{- end -}}
{{- if not (hasPrefix "OTEL_" $name) -}}
{{- fail (printf "r2-broker: telemetry.otlp.extraEnv holds OpenTelemetry SDK variables only: %q does not start with OTEL_." $name) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* The OpenTelemetry SDK environment, as list items, or nothing when no
endpoint is set: the binary exports only when a collector is named (policy
0006), so an empty `telemetry.otlp.endpoint` renders nothing and a release
that never set it is byte-identical to one before the value existed.
`extraEnv` comes last, sorted, so the file is stable. */}}
{{- define "r2-broker.otelEnv" -}}
{{- include "r2-broker.telemetryChecks" . -}}
{{- $o := (.Values.telemetry | default dict).otlp | default dict -}}
{{- if $o.endpoint }}
- name: OTEL_EXPORTER_OTLP_ENDPOINT
  value: {{ $o.endpoint | quote }}
- name: OTEL_EXPORTER_OTLP_PROTOCOL
  value: {{ $o.protocol | default "http/protobuf" | quote }}
- name: OTEL_SERVICE_NAME
  value: "r2-broker"
{{- range $name := keys ($o.extraEnv | default dict) | sortAlpha }}
- name: {{ $name }}
  value: {{ get $o.extraEnv $name | toString | quote }}
{{- end }}
{{- end }}
{{- end -}}
