{{- define "honeynet.name" -}}
honeynet-control-plane
{{- end -}}

{{- define "honeynet.fullname" -}}
{{- if .Values.namespaceOverride -}}
{{ .Values.namespaceOverride }}-{{ include "honeynet.name" . }}
{{- else -}}
{{ include "honeynet.name" . }}
{{- end -}}
{{- end -}}

{{- define "honeynet.labels" -}}
app.kubernetes.io/name: {{ include "honeynet.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

