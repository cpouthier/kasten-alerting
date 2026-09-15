{{/*
Common labels applied to every resource this chart creates.
*/}}
{{- define "kasten-alerting.labels" -}}
app.kubernetes.io/name: kasten-alerting
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{/*
Selector labels - "app: kasten-alerting" matching the Deployment/Service
pair 1:1 (single instance per cluster).
*/}}
{{- define "kasten-alerting.selectorLabels" -}}
app: kasten-alerting
{{- end -}}

{{- define "kasten-alerting.image" -}}
{{ .Values.image.registry }}/{{ .Values.image.repository }}:{{ .Values.image.tag }}
{{- end -}}
