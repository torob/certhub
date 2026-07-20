{{/*
Return the chart name used in resource names and labels.
*/}}
{{- define "certhub-operator.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{/*
Return the default namespaced resource name. The default preserves the chart's
existing <release>-certhub-operator naming for ordinary release names.
*/}}
{{- define "certhub-operator.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "certhub-operator.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end }}

{{/*
Cluster-scoped resources must remain unique when the same release name is used
in multiple namespaces.
*/}}
{{- define "certhub-operator.clusterFullname" -}}
{{- $fullname := include "certhub-operator.fullname" . -}}
{{- $identity := printf "%s/%s/%s" .Release.Namespace .Release.Name $fullname -}}
{{- $hash := sha256sum $identity | trunc 8 -}}
{{- printf "%s-%s" ($fullname | trunc 54 | trimSuffix "-") $hash -}}
{{- end }}

{{/*
Namespaced RBAC can live outside the Helm release namespace. Include a stable
release identity hash in that case so two releases cannot take ownership of the
same Role or RoleBinding in a shared target namespace.
*/}}
{{- define "certhub-operator.namespacedRBACName" -}}
{{- $root := index . 0 -}}
{{- $targetNamespace := index . 1 -}}
{{- $baseName := index . 2 -}}
{{- if eq $targetNamespace $root.Release.Namespace -}}
{{- $baseName -}}
{{- else -}}
{{- $identity := printf "%s/%s/%s/%s" $root.Release.Namespace $root.Release.Name $targetNamespace $baseName -}}
{{- $hash := sha256sum $identity | trunc 8 -}}
{{- printf "%s-%s" ($baseName | trunc 54 | trimSuffix "-") $hash -}}
{{- end -}}
{{- end }}

{{- define "certhub-operator.serviceAccountName" -}}
{{- if .Values.serviceAccount.name -}}
{{- .Values.serviceAccount.name -}}
{{- else -}}
{{- include "certhub-operator.fullname" . -}}
{{- end -}}
{{- end }}

{{- define "certhub-operator.metricsServiceName" -}}
{{- $fullname := include "certhub-operator.fullname" . -}}
{{- printf "%s-metrics" ($fullname | trunc 55 | trimSuffix "-") -}}
{{- end }}

{{- define "certhub-operator.tokenRBACName" -}}
{{- $fullname := include "certhub-operator.fullname" . -}}
{{- printf "%s-token" ($fullname | trunc 57 | trimSuffix "-") -}}
{{- end }}

{{- define "certhub-operator.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{- define "certhub-operator.selectorLabels" -}}
app.kubernetes.io/name: {{ include "certhub-operator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "certhub-operator.labels" -}}
helm.sh/chart: {{ include "certhub-operator.chart" . }}
{{ include "certhub-operator.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: certhub
{{- end }}

{{- define "certhub-operator.image" -}}
{{- if and .Values.image.tag .Values.image.digest -}}
{{- fail "image.tag and image.digest cannot both be set" -}}
{{- end -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
{{- end }}
