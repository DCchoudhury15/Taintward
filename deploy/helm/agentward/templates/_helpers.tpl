{{- define "agentward.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "agentward.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "agentward.collector.fullname" -}}
{{- printf "%s-collector" (include "agentward.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "agentward.routing.fullname" -}}
{{- printf "%s-routing" (include "agentward.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "agentward.gateway.fullname" -}}
{{- printf "%s-gateway" (include "agentward.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "agentward.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "agentward.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/* Selector labels. Call with (dict "ctx" $ "component" "collector"). */}}
{{- define "agentward.selectorLabels" -}}
app.kubernetes.io/name: {{ include "agentward.name" .ctx }}
app.kubernetes.io/instance: {{ .ctx.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{- define "agentward.policy" -}}
{{- if .Values.collector.policy.rego }}
{{- .Values.collector.policy.rego }}
{{- else }}
{{- .Files.Get "files/pii_egress.rego" }}
{{- end }}
{{- end }}

{{/* Generated config for the policy collector tier. */}}
{{- define "agentward.collector.config" -}}
{{- $c := .Values.collector -}}
{{- $e := .Values.exporter -}}
{{- $backend := ternary "otlp_http/backend" "otlp_grpc/backend" (eq $e.protocol "http") -}}
{{- $exporters := list $backend -}}
{{- if $c.fileExport.enabled }}{{ $exporters = append $exporters "file" }}{{ end -}}
{{- if $c.debugExporter }}{{ $exporters = append $exporters "debug" }}{{ end -}}
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4319
      grpc:
        endpoint: 0.0.0.0:4317
extensions:
  health_check:
    endpoint: 0.0.0.0:13133
processors:
  memory_limiter:
    check_interval: 1s
    limit_percentage: {{ $c.memoryLimiter.limitPercentage }}
    spike_limit_percentage: {{ $c.memoryLimiter.spikeLimitPercentage }}
  taint_policy:
    policy_path: /etc/agentward/policy/pii_egress.rego
  batch:
    timeout: {{ $c.batch.timeout }}
    send_batch_size: {{ $c.batch.sendBatchSize }}
    send_batch_max_size: {{ $c.batch.sendBatchMaxSize }}
exporters:
  {{ $backend }}:
    endpoint: {{ required "exporter.endpoint is required" $e.endpoint | quote }}
    tls:
      insecure: {{ $e.insecure }}
    {{- with $e.headers }}
    headers:
      {{- toYaml . | nindent 6 }}
    {{- end }}
    sending_queue:
      enabled: true
    retry_on_failure:
      enabled: true
  {{- if $c.fileExport.enabled }}
  file:
    path: {{ $c.fileExport.path }}
    format: json
    create_directory: true
    rotation:
      max_megabytes: {{ $c.fileExport.maxMegabytes }}
      max_backups: {{ $c.fileExport.maxBackups }}
  {{- end }}
  {{- if $c.debugExporter }}
  debug:
    verbosity: basic
  {{- end }}
service:
  extensions: [health_check]
  telemetry:
    logs:
      level: info
  pipelines:
    traces:
      receivers: [otlp]
      # taint_policy runs before batch (batching clears request context).
      processors: [memory_limiter, taint_policy, batch]
      exporters: [{{ join ", " $exporters }}]
{{- end }}

{{/* Config for the optional routing tier (same as collector/config.gateway-tier.yaml). */}}
{{- define "agentward.routing.config" -}}
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4319
      grpc:
        endpoint: 0.0.0.0:4317
extensions:
  health_check:
    endpoint: 0.0.0.0:13133
processors:
  memory_limiter:
    check_interval: 1s
    limit_percentage: 80
    spike_limit_percentage: 20
exporters:
  load_balancing:
    routing_key: traceID
    # Top level queue and retry: when a policy pod goes away (rollout, scale
    # in), data that could not reach it comes back here and is routed again
    # over the new set of pods instead of being dropped.
    timeout: 20s
    retry_on_failure:
      enabled: true
      max_elapsed_time: 120s
    sending_queue:
      enabled: true
      queue_size: {{ .Values.routingTier.queueSize }}
    protocol:
      otlp:
        tls:
          insecure: true
        timeout: 5s
        # Fail fast per pod and hand the data back to the top level queue.
        retry_on_failure:
          enabled: true
          max_interval: 2s
          max_elapsed_time: 10s
        sending_queue:
          enabled: false
    resolver:
      dns:
        hostname: {{ include "agentward.collector.fullname" . }}-headless.{{ .Release.Namespace }}.svc.cluster.local
        port: "4317"
        interval: 5s
service:
  extensions: [health_check]
  telemetry:
    logs:
      level: info
  pipelines:
    traces:
      receivers: [otlp]
      processors: [memory_limiter]
      exporters: [load_balancing]
{{- end }}

{{/* Shared container security settings. */}}
{{- define "agentward.containerSecurity" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: ["ALL"]
{{- end }}
