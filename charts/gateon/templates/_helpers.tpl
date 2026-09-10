{{/* Copyright (c) 2026 Gembit Soultan Shirazi. SPDX-License-Identifier: MIT */}}

{{- define "gateon.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "gateon.fullname" -}}
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

{{- define "gateon.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "gateon.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "gateon.selectorLabels" -}}
app.kubernetes.io/name: {{ include "gateon.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "gateon.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "gateon.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Guard the one arrangement that loses data quietly.

Each replica keeps its own SQLite database, Pebble trace store and ACME cache on
its own volume. Two replicas on the default storage are therefore two gateways
that agree about nothing: a route added through one dashboard is invisible to the
other, and which one a request reaches is the load balancer's decision. Nothing
errors — it just behaves differently on every other request.

So scaling out requires an external database, and Redis for session revocation to
propagate faster than the binding TTL. Refusing at install time is the whole
point: this is not recoverable by noticing later.
*/}}
{{- define "gateon.validateScaleOut" -}}
{{- if gt (int .Values.replicaCount) 1 -}}
{{- if not .Values.externalDatabase.enabled -}}
{{- fail "replicaCount > 1 requires externalDatabase.enabled=true. Each replica keeps its own SQLite file, so multiple replicas on the default storage silently serve different configuration. Set externalDatabase.* to a shared Postgres/MySQL, or keep replicaCount=1." -}}
{{- end -}}
{{- if not .Values.redis.enabled -}}
{{- fail "replicaCount > 1 requires redis.enabled=true. Without it a session revocation reaches only the replica that handled it, and the others keep honouring the token until their binding TTL expires (30s by default). See doc/adr/0012." -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
GOMEMLIMIT as 80% of the memory limit.

A Go process sized to exactly its cgroup limit gets OOM-killed rather than
collected: GOMEMLIMIT bounds the heap, while the pod's limit covers the heap
plus stacks, the allocator's own metadata and anything mmapped. The 20% is that
gap. Explicit memoryLimit wins; with no limit at all the runtime is left alone,
because guessing a ceiling for an unbounded pod is worse than having none.
*/}}
{{- define "gateon.memoryLimit" -}}
{{- if .Values.memoryLimit -}}
{{- .Values.memoryLimit -}}
{{- else if .Values.resources.limits -}}
{{- if .Values.resources.limits.memory -}}
{{- $mem := .Values.resources.limits.memory | toString -}}
{{- if hasSuffix "Gi" $mem -}}
{{- printf "%dMiB" (div (mul (int (trimSuffix "Gi" $mem)) 1024 80) 100) -}}
{{- else if hasSuffix "Mi" $mem -}}
{{- printf "%dMiB" (div (mul (int (trimSuffix "Mi" $mem)) 80) 100) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Render global.json.

Gateon parses this file with encoding/json against the generated protobuf
structs, so the keys are the `json:` struct tags -- snake_case, e.g.
"database_config". This project has already shipped one bug where the dashboard
wrote camelCase and Go read snake_case, leaving 73 settings inert; the casing
here is not cosmetic.

The database is configured here rather than through the environment because
gateon reads no database env var at all: internal/db.AuthDatabaseURL builds the
DSN from auth.database_config, then auth.database_url, then auth.sqlite_path.
An env-var-shaped chart would have left every replica on SQLite while appearing
to be configured -- which is exactly the split-brain the replica guard exists to
prevent, arriving by a different route.
*/}}
{{- define "gateon.globalConfig" -}}
{{- $cfg := deepCopy (default dict .Values.globalConfig) -}}
{{- if .Values.externalDatabase.enabled -}}
{{- $db := dict "driver" .Values.externalDatabase.driver "host" .Values.externalDatabase.host "port" (int .Values.externalDatabase.port) "database" .Values.externalDatabase.database "user" .Values.externalDatabase.user "ssl_mode" .Values.externalDatabase.sslMode -}}
{{- if .Values.externalDatabase.password -}}
{{- $_ := set $db "password" .Values.externalDatabase.password -}}
{{- end -}}
{{- $auth := merge (dict "database_config" $db) (default dict (get $cfg "auth")) -}}
{{- $_ := set $auth "database_config" (merge $db (default dict (get (default dict (get $cfg "auth")) "database_config"))) -}}
{{- $_ := set $cfg "auth" $auth -}}
{{- end -}}
{{- if .Values.redis.enabled -}}
{{- $redis := merge (dict "enabled" true "addr" .Values.redis.addr "db" (int .Values.redis.db)) (default dict (get $cfg "redis")) -}}
{{- $_ := set $cfg "redis" $redis -}}
{{- end -}}
{{- toPrettyJson $cfg -}}
{{- end -}}

{{- define "gateon.hasGlobalConfig" -}}
{{- if or .Values.globalConfig .Values.externalDatabase.enabled .Values.redis.enabled -}}true{{- end -}}
{{- end -}}

{{/*
Render entrypoints.json from .Values.entrypoints, so the ports the Service
publishes are ports the gateway actually listens on. Without this the Service
forwards to a container that is not bound, and every request times out with
nothing in the logs to say why.

Seeded **once, onto a fresh database** (cmd/gateon/config_seed.go). After the
first start the database is authoritative and the dashboard is where entrypoints
change, so editing this value on an existing install does nothing. That is
gateon's model, not a chart limitation, and it is called out in the README
because a values change that silently no-ops is worse than one that errors.

type/protocol are the EntryPoint enums: type 0 = HTTP, protocol 0 = TCP.
*/}}
{{- define "gateon.entrypointsJSON" -}}
{{- $eps := list -}}
{{- range .Values.entrypoints -}}
{{- $eps = append $eps (dict "id" .name "name" .name "address" (printf ":%v" .targetPort) "type" (int (default 0 .entrypointType)) "protocol" (int (default 0 .entrypointProtocol))) -}}
{{- end -}}
{{- toPrettyJson $eps -}}
{{- end -}}
