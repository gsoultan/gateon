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
Refuse more than one replica (ADR 0056).

The chart used to allow it with an external database and Redis. The database
was then shared, but each replica still kept its own global.json on its own
volume, so the global settings were per replica: setup ran on one, and only
that one had auth.enabled, the audit log on, the management bind setup chose,
and every setting saved in its dashboard afterwards. The others kept the seed.
Which replica a request reached decided which gateway answered it, and nothing
errored.

The identity secrets the replicas also used to disagree on now come from the
Secret this chart creates (GATEON_SESSION_KEY and its two siblings), so a
session and a second factor are the same on every pod. The global settings are
not: they live in global.json, and until they live in the shared database a
second replica is a second gateway. Refusing at install time is the point --
this is not recoverable by noticing later. `kubectl scale` bypasses this check;
do not.
*/}}
{{- define "gateon.validateScaleOut" -}}
{{- if gt (int .Values.replicaCount) 1 -}}
{{- fail "replicaCount > 1 is not supported: each replica keeps its own global.json, so setup, the audit setting and every global setting saved in the dashboard would reach one replica only (ADR 0056). Keep replicaCount=1; see the chart README's \"High availability\" section for the supported shape." -}}
{{- end -}}
{{- end -}}

{{/* The Secret holding the encryption key and the gateway's identity secrets. */}}
{{- define "gateon.secretName" -}}
{{- default (printf "%s-secrets" (include "gateon.fullname" .)) .Values.secrets.existingSecret -}}
{{- end -}}

{{/*
The identity secrets every pod of this release reads from the Secret (ADR 0056):
environment variable -> Secret key. Each is a value gateon otherwise generates
for itself on first start and keeps in global.json -- on the pod's own volume,
so a second pod or a fresh volume generated another, and a session or a second
factor from one was refused by the other.
*/}}
{{- define "gateon.identityKeys" -}}
GATEON_SESSION_KEY: session-key
GATEON_AUDIT_SIGNATURE_KEY: audit-signature-key
GATEON_POW_SECRET: pow-secret
{{- end -}}

{{/*
GOMEMLIMIT as 80% of the memory limit.

A Go process sized to exactly its cgroup limit gets OOM-killed rather than
collected: GOMEMLIMIT bounds the heap, while the pod's limit covers the heap
plus stacks, the allocator's own metadata and anything mmapped. The 20% is that
gap. Explicit memoryLimit wins; with no limit at all the runtime is left alone,
because guessing a ceiling for an unbounded pod is worse than having none.

The number is parsed as a float. sprig's `int` returns 0 for "1.5", so a limit
of 1.5Gi used to render GOMEMLIMIT="0MiB" -- which the Go runtime accepts as a
zero-byte ceiling and answers by collecting continuously. A result below one
MiB renders nothing for the same reason. internal/config's
helm_memory_limit_test.go runs helm over this.
*/}}
{{- define "gateon.memoryLimit" -}}
{{- if .Values.memoryLimit -}}
{{- .Values.memoryLimit -}}
{{- else if .Values.resources.limits -}}
{{- if .Values.resources.limits.memory -}}
{{- $mem := .Values.resources.limits.memory | toString -}}
{{- $mib := 0.0 -}}
{{- if hasSuffix "Gi" $mem -}}
{{- $mib = mulf (float64 (trimSuffix "Gi" $mem)) 1024 -}}
{{- else if hasSuffix "Mi" $mem -}}
{{- $mib = float64 (trimSuffix "Mi" $mem) -}}
{{- end -}}
{{- $limit := int (floor (divf (mulf $mib 80) 100)) -}}
{{- if gt $limit 0 -}}
{{- printf "%dMiB" $limit -}}
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
{{- /*
  The audit log starts on, signed, as first-run setup turns it on (ADR 0050).
  On a persistent volume this changes nothing -- setup writes the same. Without
  one the seed is all a restarted pod has, and a seed without this restarted
  every pod with the audit log off. globalConfig.audit still wins.
*/ -}}
{{- $_ := set $cfg "audit" (merge (default dict (get $cfg "audit")) (dict "enabled" true "sign_entries" true)) -}}
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
