# Threat Correlation & SIEM Export

Gateon already records individual security detections (brute-force attempts,
exploit scans, WAF blocks, rate-limit hits, impossible travel, bot/GeoIP blocks,
behavioral/DGA anomalies, etc.) via `telemetry.RecordSecurityThreat`. This guide
covers two features built on top of that stream that turn Gateon into a
Wazuh-like sensor:

1. **Correlation engine** — aggregates related detections from the same source
   into higher-level **incidents** annotated with **MITRE ATT&CK** techniques.
2. **SIEM export** — ships threats and incidents to an external SIEM/log
   collector (Wazuh indexer, Elasticsearch/OpenSearch, Splunk, syslog).

Both are dependency-free (standard library only) and run off the request hot
path. The correlation engine **always runs** and logs incidents; SIEM export is
**opt-in** via environment variables.

---

## How it fits together

```
RecordSecurityThreat  ──▶  ThreatBroadcaster  ──▶  threat pipeline (cmd/gateon)
                                                      │
                                   ┌──────────────────┼─────────────────────┐
                                   ▼                                          ▼
                        correlation.Engine                         siem.Shipper (optional)
                     (sliding window, MITRE)                      (json / cef / syslog)
                                   │                                          ▲
                                   └── OnIncident ─▶ log + ship incident ─────┘
```

- Every recorded threat is converted into a `correlation.Signal` and observed by
  the engine.
- When enough related signals appear from one source within the window, an
  `Incident` is raised (logged as a warning, and shipped to the SIEM if enabled).
- Raw threats can optionally also be shipped (`GATEON_SIEM_RAW_THREATS=true`).

---

## Correlation engine

Sources are keyed by **fingerprint** (preferred) or **source IP**. Within a
sliding **window**, signals are accumulated; an incident is raised when either:

- the number of signals reaches **MinSignals** (default `3`), or
- the cumulative score reaches **MinScore** (disabled by default).

A **re-alert interval** (default `1m`) debounces repeated alerts for the same
active source, preventing alert storms. Idle sources are garbage-collected after
the window elapses, and both the number of tracked sources and the signals
retained per source are bounded for memory safety.

Each incident carries the deduplicated **MITRE ATT&CK techniques** implied by its
signal types, e.g.:

| Threat type | MITRE technique(s) |
|-------------|--------------------|
| `brute_force_attempt` | T1110 Brute Force |
| `exploit_scan` | T1190 Exploit Public-Facing Application, T1595 Active Scanning |
| `probe_detected` / `api_fuzzing` | T1595 Active Scanning |
| `dga_detected` | T1568.002 Domain Generation Algorithms |
| `rate_limit` / `error_rate_spike` / `latency_spike` | T1499 Endpoint DoS |
| `waf_block` / `sql_injection` / `security_threat` | T1190 Exploit Public-Facing Application |
| `bot_detected` / `behavioral_anomaly` | T1071 Application Layer Protocol |
| `geoip_block` | T1090 Proxy |
| `impossible_travel` / `device_posture_change` | T1078 Valid Accounts |

The current defaults are conservative; the engine is tuned in code via
`correlation.Config`.

---

## SIEM export

Enable export by setting `GATEON_SIEM_ENDPOINT`. The exporter ships events
asynchronously over a bounded queue — if the queue is full, events are **dropped
and counted** rather than blocking the proxy.

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GATEON_SIEM_ENDPOINT` | _(unset → disabled)_ | URL (`http`) or `host:port` (`udp`/`tcp`). Setting it enables export. |
| `GATEON_SIEM_ENABLED` | `true` when endpoint set | Set to `false` to disable without removing the endpoint. |
| `GATEON_SIEM_FORMAT` | `json` | Wire format: `json`, `cef`, or `syslog` (RFC 5424). |
| `GATEON_SIEM_TRANSPORT` | `http` | `http`, `udp`, or `tcp`. |
| `GATEON_SIEM_TOKEN` | _(unset)_ | Optional bearer token sent as `Authorization` (HTTP only). |
| `GATEON_SIEM_QUEUE_SIZE` | `2048` | Bounded async queue size. |
| `GATEON_SIEM_TIMEOUT` | `5s` | Per-send timeout (e.g. `5s`, `500ms`). |
| `GATEON_SIEM_RAW_THREATS` | `false` | Also ship every individual threat, not just incidents. |

### Examples

Ship correlated incidents to an OpenSearch/Wazuh-style HTTP collector as JSON:

```sh
export GATEON_SIEM_ENDPOINT="https://siem.example.com/ingest"
export GATEON_SIEM_TOKEN="$SIEM_INGEST_TOKEN"
```

Ship to a syslog collector over UDP in CEF (also forward raw threats):

```sh
export GATEON_SIEM_ENDPOINT="logs.example.com:514"
export GATEON_SIEM_TRANSPORT="udp"
export GATEON_SIEM_FORMAT="cef"
export GATEON_SIEM_RAW_THREATS="true"
```

### Wire formats

- **json** — newline-delimited JSON objects (`{timestamp, kind, name, severity,
  source_ip, message, fields}`), ideal for Elastic/OpenSearch/Wazuh/Splunk HEC.
- **cef** — ArcSight Common Event Format:
  `CEF:0|JetBrains|Gateon|<version>|<kind>|<name>|<0-10 severity>|src=… cs_mitre=…`.
- **syslog** — RFC 5424 with a `[gateon@0 …]` structured-data block (facility
  `local0`).

---

## Security & resource notes

- The exporter and correlation engine never block request handling: ingestion is
  non-blocking and overflow is dropped (and counted via shipper `Stats`).
- A bearer token is the only secret used; it is read from the environment and
  never logged.
- Memory is bounded: the correlation engine caps tracked sources and signals per
  source and GCs idle sources; the shipper queue is bounded.
- All goroutines stop when the server context is cancelled; the shipper performs
  a best-effort flush of queued events on shutdown.
