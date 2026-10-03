# 49. A gateway that cannot do its job says so, and its telemetry cannot take it down

Date: 2026-10-03

## Status

Accepted. `ops` drives; `mem` and `obs` co-sign the trace-store bounds and the
access-log cap, `sec` co-signs the unit's capabilities and sandboxing (a trust
boundary: what a compromised proxy holds), and `data` the database-path and
setup changes.

## Context

The 2026-10-02 production-readiness review (ops F3-F13, mgmt M12-M14) found the
shipped artifact failing in ways an operator only learns about in production:

- **The trace store filled the disk, then took the gateway with it** (F3). It
  was bounded by age alone -- about 1.1 KB a request for seven days on the
  standard profile, some 66 GB at 100 req/s. On the review's 48 MB disk Pebble
  retried a failed compaction in a loop at two cores, logged at INFO, and
  /readyz said ready. Reproducing it for this ADR found worse: when the
  write-ahead log hit ENOSPC, Pebble's default logger called `log.Fatalf` and
  the process exited, proxy and all.
- **A listener that could not bind was logged and ignored** (F5, M14). With the
  management port taken there was no management plane; with :443 taken there
  was no :443; /healthz and /readyz said 200 in both, so neither systemd nor a
  load balancer noticed.
- **A Postgres outage looked like a wrong password** (F12): 401 with the
  driver's error, and nothing in /readyz or /metrics.
- **The database lived wherever the process started** (F6), and a missing one
  was recreated empty, which reopened first-run setup on a configured gateway.
- **One stdout line per request** (F7) put a busy gateway past journald's
  default rate limit (10000 lines in 30 s), which then dropped its ERRORs too.
- **The container image and Helm chart could not finish setup** (F4): global.json
  was at a read-only (chart) or missing (image) /etc/gateon. And setup was not
  atomic (M13): a failed config write left the administrator behind, which on
  an existing global.json closed setup for good.
- **The unit held CAP_NET_ADMIN and CAP_BPF ambiently** with eBPF and HA off
  (F8), carried none of systemd's standard sandboxing, set no memory ceiling,
  and pointed operators at `Environment=` for the encryption key (F13), which
  every local account can read. **Every package upgrade re-enabled and
  restarted a service the operator had disabled** (F11), and on rpm the old
  package's scriptlet then stopped and disabled it again whatever its state.

## Decision

**/readyz describes whether this instance should get traffic, and says what
is failing on one that should.** It answers 503, with every reason, when the
instance cannot serve: the telemetry store did not open (as before), or an
entrypoint listener did not bind (named, with its address and error). It
answers 200 `ready, degraded: ...` when the instance serves but something is
failing: the trace store has stopped writing for a full disk, or the
configuration database does not answer a ping (every 10 s in the background;
the probe never waits on the database). A load balancer that health-checks
/readyz removes a 503 instance, and on the single-node target that is an
outage; a full trace disk loses traces, and an unreachable database stops
sign-in and writes while the data plane keeps serving by design (ADR 0043
fails block lookups open), so neither is a reason to stop routing traffic to
it. Gauges `gateon_entrypoint_up{entrypoint}`, `gateon_config_db_up` and
`gateon_trace_dropped_total{reason}` carry the same, and are what to alert on.
(As first written this ADR made both degraded conditions 503; integration
review changed that before release.)

**The management listener is required; an entrypoint is not.** The management
listener binds before StartServers returns, and failing to is an error Run
exits non-zero on, so `Restart=on-failure` acts. An entrypoint that cannot bind
logs ERROR and makes /readyz 503, but the gateway keeps serving its other
entrypoints: one port held by a stale process should not take every other port
down. Entrypoint runners run in turn rather than on goroutines -- each already
bound before returning -- so /readyz cannot be ready before they have.

**Sign-in tells a refusal from a failure.** A credentials refusal is 401; any
other error is 503 with the detail in the log. A second factor that does not
decrypt under the session key says so instead of "cipher: message
authentication failed".

**The trace store is bounded by size and by the disk under it**
(`internal/telemetry/tracebudget`):

- a per-profile budget (256 MiB / 2 GiB / 20 GiB, `GATEON_TRACE_STORE_MAX_MB`),
  held every 30 s and by the hourly prune, evicting the oldest traces to four
  fifths of it whatever their age. It does not wait for the trace archive's
  guard: a store that may not shrink until something else catches up is not
  bounded;
- a free-space floor (a twentieth of the disk, at least four memtables, at most
  1 GiB) below which trace writes stop, counted in `gateon_trace_dropped_total`
  and logged at ERROR once a minute, resuming at 1.5x the floor -- the floor is
  derived, not a new tunable;
- a backoff on Pebble's file creation after ENOSPC (1 s doubling to 30 s), which
  turns the compaction retry loop into one attempt a period; and a Pebble
  `Fatalf` caused by a full disk stops the trace store for the life of the
  process instead of exiting it. Any other `Fatalf` still exits.

Trace data is observability. Losing it must never cost a request.

**The access log is capped, not turned off**: at most 50 / 100 / 200 lines a
second by profile (`GATEON_ACCESS_LOG_MAX_PER_SECOND`, 0 lifts it), with a WARN
once a minute counting what it left out. Turning it off by default would have
removed it silently from every small install that reads it; below the cap
nothing changes, and the trace store still records every request.

**State lives in the data directory.** A relative SQLite path resolves against
GATEON_DATA_DIR. A gateway whose global.json says it was set up
(`auth.enabled`, which setup writes) refuses to start when its SQLite database
is missing or the database it opens has no administrator.

**Containers keep global.json on the data volume.** The image and chart set
`GLOBAL_CONFIG_FILE=/var/lib/gateon/global.json`; a global.json mounted at
/etc/gateon is a seed (`GATEON_GLOBAL_CONFIG_SEED`), copied once onto a volume
that has none and not read again. The image's /var/lib/gateon is owned by
nonroot; the image is still distroless, nonroot and CGO-free. Setup is all or
nothing: a failed config write deletes the administrator the call created and
uninstalls the auth service it installed.

**The unit holds what the default gateway uses.** CAP_NET_BIND_SERVICE only;
CAP_BPF and CAP_NET_ADMIN move to a shipped, inactive drop-in
(`/usr/share/gateon/systemd/ebpf-ha.conf`) an operator links to turn eBPF or HA
on. The unit adds systemd's standard sandboxing (PrivateDevices,
ProtectKernel*, ProtectControlGroups, RestrictNamespaces, RestrictAddressFamilies
with AF_NETLINK for interface discovery, SystemCallFilter=@system-service with
EPERM, and the rest), `MemoryMax=90%` -- from which gateon derives its Go soft
limit at 85% when none is set, ~1.5 GiB on the 2 GB target -- and
`EnvironmentFile=-/etc/default/gateon` for secrets. The package scripts leave
an upgraded service as the operator had it: preinstall records enabled/active,
postinstall (and, for rpm, posttrans) restores it, postremove acts only on
removal. The Windows service XML is no longer shipped as a Linux conffile.

## Consequences

- An operator whose management port is taken now sees the service restart in
  a loop with the reason in the journal, instead of a quiet gateway with no
  dashboard. A load balancer stops sending traffic to a gateway with an unbound
  entrypoint. A full trace disk or an unreachable configuration database leaves
  it in rotation, answering "ready, degraded" -- as amended above: taking a
  working data plane out of rotation turned a single-node gateway's lost traces
  into an outage. The gauges are what alert on those.
- On a busy gateway the trace store's budget, not its retention, decides how far
  back traces go: 2 GiB is about 1.9 million requests. The budget counts the
  store's tables; the write-ahead log adds up to a few memtables.
- Turning eBPF or HA on under the packaged unit needs the drop-in; without it
  the existing capability check logs which capabilities are missing.
- Changing `globalConfig`, `externalDatabase` or `redis` in Helm values no longer
  reaches an existing install; the dashboard is where those change after the
  first start.
- The unit's sandboxing was checked against the gateway's own needs and eBPF's;
  a deployment that runs something unusual from the gateway (a custom ACME
  hook, say) may need a drop-in relaxing it.
