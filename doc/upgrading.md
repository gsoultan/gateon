# Upgrading

Changes that alter behaviour on upgrade, newest first. Anything not listed here
is additive or internal.

Where a change can silently disable something that previously worked, gateon
also warns at startup naming the exact setting — you should not have to find it
here after the fact.

---

## Unreleased

### `redis.enabled` and `otel.enabled` are now honoured — **may disconnect Redis or stop traces**

Both flags were read by nothing. Redis connected because `redis.addr` was set,
and traces exported because `otel.endpoint` was set; the dashboard toggles
changed nothing either way.

They now gate their subsystems, which is what the dashboard has always claimed.

**Who is affected:** a hand-written `global.json` that sets an address or
endpoint *without* also setting the flag. That deployment works today and stops
after upgrading.

**Who is not:** configs saved through the dashboard (it writes the flag
explicitly), and deployments configured with the `REDIS_ADDR` or
`OTEL_EXPORTER_OTLP_ENDPOINT` environment variables — those still enable their
subsystem on their own, since setting one is an unambiguous instruction with no
flag to contradict it.

```jsonc
// before — worked
"redis": { "addr": "redis:6379" }

// after — set the flag
"redis": { "enabled": true, "addr": "redis:6379" }
```

proto3 cannot distinguish an unset bool from an explicit `false`, so there is no
migration that could tell "never set it" from "turned it off". gateon logs a
warning at startup for exactly this shape.

### Generic XDP is refused unless `ebpf.allow_generic_xdp` is set

If the driver rejects a native XDP attach, gateon no longer silently falls back
to generic (SKB) mode. Generic XDP runs after the `skb` is allocated, so it drops
no earlier than a firewall rule while still charging every passed packet the full
program cost — on a jumbo-MTU NIC it is slower than running no eBPF at all.

**Who is affected:** anyone whose eBPF was silently running in generic mode —
which on a default EC2 instance is everyone, because the ENA driver refuses
native XDP above a page-sized MTU (the VPC default is 9001) and unless the
driver is using at most half its queues.

The refusal is logged with the specific reason and the remediation commands.
Preferred fix on a virtualized NIC is `ebpf.tc_filtering = true`, which attaches
at the clsact hook and carries none of generic XDP's per-packet cost. Setting
`ebpf.allow_generic_xdp = true` restores the old behaviour.

### `make build` and `make release` now include eBPF

`HAS_EBPF` probed for a filename `bpf2go -target bpf` never emits, so the
wildcard never matched and both targets compiled the `noebpf` stub — while the
Dockerfile's plain `go build` compiled eBPF in. The two paths produced different
binaries.

**Effect:** binaries from `make release` now contain a subsystem the previous
ones did not. Combined with the change above, an eBPF-enabled config that
appeared inert may now attach — or refuse, with a logged reason.

### Bot-challenge secret is no longer a published constant

When `waf.bot_management.secret_key` was unset, challenge tokens were signed with
a literal compiled into the source. Anyone who read the repository could forge a
valid clearance token for any user agent and address and bypass the JS challenge
and browser integrity check.

The fallback is now 32 random bytes per process.

**Effect:** with no secret configured, tokens do not survive a restart and are
not shared between instances, so clients are challenged again. Set
`waf.bot_management.secret_key` to avoid that. This is a reason to configure a
secret, not a reason to keep shipping one everybody has.

### HA heartbeats and gossip require `ha.auth_pass`

HA adverts were unauthenticated: any host that could reach the port could make
the master release its virtual IP with one forged datagram. Gossip likewise ran
memberlist with no `SecretKey`, and arriving messages are applied to IP
reputation, which decides who gets shunned.

Both now authenticate with `ha.auth_pass`, and **refuse to start without it**.

**Effect:** HA and gossip do not run until `ha.auth_pass` is set to the same
value on every node. Clusters must be upgraded together — an upgraded node
rejects a legacy peer's adverts as malformed — and during a rolling upgrade both
halves may claim the VIP, so drain the passive node first.

### Removed configuration

All tags are `reserved`, so nothing can silently reuse them. Each of these was
read by no code; removing them changes no behaviour.

| Setting | Why |
| :--- | :--- |
| `geoip.xdp_geofencing` | wrote to a map no BPF program read; geofencing works via MaxMind and was never affected |
| `acme.dns_provider`, `acme.dns_config` | ACME here is autocert, which has no DNS-01 support at all |
| `gitops.ssh_private_key` | only go-git's HTTP transport is imported; SSH needs a host-key story first |
| `waf.rules_url`, `waf.update_interval_hours` | the rule downloader was retired with the gwaf engine change |
| `anomaly_detection.prometheus_url` | detection reads a local aggregator by design, not an external Prometheus |
| `anomaly_detection.anomaly_retention_days` | anomalies are never persisted, so there is nothing to retain |
| `debugger.max_captures` | there is no in-memory capture list to bound |
| `management.enable_port_knocking`, `management.port_knocking_sequence`, `management.xdp_management_whitelisting` | duplicates of the `ebpf.*` settings that do work |
| `auth.oidc` and all of `OidcConfig` | dashboard SSO was never built; **per-route OIDC is separate and unaffected** |
| all of `titan` | seven dashboard toggles controlling nothing; the phantom core still runs |
| `ebpf.xdp_cuckoo_filter` | nothing populated the map, while both programs looked it up per packet |

`waf.auto_update_rules` is kept but **relabelled** in the dashboard: it no longer
updates anything and means "load custom rules from `<data_dir>/waf/rules`".

### Diagnostics: `cuckoo_filter_entries` → `shunned_ip_count`

The field was populated with the shunned-IP count while the cuckoo map was
always empty, so the dashboard reported one number under another's name. The
value was real; only the label was wrong.
