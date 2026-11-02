# 80. A global change is applied whoever stores it

Date: 2026-11-02

## Status

Accepted. Driver `arch`, Challenger `conc`. Moves no trust boundary: who may
store a global configuration, and what is checked before it is stored, are
unchanged.

## Context

A stored global configuration reaches the running gateway in two ways. The
subsystems the security supervisor owns -- anomaly detection, GitOps, HA,
eBPF, ClamAV and the WAF updater -- subscribe to the registry and reconcile
on every change. Everything else -- the WAF cache, every route chain (and the
tarpit, proof of work, deception, debugger and global WAF built into them),
alerting, the audit settings, IP reputation, log retention, the GeoIP
databases and the port-knocking sequence -- was reconfigured by
`applyGlobalConfig`, which only `UpdateGlobalConfig` called.

Four other writers store through the registry: a GitOps sync, the fixes
applied from Diagnostics, the ClamAV install mode and first-run setup. Each
stored a change the running gateway then ignored. A WAF switched off in the
synced repository kept running until something else saved; a Diagnostics fix
reported success and applied only the parts its handler happened to rebuild
by hand.

## Decision

`NewApiService` subscribes `applyGlobalConfig` to the global store when the
store reports its changes (`config.GlobalRegistry` does), so every stored
change is applied once, from the registry's notification, whoever wrote it.
`UpdateGlobalConfig` applies its own change only when the store does not
report -- a bare `ApiService` literal, as the tests build one -- so a save is
never applied twice (each apply starts an IP reputation feed refresh).

The registry notifies synchronously, outside its lock, with clones, so the
RPC still returns after its change is in force, and a GitOps sync applies on
its own goroutine as it already wrote on it.

## Consequences

- A GitOps sync, a Diagnostics fix and setup now reconfigure the same
  subsystems a save from the dashboard does.
- The fixed-purpose writers that rebuild routes themselves after
  `editGlobal` now rebuild twice; the second is redundant and harmless, and
  can be removed as those handlers are touched.
- A GitOps sync still stores without `validateGlobalSave`; that is a
  separate decision about what a synced repository is trusted to say.
