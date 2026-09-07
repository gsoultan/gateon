<!--
Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
SPDX-License-Identifier: MIT
-->

# Deployment sizing

Gateon targets a **2 core / 2 GB** host. This page records what that was
measured to mean, how to re-measure it, and which knobs move it.

## What was measured

`TestSoakOnDeploymentBudget` runs the real binary with the Go runtime pinned to
the target budget and drives sustained load through it.

**2026-09-07 — 2 cores, 1536 MiB runtime limit, 45s at concurrency 24:**

| | |
| :--- | :--- |
| Throughput | 10,651 req/s (479,317 requests, 0 failed) |
| Latency | p50 1.5ms · p90 4.8ms · p99 11.4ms · max 54.8ms |
| Resident memory | 131 MB idle · 140 MB peak · 121 MB after load stopped |
| Goroutines | 127 idle → ~145 under load |

**What was in the request path:** the `/test` route runs the headers
middleware, the WAF in **blocking** mode (`audit_only: false`, SQLi + XSS + LFI
+ RCE detectors, anomaly threshold 5) and CORS. This is not a bare proxy
measurement — every one of those 479,317 requests was inspected and scored.

The headline is the memory. Gateon holds around **140 MB of a 2 GB host** under
sustained load — roughly 7% — so the target is not a tight fit, it has an order
of magnitude of headroom. Two cores serve five figures of requests per second
through a blocking WAF with a single-digit-millisecond median.

A second run at 30s measured 7,489 req/s and p99 16.2ms. Run-to-run spread on a
shared machine is wide; treat a single number as an order of magnitude, not a
figure.

## What the measurement is not

Read these before quoting the numbers.

- **It is not a cgroup.** `GOMAXPROCS` and `GATEON_MEMORY_LIMIT` hold the Go
  runtime to the budget, which is the part Gateon controls. The kernel is not
  stopping the process from exceeding it. This catches a gateway that *wants*
  more than the target has; it does not reproduce what the OOM killer does when
  it gets it.
- **The load generator is not inside the budget.** The client and the mock
  backend run on the same machine, outside the two cores. A real 2-core host also
  spends those cores on its network stack. Read the throughput as the gateway's
  own appetite, not as a capacity figure for the target.
- **It is one route, one backend, small responses.** Large bodies, many routes,
  a higher WAF paranoia level and trace storage all cost more. The tier defaults
  below exist for exactly that reason. Request bodies in particular are not
  exercised here: these are GETs, so the WAF's body-inspection path — the
  expensive half — is not on this measurement.

## Re-measuring

```bash
GATEON_SOAK_TEST=1 go test ./tests/e2e/ -run TestSoakOnDeploymentBudget -v -timeout 15m
```

| Variable | Default | Meaning |
| :--- | :--- | :--- |
| `GATEON_SOAK_TEST` | unset | Must be `1`; the soaks are opt-in because they build and run the binary |
| `GATEON_BUDGET_CORES` | `2` | `GOMAXPROCS` for the gateway process |
| `GATEON_BUDGET_RUNTIME_MIB` | `1536` | `GATEON_MEMORY_LIMIT`, in MiB |
| `GATEON_SOAK_SECONDS` | `60` | Load duration |

The assertions are anchored to the run above with room for slower hardware, not
to the host budget alone: a ceiling of 1740 MB against an observed 140 MB would
let a twelvefold regression pass. There are two memory lines — 512 MB flags a
structural regression while there is still plenty of host left, and 1740 MB is
the point where the host itself is in trouble.

The companion soaks are worth running in the same session:

```bash
GATEON_SOAK_TEST=1 go test ./tests/e2e/ -run 'TestSoakStability|TestGracefulDrain' -v -timeout 15m
```

`TestSoakStability` watches for leaks unconstrained; `TestGracefulDrain` checks
that the gateway drains in-flight requests and exits on its own when signalled,
which is what every rolling deploy depends on. Measured drain: **1.6s** with 8
requests in flight against a 2s backend.

## Knobs

| Variable | Default | Effect |
| :--- | :--- | :--- |
| `GATEON_PROFILE` | `standard` | Tier: `minimal`, `standard`, `enterprise`. Sizes correlation tracking, trace sampling, CMS sketches, Pebble cache and retention. Wins over the stored config so a container can pin its footprint. |
| `GATEON_MEMORY_LIMIT` | unset | Soft memory limit (`512MiB`, `1GiB`, or raw bytes) applied via `debug.SetMemoryLimit`. Makes the GC work harder rather than letting the process grow. `GOMEMLIMIT` is honoured natively too. |
| `GOMAXPROCS` | from cgroup | Go 1.25+ derives this from cgroup CPU bandwidth, so a container with a CPU limit is usually already correct. Set it explicitly if not. |
| `GOGC` | `100` | Standard Go GC tuning. Lower trades CPU for memory. |

On a 2 GB host, set `GATEON_MEMORY_LIMIT` to around **1536MiB** rather than the
full 2 GB: the limit governs the Go runtime, and the kernel, the container
runtime and any sidecar still need the difference.

`minimal` exists for hosts smaller than the target — it disables correlation
tracking and trace storage, the two subsystems whose cost scales with traffic
rather than with configuration.
