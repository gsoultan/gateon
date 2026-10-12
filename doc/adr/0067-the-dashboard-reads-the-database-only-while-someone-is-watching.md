# 67. The dashboard reads the database only while someone is watching

Date: 2026-10-11

## Status

Accepted.

## Context

The metrics snapshot behind the dashboard was refreshed on the tier's
telemetry interval: every 30 s on minimal, 5 s on standard, and 2 s on
enterprise. Every refresh on standard and enterprise made nine database reads.
Four of them scan all of `security_threats` with no time filter:

- the total count;
- the top sources;
- the top types;
- the top countries.

The others are a trend over up to 366 days, the traffic history and two
domain-stats windows. The loop ran whether or not anyone had the dashboard
open. That is about 6,500 reads an hour on standard and 16,000 on enterprise,
most of them for nobody.

The Security Hub pages through recent threats with its own page size. Every
page went down the synchronous path, which collected a whole new snapshot,
every aggregate read included, to return ten rows.

## Decision

**No reads while nobody watches.** Someone is watching while a live stream
(`/v1/watch` or `/v1/diag/metrics/watch`) is subscribed, or for a minute after
a request for the snapshot. The rest of the snapshot comes from Prometheus and
in-memory counters. It keeps refreshing, because the anomaly aggregator and
the status card read it.

**While someone watches, two cadences:**

- The newest page of threats is read on every tick. It is one indexed query.
- The aggregates are read at most once per `TierDefaults.DashboardAggregateInterval`:
  2 min on minimal, 1 min on standard, 30 s on enterprise. Override it with
  `GATEON_DASHBOARD_AGGREGATE_INTERVAL`. These numbers span the whole retention
  window, so a few seconds of traffic barely moves them.

**A viewer arriving after a quiet period gets current numbers.**

- Subscribing wakes the loop at once.
- A request that finds the aggregates more than two intervals old reads them
  synchronously and publishes the result. Concurrent requests share that one
  read.

**Another page of threats reads that page only.** The aggregates in the
response come from the published snapshot. Everything else is built fresh from
memory, as before.

`gateon_dashboard_aggregate_reads_total` counts aggregate reads, so the effect
is visible in production.

## Considered and rejected

**Hourly counters kept in memory by the threat writer.** These would remove
even the watched reads. But each gateway sees only the threats it recorded.
With several gateways on one database, the dashboard would show one node's
attacks instead of the cluster's. Re-reading the database to reconcile them
would bring the reads back. A rollup table written once per flush avoids both
problems, but it needs a migration and its own retention. It is worth doing
only if the watched cost still matters once this change has shipped.

## Consequences

- Reads per hour drop as follows:

  | Tier | No one watching | Someone watching |
  |---|---|---|
  | Standard | about 6,480 → 0 | → about 1,200 |
  | Enterprise | about 16,200 → 0 | → about 2,760 |
  | Minimal | already lower → 0 | about the same as before |

- While someone watches, the top lists, total and trend can lag by up to one
  interval. The newest threats, today's counters and the golden signals do not
  lag.
