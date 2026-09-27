# 22. Traces are archived an hour at a time, in files named for the hour

Date: 2026-09-26

## Status

Accepted.

## Context

The live trace store (Pebble, `internal/telemetry`) keeps per-request traces for
the access-log retention — seven days on the standard profile — and then
deletes them. People investigate incidents after that: a WAF false positive
reported a fortnight late, a breach found a month in. They asked for traces to be
archived automatically, for the archive to be browsable in the dashboard, and
for traces to be findable by period.

Three things constrained the design:

- **The host.** Gateon is sized for 2 cores and 2 GB. Archiving must not parse
  every trace again, must not hold an hour of traces in memory, and a search
  over a long period must not take a core from the proxy.
- **The key.** A trace is keyed by when its request *started* and written when
  it *finished*. A long-lived connection therefore lands in the store for an hour
  that closed long before — so "archive an hour once it has closed" alone loses
  traces, silently, which is the failure an archive exists to prevent.
- **The package-size ratchet.** `internal/telemetry` (31), `internal/api` (36)
  and `internal/server/handlers` (22) are at their pinned file counts.

## Decision

**The unit is one UTC hour, written as one file named for that hour:**

```
<data dir>/trace_archive/2026/09/26/traces-2026-09-26T14Z.ndjson.zst
```

- *An hour* because it bounds everything that scales with traffic: the file a
  query has to open, the work of writing one, the delay before a closed period is
  in the archive. A day at a thousand requests a second is 3 GB of JSON to
  decompress for a query about one minute of it. A week or a month cannot be
  written from a store that keeps seven days without appending to a file, and a
  file that is appended to is one a crash can leave half-written. Days, weeks and
  months are views over hours, which the directory layout and the query provide.
- *Named for the hour it holds, in UTC, with a literal `Z`.* A local-time name
  repeats or skips an hour around a daylight-saving change and means different
  hours on nodes in different zones. The fixed-width ISO 8601 stamp makes names
  sort in time order and makes a glob a period (`traces-2026-09-*` is a month).
- *A directory per UTC day* so ordinary tools work on days and months (`du`,
  `rsync`, `rm -r`), and a listing for a period opens only that period's
  directories. The name repeats the date so a file copied out of its directory
  still says what it holds.

**The format is NDJSON in zstd, readable by stock tools.** Each line is the
store's own JSON for a trace, copied without being parsed — the store has already
redacted credential headers — so exporting costs a read and compression. A file
is a run of independent zstd frames of about 1 MiB of NDJSON, framed by two
*skippable* frames that every zstd decoder ignores: a fixed 512-byte JSON header
(hour, count, first and last trace, where the index is, the index's CRC) and a
binary index of the data frames with the time range each holds. `zstd -dc` of a
file is exactly its NDJSON; the gateway uses the index to decode only the frames
a query or a lookup needs, from either end. Files are written to a temporary
name, synced and renamed, so a file under its real name is complete.

**Archiving is two passes, and the store waits for the second.** A background
archiver (one goroutine, a tick a minute) writes each hour a couple of minutes
after it closes, then, as the store's retention cutoff comes within two hours of
an hour, checks it again: if the store now holds a different number of traces
for the hour than the file was written against, it writes a new file from the
store and the old file merged in key order. The store's prune consults a guard
before deleting: it deletes whole hours, and only hours that check has
confirmed. A guard can only move the cutoff earlier; retention is still the most
that is ever deleted.

**Holding back is bounded.** If the archive cannot catch up — a full disk is the
likely cause — the store keeps unconfirmed hours for at most 24 hours past
retention, then deletes them and counts it
(`gateon_trace_archive_unverified_prunes_total`). Holding traces indefinitely
because archiving is failing would fill the disk that is probably why it is.

**One query reads both.** `QueryTraces` splits a period at the store's *hot
floor* — the later of where the last prune stopped and the store's oldest
trace — and reads the store above it and the archive below it, as one ordered
stream with a cursor that is a trace key, so pages neither repeat nor skip a
trace across the boundary. The floor and the store's part are read from one
Pebble snapshot, so a prune landing between the two phases of a page cannot
take an hour the page had assigned to the store; the prune point is kept on
disk, so a restart does not lower the floor. A call examines at most 200 000
traces or 256 MiB of them before returning what it has, and one query runs at
a time. `GetTrace` falls back to the archive, so a trace found by period opens
whichever store holds it. An hour downloads over REST
(`GET /v1/traces/archives/{name}`), streamed from disk as an attachment the
browser may not sniff or keep, because a unary RPC would hold the file in
memory; four download at once at most, each write with its own deadline.

**It is off until enabled, on every profile.** Retention and a size budget
default per profile (7 days / 256 MB, 90 days / 2 GB, 365 days / 20 GB) and the
oldest hours go first when either binds. Every setting has an environment
variable that beats the global config, which beats the profile.

The code is its own package, `internal/telemetry/tracearchive`: the files, the
archiver, the query and the download. The trace store gained a range scan, the
hot floor and the prune guard, in files it already had.

## Consequences

- Traces outlive the live store by the archive's retention, at about 130 bytes a
  trace on disk (measured 7:1 on realistic traces without bodies), and the
  dashboard can search any period of them.
- When archiving is on, the store's prune deletes whole hours, so traces can
  stay up to an hour past retention; with it off, pruning is exactly as before.
- A trace whose request outlived the store's retention minus two hours reaches
  the store after its hour was last checked and is not archived. Such a request
  ran for days; before this, it was deleted by the next prune anyway.
- Each node archives its own traces. Nodes that share a directory overwrite each
  other's hours; the documentation says to give each node its own.
- The store now keeps at most 128 bytes of a trace's ID, as valid UTF-8. The ID
  is the client's `X-Request-ID`; unbounded, a long one produced cursors the
  next call refused, and bytes that were not UTF-8 made an archived trace never
  match its own copy in the store, so every merge added it again.
- Nothing on the request path changed. The costs are a sequential read of each
  hour twice (once to write it, once more to check it before it is pruned),
  zstd at about 390 MB/s a core, and a few megabytes while an hour is written.

## Alternatives considered

- **Archive only at retention, when the store deletes.** One read instead of
  two, and no late traces to merge. Rejected: nothing appears in the archive for
  the first week after it is turned on, which reads as broken, and a lost store
  loses a week instead of an hour.
- **A JSON array per retention run, brotli at its best level** — what the audit
  log does. It must be built in memory and parsed whole to read one entry, and
  brotli at level 11 is minutes of CPU per gigabyte on the target host.
- **A configurable rotation period** (hourly, daily, weekly). Every reader must
  then handle files of mixed length and overlapping names after a change, and
  the long periods cannot be written from a store that keeps less than them.
- **A seekable-zstd library or a SQL index of the files.** A dependency, or a
  second source of truth that drifts from the files; a header and an index inside
  each file cannot drift from it.
- **Node-qualified names.** Longer names that every reader must parse, to solve
  a problem a directory per node solves.
