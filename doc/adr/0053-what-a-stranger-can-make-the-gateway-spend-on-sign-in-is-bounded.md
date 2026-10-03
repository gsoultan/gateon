# 53. What a stranger can make the gateway spend on sign-in is bounded, per client and in total

Date: 2026-10-04

## Status

Accepted. `sec` co-signs with `perf` and `mem`: the admission sits in front of
every endpoint a stranger can reach without a session, and it decides how much
CPU and memory the management plane may take from the data plane.

## Context

The 2026-10-04 review found MGMT-N3, anonymous and exposed by default:

- `POST /v1/auth/2fa/enroll` takes the sign-in's password step, and had no
  rate limit at all. Only `/v1/login` had one: five a minute per address, REST
  and Connect only (a native gRPC client was answered with an HTTP 429 it reads
  as `UNAVAILABLE`), and keyed per IPv6 /128.
- ADR 0050 made an unknown username cost what a real one does -- a bcrypt
  comparison at the production cost -- so that timing does not say which
  accounts exist. Nothing bounded how many ran at once.
- From one address in 75 s: 18,252 answers of 401, never a 429; ten to eleven
  cores busy; the data plane's median latency 0.7 -> 86 ms; the process at
  1.7 GB.
- The lockout tables (ADR 0050) were bounded by entry count, and the
  unknown-name table was keyed by the username the caller typed. With the public
  body cap at 64 KiB, 16,384 entries held a GiB: a unit probe measured
  1,029 MiB per tracker.

## Decision

**One admission for every pre-session endpoint that can reach a password
check.** `/v1/login`, `/v1/auth/2fa/enroll`, `/v1/auth/2fa/verify`,
`/v1/setup`, `/v1/setup/test-db`, and `/gateon.v1.ApiService/Login` and
`/Setup` (Connect and gRPC share a path) spend from one token bucket per client
(`internal/auth/admission.Sources`), in the base handler, before the body is
read and whatever the authentication setting. A client is an IPv4 address or an
IPv6 /64 -- the unit an IPv6 client is handed -- read with `request.ClientAddr`,
so a trusted proxy's client is the one behind it. Ten a minute, ten at once, on
every tier: enough for a sign-in, its second step and a few typos.
`IsSetupRequired` and `/v1/setup/required` are not on the list: they read a row
and the dashboard polls them. Loopback is not exempt, unlike the listener's
per-address cap (ADR 0036): a same-host proxy the gateway is not told to trust
makes every client loopback, and an exemption there would give whoever comes
through it an unlimited budget.

A refusal is `429` with `Retry-After`, in the caller's protocol: a trailers-only
gRPC answer with `grpc-status` 8 (`RESOURCE_EXHAUSTED`) to `application/grpc*`,
a Connect error `resource_exhausted` on `/gateon.v1.*`, the REST error JSON
otherwise. It is logged at most once a minute and counted with the local
rate-limit rejections.

The table is an LRU of at most 16,384 clients keyed by `netip.Prefix`, a fixed
size: about 3 MiB full, measured. An evicted client starts again with a full
bucket; the gate, not the table, is what bounds a client with many addresses.

**A gate on concurrent hashes, for the whole process.** Every bcrypt
comparison and hash in `auth.Manager` takes a slot of an
`admission.Gate` first. General slots: the tier's `AuthHashConcurrency`
(minimal 1, standard 2, enterprise 4), never more than half of `GOMAXPROCS`
(at least one) -- each slot is a core while it is busy, and the other half is
the data plane's. An anonymous password step that finds them all taken is
refused at once as `auth.ErrBusy`, before any hash, and never queued. Work a
signed-in caller asked for -- a password change, a 2FA enrolment and its
recovery codes, a recovery-code sign-in, saving an account with a password --
waits up to two seconds for a slot, at most 64 waiters, then is refused the
same way. `ErrBusy` carries the gRPC status `ResourceExhausted`, so a layer that
returns it unchanged answers it correctly on every transport; the REST sign-in
steps answer it `429` with `Retry-After: 1` explicitly, and no audit entry is
written for it (nothing was checked).

**One slot is held back for the owner.** When the general slots are full, an
attempt naming an account that exists, from a source that account has signed in
from before (ADR 0050's `login_sources`), may take the reserve. A flood from any
number of addresses the account has never used therefore cannot keep its owner
out. A stranger naming the same account, and any name that does not exist, is
refused as busy -- the decision is made before any hash, so the answer and its
timing do not depend on whether the name exists beyond what ADR 0050's
under-attack rule already reveals to a request from the account's own sources.

**The lockout tables are bounded in bytes.** Every account and source key is
the first 128 bits of its SHA-256: a fixed size whatever the caller typed, and
no collision anyone can find, so two names never share a count. Both tables
keep their entry caps and LRU eviction. A flood of 4 KiB names now leaves a
tracker at about 4.5 MiB (it held 80 MiB, and with 64 KiB names a GiB).

**ADR 0050's guarantees are kept.** A stranger still cannot lock the owner out
(the budget is per client, and the reserve is the owner's); unknown names still
pay for the dummy comparison when they are admitted, and are refused exactly as
real ones when they are not.

Overrides: `GATEON_AUTH_ATTEMPTS_PER_MINUTE` and `GATEON_AUTH_HASH_CONCURRENCY`.
Neither switches its bound off: a value that is not a positive integer is
ignored with a warning.

## Proof

Tests, each shown failing against the unfixed code and mutation-checked:
`internal/server/public_auth_admission_test.go` (a burst of three times the
budget from one address, on each endpoint, REST, Connect and gRPC; one budget
across endpoints and per /64; a full gate answered 429 / `ResourceExhausted`;
the owner signing in during a flood), `internal/auth/hash_gate_test.go`
(32 concurrent sign-ins never hash past the gate; the owner's reserve),
`internal/auth/lockout/lockout_bytes_test.go` (byte bound under long names),
`internal/auth/admission/admission_test.go`.

The data plane under the review's attack, measured on the built binary
(standard profile, 15-core host shared with other work, SQLite): one address
floods `/v1/auth/2fa/enroll` with invented 64-character usernames over 32
keep-alive connections for 30 s, while a separate process times `GET` through a
proxied route on one keep-alive connection every 10 ms.

| binary | flood answered | gateway CPU (peak) | data-plane p50 idle -> under attack (p99) |
| :--- | :--- | :--- | :--- |
| before | 5,978 x 401, no 429 | 1261 % | 1.14 -> **90.0 ms** (222 ms) |
| after, default budget | 6 x 401, 312,517 x 429 | 90 % | 1.29 -> **0.95 ms** (4.6 ms) |
| after, budget lifted (stands in for many addresses), standard | 520 x 401, 137,553 x 429 | 198 % | 2.11 -> **3.24 ms** (47 ms) |
| after, budget lifted, minimal | 327 x 401, 159,642 x 429 | 167 % | 2.62 -> **2.36 ms** (30 ms) |

The bound this decision holds the data plane to: its median under such a
flood within 2 ms of its idle median, from one address or (by the gate) from
many. The load test is `load.py`/`probe.py` in the work report; it is not a CI
test, because a latency bound on a shared CI runner fails for reasons that are
not the code.

## Consequences

- Everyone behind one address -- an office NAT, an untrusted same-host proxy --
  shares ten sign-in requests a minute. Trust the proxy so the gateway sees
  each client, or raise `GATEON_AUTH_ATTEMPTS_PER_MINUTE`.
- On the minimal tier, two people signing in in the same instant may see one
  "try again in a moment". The dashboard shows its existing 429 copy.
- Budgets, the gate and the lockout are per instance; an HA pair allows each
  node its own.
- The gate is per `auth.Manager`. Setup replaces the manager once, on first
  run, when nothing else is hashing.
- Connect `Login` is not implemented (it answers 501, so it never hashed); it is
  budgeted anyway, because the path is the gRPC one.
