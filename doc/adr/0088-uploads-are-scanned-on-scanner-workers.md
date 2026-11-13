# 88. Uploads are scanned on scanner workers

Date: 2026-11-13

## Status

Proposed. Nothing in this ADR is built. The dashboard design it describes is
the "ClamAV scanner workers" mock-up reviewed on 2026-11-13.

## Context

Gateon scans uploads by sending each file part to one `clamd` address. Three
things about that are wrong for the hosts Gateon targets.

1. **clamd does not fit beside the proxy on a small host.** It keeps its
   signature database resident, about 1 GB. On the 2-core / 2 GB host the
   2026-11-13 review measured, the gateway under attack already reached the
   cgroup limit on its own. The dashboard's install button puts clamd there
   anyway, and to do it the gateway's user needs docker or sudo (ADR 0087).
2. **One address is one point of failure.** When it is down every scanned
   route either refuses uploads or forwards them unscanned (`fail_open`), per
   route, with nothing in the dashboard saying which is happening.
3. **A file that is not `multipart/form-data` is never scanned.**
   `file_security` passes any other body straight through. An API that takes a
   file as a base64 string in JSON -- common for mobile and single-page
   clients -- has no malware scanning however the route is configured. (Base64
   *inside* multipart, `Content-Transfer-Encoding: base64`, is already refused,
   because the scanner would read text while a backend stored the decoded
   file.)

## Decision

### 1. A pool of scanner workers replaces the single address

A **scanner worker** is any machine running `clamd` that the gateway can reach
on TCP. Gateon does not install, start or update it. How clamd got there --
the official container, `apt install clamav-daemon`, a Kubernetes Deployment --
is the worker's business, and the dashboard shows the container command and
the package commands as equal choices. **A worker needs no Docker and no
Gateon software.**

- `waf.clamav.scanners` is a list of `{name, address}`, administrator-only
  (ADR 0087's rule: it is where uploads go). `clamav_addr` remains as a
  one-entry pool, so existing installs are unchanged.
- **Bound:** at most 16 workers. Each has a fixed-size connection pool, and
  the existing per-route `MaxConcurrentScans` semaphore still bounds in-flight
  scans and therefore buffered bytes.
- **Health:** a background checker sends clamd's `PING` and `VERSION` every 10 s
  with a 2 s timeout. Two consecutive failures mark a worker unhealthy, two
  successes bring it back. No health check runs on the request path.
- **Selection:** least in-flight among healthy workers. A scan that fails on
  one worker is retried once on another, inside the route's existing scan
  timeout, never beyond it.
- **No worker healthy:** one global setting, `when_unavailable`, `refuse`
  (default, today's `fail_open=false`) or `allow_unscanned`, which records
  every file it let through in the audit log. A route's `fail_open` still
  overrides it, so nothing changes for a route that set it.
- **Adding a worker tests it first:** the dashboard sends the EICAR test
  string and saves the worker only if clamd reports it. Version, signature age
  and scan time are shown per worker.
- **Transport:** clamd speaks plaintext. The dashboard says so and tells the
  administrator to keep workers on a private network. TLS to a worker
  (through stunnel or a sidecar on the worker) is a later addition, not a
  reason to hold this back.

Topology, stated as `net` requires: **one worker down** -- uploads go to the
rest, the dashboard shows it unreachable and it rejoins by itself. **All
down** -- `when_unavailable` decides, and the dashboard says which. **Mid
rollout** -- a pool edit applies to the next scan; a scan in flight finishes
on the connection it has.

### 2. Installing ClamAV on the gateway becomes the exception

"Install locally" stays for a single-machine install with memory to spare, and
is disabled with the reason shown when the host has under 4 GB. The default
path in the dashboard is "Add scanner worker". Removing local install
altogether is deferred until the pool has shipped a release.

### 3. A file carried as base64 in JSON is decoded and scanned

Per route, `file_security` gains `json_file_fields`: the JSON paths that carry
a file, for example `file` or `documents[].content`.

- Only named fields are decoded. Ordinary JSON traffic on the route costs one
  bounded pass to find them and nothing else; a route with no fields named
  behaves exactly as today.
- The decoded bytes get every check a multipart part gets: MIME allow/deny,
  signatures, embedded executable, ClamAV. Standard and URL-safe alphabets,
  with or without padding, and a `data:...;base64,` prefix are all read --
  every decoding a backend plausibly applies, not one.
- **The body forwarded to the backend is the body received.** Gateon scans a
  copy and never rewrites the request.
- **Bound:** decoded size is capped by the route's existing `max_file_size`
  and `MaxScanBytes`, and a field is refused as too large from its encoded
  length before any decoding.
- **`mode: report | block`, default `report`.** In `report` a flagged file is
  recorded as a security event and forwarded. In `block` it is refused with
  the same answer a multipart upload gets. A new control that starts refusing
  traffic on the day it is enabled gets turned off; one that shows what it
  would refuse gets turned on.
- A named field that is present but is not valid base64 is recorded in
  `report` and refused in `block`: a backend with a lenient decoder may accept
  what a strict one rejects, and an unscannable file is not a clean one.

Not decided here: scanning *unnamed* long base64 strings. It finds files
nobody declared, at a CPU cost on every JSON request and with a real
false-positive surface. If built it is a separate, tiered, off-by-default
setting with its own measurements.

## Consequences

- A 2 GB gateway can scan uploads without giving half its memory to clamd, and
  without docker or sudo on the gateway.
- Scanning survives the loss of a scanner, and what happens when none is left
  is one visible setting instead of a per-route flag.
- New surface to prove before it ships: the pool's behaviour for one-down,
  all-down and mid-rollout as tests; a benchmark showing no allocation on the
  request path for a route with no `json_file_fields`; a fuzz target on the
  JSON field walker and the base64 decoder, both of which read hostile input;
  an effect test per new dashboard key on REST, gRPC and Connect.
- `proto` gains fields, so the change goes through `make proto`. The settings
  live in the stored global configuration document and in middleware config
  maps, so no SQL migration is expected.

## Plan

1. Pool and health checker behind the existing single address (no behaviour
   change), with the one-down / all-down / mid-rollout tests.
2. `scanners` list, `when_unavailable`, add-worker test, and the dashboard
   screens from the mock-up.
3. `json_file_fields` in `report` mode only, with the fuzz targets and the
   no-allocation benchmark.
4. `block` mode, after a release in which `report` has been available.
