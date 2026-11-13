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

## Negative cases

What a hostile client, a hostile or broken worker, or a mistake does to each
part, and the answer the design owes. Each line is a test the implementation
must ship with; one that cannot be answered blocks the step it belongs to.

### The scanner pool

| Case | Answer |
| :--- | :--- |
| A worker accepts the connection and never answers | The route's scan timeout ends it; the scan is retried once elsewhere inside the same deadline, never a second full timeout. Repeated timeouts count as health failures. |
| A worker answers `PING` but fails every scan (signatures missing, out of memory) | A failed scan counts against health the same as a failed check, so a worker that is "up" but useless leaves the pool. |
| A worker answers garbage, or a truncated reply | Anything that is not exactly clamd's `OK` or `FOUND` is a failed scan, never "clean". The reply is read with a size cap. |
| A worker always answers "clean" (compromised, or the wrong service on that port) | Not detectable per request. The add-worker EICAR test is repeated by the health checker on a slow interval; a worker that stops detecting it is removed and reported. This is why the address is administrator-only. |
| A worker's signatures are weeks old | Signature age is read with `VERSION`. Past a threshold (default 7 days) the worker is shown as stale and, as a setting, treated as unhealthy. |
| A health check flaps | Two-failure / two-success thresholds; state changes are rate-limited in the log and the event stream so a flapping worker cannot flood either. |
| All workers lost during an upload burst | `when_unavailable` applies per request. Requests are refused or passed immediately; they do not queue waiting for a worker, so memory stays bounded by the scan semaphore. |
| Many slow scans at once (large files, slow worker) | The per-route semaphore bounds buffered bytes. A request that cannot get a slot within the wait budget is answered by `when_unavailable`, not held. |
| An administrator enters a worker address that is the cloud metadata service or the gateway's own management port | The add-worker test must see clamd's EICAR answer before saving, so an address that is not clamd is never stored. No response body from the address is shown in the dashboard beyond version and verdict. |
| A worker address resolves to a different host later (DNS change) | Resolved at connect, as today. The periodic EICAR check is what notices a host that is no longer a scanner. |
| A scanned file reaches a worker over a network someone can read | Plaintext is stated in the dashboard next to the address. Not solved by this ADR. |
| Config file edited on disk with 500 workers, or a bad address | The bound (16) and the address grammar are enforced at load as well as at save; the excess is refused with the reason, and scanning continues on the valid entries. |
| An operator, or a route's middleware, tries to add a worker | Refused: ADR 0087. Tested on REST, gRPC and Connect. |

### Base64 in JSON

| Case | Answer |
| :--- | :--- |
| The same key twice (`{"file": clean, "file": malware}`) | Backends disagree on first or last. Every occurrence is scanned; in `block` a duplicated file field is itself refused. |
| The key written with escapes (`"f\u0069le"`) | Keys are compared after JSON unescaping. |
| The value is base64 of base64, or base64 of a gzip or zip | Decoded once: that is what the backend stores. ClamAV unpacks archives itself. A second base64 layer is scanned as the text it is and noted in the ADR's limits; the field is the contract. |
| Whitespace, line breaks, `-_` vs `+/`, missing padding, a `data:` prefix | Every decoding a lenient backend applies is tried. If two decodings give different bytes, both are scanned. |
| Bytes after valid base64 (`TVqQ...==garbage`) | Not valid base64 as a whole: recorded in `report`, refused in `block`. A decoder that stops at the padding is exactly the mismatch to avoid. |
| The file is in a field nobody named | Not scanned, and the dashboard says "only the fields listed are scanned" beside the setting. This is the stated limit. |
| The named field is an array of 10,000 files, or nesting 10,000 deep | Bounds from config: maximum files per request, maximum JSON depth, total decoded bytes per request. Over a bound: recorded in `report`, refused in `block`. |
| A 50 MB JSON body with no file in it, sent to burn CPU | The walk is one streaming pass with no decoding unless a named field is found, bounded by the route's body cap. Benchmarked; if it cannot be shown allocation-free for the no-match case the feature is tiered. |
| Content-Type lies (`text/plain` with a JSON body, or `application/json` with something else) | Backends differ on whether they trust the header. Scanning follows the route's setting, not the header: a route with `json_file_fields` attempts the walk on any body that parses as JSON. A body that does not parse is not a JSON upload and passes as today. |
| JSON that Go parses one way and the backend another (comments, trailing commas, duplicate keys, big numbers, invalid UTF-8) | The same class as the multipart mismatches already handled. A body the strict walker rejects but that carries a named key as text is recorded in `report` and refused in `block`. Fuzzed against at least two other parsers' accept sets. |
| `Content-Encoding: gzip` on the request | Checked against how `file_security` handles compressed multipart today before building; the two must give the same answer. Decompression is bounded or the body is treated as unscannable. |
| Chunked body with no length | Read up to the scan cap, as multipart is today. |
| A clean file ClamAV wrongly flags | `report` shows it before `block` is on. In `block`, the refusal names the signature so an administrator can allowlist that signature, not turn scanning off. |
| `report` mode left on forever | The dashboard shows the route as "reporting, not blocking" with the count it would have blocked, so it cannot be mistaken for protection. |
| The scanner is down in `report` mode | Recorded as unscanned and forwarded. `report` never refuses, whatever `when_unavailable` says. |
| The security event stores the file name or the JSON value | Attacker-controlled text: truncated, stored as text, rendered escaped in the dashboard. The file's bytes are never stored. |

### What stays possible after all of it

A file encrypted or password-protected, a file split across requests and
assembled by the backend, a file fetched by the backend from a URL in the
request, and malware no signature knows. A scanner at the gateway reduces what
reaches the backend; it does not replace the backend treating an upload as
hostile.

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
