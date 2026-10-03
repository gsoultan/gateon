# 47. A backend the dashboard shows is a backend the gateway checks, weighs and reports truthfully

Date: 2026-10-03

## Status

Accepted. Owned by `net` (health checks, balancing, the service save rules),
challenged by `ux` (what the service, middleware and Circuit Breaker pages say).
`perf` signs the balancer pick (benchstat below); `qa` the regression tests.
Follows ADR 0043: a setting that saves does what its label says, or is refused.

## Context

The 2026-10-02 truth review (T15-T18, T24, T29, T33, T34) found the traffic
controls the dashboard offers by default saying one thing and doing another:

- **T15 -- the default health check checked nothing.** A service saved from the
  form's defaults (type "Auto", no path) resolved to an HTTP check, and an HTTP
  check was enabled only with a path. A dead backend stayed in rotation for
  good (one request in N got 502) and `/v1/routes/stats` showed it `alive:true,
  CLOSED`.
- **T16 -- target weights were ignored under the default policy.** The form shows
  a Weight on every target ("Higher weight = more traffic"); round robin, the
  default, rotated evenly (1:2:6 gave 30/30/30). Weighted round robin honoured
  weights but in runs (6:1:1 sent six in a row to one backend; a canary at
  50/50 took 40-request bursts).
- **T17 -- the circuit breaker could not be created from the dashboard, and an
  open one read CLOSED.** The per-target rows derived their state from the
  health check alone, so a breaker refusing the route's every request with 503
  read CLOSED and the OPEN filter hid it.
- **T18 -- a malformed IP filter entry saved and blocked nothing.** `127.0.0.*`, a
  range, `/33` were dropped with a server WARN; the save answered 200.
- **T24 -- Mitigate reported success for addresses it never refuses.** Loopback
  and `GATEON_MITIGATION_ALLOWLIST` are exempt on every data path; the handler
  read back "is it listed", not "is it refused".
- **T29 -- a rebuild reset per-target counts.** The governor's purge under memory
  pressure, and any service save (even another service's), started every
  target's request and error counts again at zero.
- **T33 -- "Max Concurrent Requests" was per client address**, and with
  `per_ip=false` it keyed on the client-written Host.
- **T34 -- canary rollback judged the service's lifetime error rate**, so a long
  healthy history diluted a failing step below any threshold, and a rollback
  never appeared in the dashboard.

## Decision

**Health (T15).** Every service with targets is checked. With no path to
request, the check connects to the target (TCP), under the existing thresholds:
2 consecutive failures take a target out of rotation, 2 consecutive successes
bring it back, every 15 s. An explicit HTTP check with no path is refused at
save. Behaviour, stated per `net`'s proof rule:

- *One backend down:* out of rotation after two failed checks (at most ~35 s
  including the 5 s check timeout); its turns go to the live targets in
  proportion to their weights; back after two good checks. Until the second
  failed check its requests get 502 -- there is no passive ejection; the retry
  middleware covers that window for idempotent requests.
- *All backends down:* the route answers **503** "no healthy targets available"
  (it answered 502, which says a backend answered badly; none was asked).
- *Mid-rollout* (targets replaced by a service save): the rebuilt handler
  inherits its predecessor's health conclusions and counts for every target it
  keeps; new targets start in rotation and are checked; the old handler drains
  its in-flight requests (up to 30 s) before closing.

**Weights (T16).** Round robin serves targets in proportion to their weights with
a smooth (nginx) schedule computed when the targets change; the pick stays one
atomic increment and a slice index while the target it lands on is alive.
Weighted round robin is the same balancer. No target carrying a weight means
equal shares; once any target has one, a target at 0 is on standby (how a canary
is held at 0%). A cycle longer than 4096 entries (after dividing by the common
factor) is not interleaved but keeps exact proportions. Least connections, the
predictive balancer and TCP/UDP services do not read weights, so differing
weights there are refused at save, as are unknown policy names and negative
weights; the form hides the weight field there and saves 1. A canary may now run
on round robin.

**Circuit breaker (T17).** The dashboard can create one (error threshold, minimum
requests, window, sleep window -- the keys the gateway reads, defaults as
placeholders). A route whose chain has a breaker reports its state on every
target row: `circuitState` is OPEN when the health check took the target out
*or* the breaker is open, HALF-OPEN while it probes; `breaker` carries the
breaker's own state. Whether the chain has one is decided per build, so a
breaker removed from a route stops being reported.

**IP filter (T18).** `NewIPFilter` refuses the first entry of either list that is
not an IP address or CIDR, naming the list and the entry. Every transport
validates a middleware by building it, so REST, gRPC and config import all
refuse at save; a stored filter that no longer builds makes its route answer 503
(the router's rule for an unbuildable security middleware), not serve
unfiltered. The dashboard marks such entries before saving.

**Mitigate (T24).** The block is still recorded, but an address the request path
exempts gets `success:false`: "recorded on the block list but is not enforced",
naming loopback or the allowlist.

**Counts (T29).** A handler hands its replacement its per-target request, error
and latency counts along with its health conclusions, on direct replacement,
invalidation and purge alike (one snapshot per route, dropped with the route).

**In-flight cap (T33).** Per client address stays the default and the label says
so ("per Client Address", 429). `per_ip=false` is now one count for the route
the middleware is attached to (503), labelled "(total)".

**Canary (T34).** Each step is judged on its own requests: errors over requests
since the step began; a step that served nothing is not judged on errors. A
rollback is written to the Circuit Breaker page's event timeline as
`service <id> (canary)`, OPEN, with the step's rate.

## Consequences

- Every HTTP service now opens a TCP connection to each target every 15 s, or
  sends its path. Backends that log connections will see them.
- Saves that used to succeed are refused, each naming the fault: an explicit HTTP
  check without a path, differing weights under a policy or backend type that
  ignores them, an unknown policy, a negative weight or threshold, a malformed IP
  filter entry. Stored ones: a malformed IP filter makes its route answer 503
  until fixed; the service rules apply only at save (a stored service keeps
  working as it did, except that its health is now checked and round robin now
  honours its weights).
- Services saved through the API with mixed 0 and non-zero weights under round
  robin now hold the 0-weight targets on standby, as weighted round robin did.
- Pick cost (benchstat, darwin/arm64, n=10): round robin 1.70 -> 1.81 ns,
  weighted 1.71 -> 1.88 ns, one of three down 2.41 -> 2.93 ns, contended
  parallel 28.2 -> 28.1 ns (~), weighted round robin 3.26 -> 1.93 ns; 0 allocs
  before and after. A schedule is at most 16 KiB per route.
- Requests still in flight on a replaced handler after its counts were carried
  are not added to the new one: at most the in-flight count, once per rebuild.
- Left open: the canary's p99 is still the service's lifetime histogram (a
  per-step percentile needs the histogram buckets, which `GoldenSignals` does
  not carry; `internal/telemetry` is at its file ceiling). A canary status RPC
  would show progress and outcome in the wizard itself; it needs a proto change,
  which this round reserved to another owner. The management allowlist
  (`GATEON_MANAGEMENT_ALLOWED_IPS` / `management.allowed_ips`) is still parsed
  leniently; `security.ValidateIPList` is exported for whoever owns that save.

## Alternatives considered

- **Refuse weights under round robin** instead of honouring them. Round robin is
  the default and the form shows weights on every target; honouring them makes
  the default do what the form says and costs a fraction of a nanosecond.
- **Keep "empty path disables checks" and say so in the form.** A default that
  leaves a dead backend in rotation is the defect; the connect check is cheap.
- **Passive ejection on proxy errors.** Faster than two check intervals, but a
  new failure mode (one client's bad requests ejecting a healthy backend); left
  to the circuit breaker, which is now creatable.
- **Report the breaker on a separate row.** The page is per target, and a route's
  breaker gates every target behind it; one state per row, with `breaker` beside
  it, keeps the OPEN filter and the counts meaningful.
