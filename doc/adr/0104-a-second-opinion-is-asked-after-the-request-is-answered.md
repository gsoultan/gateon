# 104. A second opinion is asked after the request is answered

Date: 2026-11-22

## Status

Accepted. `sec` drives and co-signs `arch`: request data crosses to another
host, and what comes back can be held against a client. `perf` and `mem`
challenge what the request path and the 2 core / 2 GB host pay; `conc`
challenges the one goroutine; `ux` challenges a switch that can be on and do
nothing; `ops` challenges a second process shipped in the same binary.

## Context

The WAF judges a request in microseconds, with rules that name what they
matched. Both properties are the point, and both rule out the detection people
ask for next: a slower, broader judge — every rule family at the highest
paranoia level, or a classifier — that would catch what a route's tuned policy
lets through. Run inline it costs every request a network hop or a model's
latency, takes the gateway's memory, and refuses requests for reasons nobody
can read. A separate host removes the memory problem and leaves the other two.

ClamAV works as a worker because only uploads wait for it. The same shape
works here if nothing waits at all.

The gateway already knows which forwarded requests are worth a second look:
the ones a rule matched and the policy let through (audit-only, or scored
under the route's threshold), and the ones outside the route's OpenAPI
document in record mode. It already has a way to keep a request without its
credentials (ADR 0097), and a place where a detection becomes evidence against
a source or does not (ADR 0055).

## Decision

**A route's WAF may offer the requests it forwards to an advisory worker, and
the worker is asked after the request has been answered.** Nothing the worker
says refuses a request.

**What is offered.** `advisory_review` on a WAF middleware (off by default)
offers every forwarded request a rule matched, every forwarded request outside
the route's document, and one in `advisory_sample_rate` of the rest (0, the
default, is none). A request the WAF refused is not offered: that question is
answered.

**What leaves the gateway is the tuning sample's entry** (`corpus.Capture`):
method, path, query parameters and headers, with every credential removed. No
body and no time. With it go a number, why it was sent, and the numbers of
the rules the gateway matched.

**The client's address never leaves.** The worker answers for a sample's
number, and the gateway keeps, beside the sample and outside what it sends,
whose request that was. A worker that is compromised learns what clients ask
this route, not who they are.

**The worker is one address, set on the gateway**, not per route:
`GATEON_WAF_ADVISORY_URL`, with `GATEON_WAF_ADVISORY_TOKEN` sent as a bearer
credential. The address must be `https`, or `http` to this host; one that
carries a password, a query or a fragment is refused, and so is the feature,
with one error in the log, rather than the gateway's start. A redirect is not
followed: it would carry the token and the samples wherever it pointed.

**Everything is bounded and nothing waits.** The request path does one
comparison on a route that does not ask, and on every route once the queue is
full. The queue is `WAFAdvisoryQueue` samples per tier — 64, 256 and 1024, at
most about 6 KiB each — `GATEON_WAF_ADVISORY_QUEUE` overrides it, capped at
4096. A full queue drops the sample and counts it. One goroutine sends, one
batch of at most 32 at a time, with a ten-second deadline, and stops with the
gateway. A worker that does not answer loses its batch, is retried with a
backoff that doubles to a minute, and is reported once when it stops answering
and once when it starts again.

**The answer is not believed past what was asked.** At most 256 KiB of it is
read. A verdict for a number that was not in the batch is counted and dropped;
a sample is judged once however often it is named; a label is lower-case
letters, digits, `_` and `-` or it is "unlabelled"; a reason is printable text
of at most 240 bytes.

**A verdict is an entry in the Security Hub**, type `waf_advisory`, about the
request the gateway sampled. `GATEON_WAF_ADVISORY_MODE` says what else it is:

- `record`, the default: observed, as an audit-only match is, and held against
  nobody (ADR 0055).
- `reputation`: evidence against the source, like a detection of the
  gateway's own. Its score is capped at 60, below the 80 at which the gateway
  mitigates a source on one threat, so a client is refused on what a worker
  said only after the worker has said it of several requests — and then by the
  reputation rule, with its rule number, not by the worker.

**A reference worker ships in the binary**: `gateon advisory-worker
[--listen 127.0.0.1:8787] [--cert FILE --key FILE] [--paranoia 4]`, which
takes its token from `GATEON_WAF_ADVISORY_TOKEN` and will not start without
one. It runs the gateway's own rules over each sample with every family on, at
the highest paranoia level, with no exception — a policy that would refuse too
much to stand in front of anything, which is what a second opinion is for. Its
verdict names the rule. It does not repeat a rule the gateway already matched
on that request. The exchange is one `POST /v1/advise` of JSON; anything that
answers it can stand in the reference worker's place, and a worker that judges
by other means is why the exchange is its own thing.

**The dashboard says when the switch does nothing.** `GET /v1/waf/advisory`
answers whether the gateway has a worker, its host and mode, and how many
samples were offered, dropped, sent, lost and flagged — never the token. The
WAF form reads it as soon as the switch is on, and with no worker says so and
names the setting. A route that asks on a gateway with no worker also says so
in the log when it is built.

The code is `internal/security/waf/advisory`.

## Cost

A route that does not ask pays one nil comparison per forwarded request. A
route that asks pays, for a request that is offered, the sample: the same
allocation the tuning sample makes. Once the queue is full every request pays
one comparison more and nothing else, so a flood of requests worth asking
about costs what the worker can keep up with and no more. The gateway holds at
most the queue and one batch. Nothing is written to disk.

## Upgrade and rollback

No migration, no proto change, nothing on disk. `advisory_review` and
`advisory_sample_rate` are two more keys in a WAF middleware's string map,
written only when an operator sets them; a build that does not know them reads
the ones it does. The worker's address is environment only. Rolling back
stops the samples. Entries of type `waf_advisory` already in the Security Hub
are read by the previous release as it reads any threat type it has no special
case for.

## Consequences

- The reference worker sees no body, so it has nothing to say about an attack
  that lives in one. It sees query parameters by name and value, not in the
  order or the encoding the client used, so it cannot see an attack that lives
  in either.
- At paranoia 4 the reference worker flags ordinary requests on some
  applications. That is why `record` is the default and why the form's status
  line says which mode the gateway is in. Reputation mode is for a worker
  whose findings have been read.
- In reputation mode whoever controls the worker can lower the reputation of
  any client whose request is sampled. The cap bounds one verdict, not many.
  The worker is as trusted as a reputation feed, and should be run like one.
- A verdict arrives after the request was served. This finds what got
  through; it does not stop the first one.
- Counters are per process. Behind several gateways each has its own queue,
  and they may share a worker.
- The worker's address is not in the dashboard. It is a deployment's
  decision about where request data may go, and changing it takes a restart.

## Rejected

- **Asking the worker inline, with a deadline.** Every request pays the hop,
  the gateway's p99 becomes the worker's, and a late answer has to fail open
  or closed. The one case worth it — a route that already waits, such as an
  upload — is not built here.
- **Letting a verdict refuse.** A block has a rule number and a matched span.
  A worker's word has neither, and the next request from that client would be
  refused for a reason no operator could check.
- **Sending the client address so the worker can correlate.** It is the one
  field a worker does not need to judge a request, and the one that turns a
  leaked batch into a list of people.
- **Configuring the worker's address from the dashboard.** It would need a
  proto field, a store column and a migration, and would let anyone who can
  edit settings point request data at a host of their choosing.
- **A learned model in the gateway.** It does not fit in 2 GB beside the
  proxy, it cannot explain a verdict, and one that learns from live traffic
  can be taught by an attacker.
