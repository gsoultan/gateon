# 107. The request that passed after a search is recorded

Date: 2026-11-28

## Status

Accepted. `sec` drives. `perf` and `conc` challenge what the request path
pays, `mem` challenges what is held, and `qa` challenges what counts as a
search.

## Context

An attacker who adapts from each answer does not look like a scanner. A
fuzzer, or a language model running a loop, sends a payload, reads the
refusal, reasons about it, and sends a changed one. It can send a few a
minute, which no rate threshold sees. `api_fuzzing` (`internal/telemetry/behavior.go`)
counts the *rate* of 403 and 404 responses, so it misses exactly this
attacker. ADR 0106 took away what the refusal said. It did not take away the
fact of the refusal, and the search can still go on.

The request that matters in such a search is the one the WAF finally let
through: different payloads from one client were refused on one endpoint,
and then a request from that client on that endpoint was forwarded. It is
the likeliest bypass the gateway will ever have in hand, and nothing pointed
an operator at it.

## Decision

**The WAF keeps a bypass watch** (`internal/security/waf/bypasswatch`). It
remembers, per client address, the endpoints on which the WAF refused that
client and how many *distinct* payloads were refused there. An endpoint is
the route, the method and the path. A forwarded request on such an endpoint,
once the count reaches the threshold, is a finding.

- **What counts as a refusal:** a request-phase WAF decision, and a
  fast-path refusal (entropy, fingerprint, token, protocol). Each refusal is
  hashed from the rule that refused it, the key it matched, the query string
  and the body length. A request retried unchanged counts once, so a client
  that just repeats itself is not running a search.
- **The threshold** is 5 distinct payloads. `GATEON_WAF_BYPASS_REFUSALS`
  sets it between 2 and 32.
- **A finding is an entry in the Security Hub** of type
  `waf_bypass_suspected`. It names the client, the route and the endpoint, and
  carries the forwarded request's query as the tuning sample captures it,
  with every credential masked (ADR 0097).
- **A finding is observed and held against nobody** (ADR 0059). The request
  was let through, and a person who retypes a form after a false refusal
  looks the same. That case is a false positive the tuning loop wants to see.
- **One finding per search.** The endpoint's count starts again after it, so
  a client that keeps getting through is not reported on every request.

**Bounds.** `WAFBypassWatchSources` clients per tier: 256, 1024 and 4096.
`GATEON_WAF_BYPASS_SOURCES` overrides it, capped at 65536, and 0 turns the
watch off. The client refused longest ago makes room for a new one. For each
client the watch keeps at most 8 endpoints and 32 payload hashes per
endpoint. A client idle for an hour is forgotten. That comes to about 5 KiB a
client at most, so 5 MiB on `standard`.

**The request path.**

- **A refusal** hands its event to the watch's goroutine on a channel of 256
  events. When the channel is full the event is dropped and counted.
- **A forwarded request** costs one lock-free `sync.Map` lookup of its
  client's address: 11 ns, with no allocation.
- **Only a client with a search under way** (an endpoint at the threshold) is
  in that map. Only that client's forwarded requests are captured and handed
  over, so a client refused once, which is usually a person, costs its later
  requests nothing.
- **One goroutine** owns every count and stops with the gateway.

`BenchmarkWAFRequestWithoutInboundDLP` before and after: 3.07 ms and
3.11 ms ± 14% (p=0.38), and 559 allocations both times.

## Upgrade and rollback

There is no migration, no proto change and no new route setting. The watch is
on by default and only adds Security Hub entries, so a previous release reads
the new threat type as it reads any type it has no special case for.

## Consequences

- The source is the client's address. A search spread over many addresses
  is not one search here. The attack graph (`internal/telemetry/graph.go`)
  is where a client class across addresses is seen.
- A search against an endpoint whose path changes on every request (an
  identifier in the path) is several endpoints. A search usually holds the
  endpoint still and varies the payload.
- The watch is one process's. Behind several gateways, each has its own.
- Acting on a finding automatically (blocking the client for a while) is not
  built. A finding is a request the WAF judged clean, and refusing on it would
  refuse for a reason no rule names. The finding is for an operator to read
  and turn into a rule.

## Rejected

- **Counting refusals per parameter.** A forwarded request's parameters
  would have to be parsed on the request path for every followed client, and
  a search moves between parameters as readily as between payloads.
- **Feeding the finding to reputation.** See ADR 0059.
