# 100. A route drafts its own API document from the shape of its traffic

Date: 2026-11-17

## Status

Accepted. `sec` drives (what is learned from hostile clients, and what a draft
may be allowed to do); `conc` challenges the lock; `mem` challenges what is
held; `ux` challenges how a draft reaches a route; `ops` challenges rollback.

## Context

A route can be checked against an OpenAPI document (ADR 0095). It is the
strongest check the WAF has, because it says what a request must look like
instead of what an attack looks like, and it is the least used, because most
APIs behind a gateway have no document and nobody is going to write one.

gwaf now drafts one from observed requests (`schema/infer`): path identifiers
become template segments, and a query parameter is declared an integer,
number, boolean, UUID, date or bounded string when every value seen fit. It
keeps shapes only, with no value, hash or enumeration.

`gwaf tune -schema` does this offline from an exported sample (ADR 0097). That
path needs a shell and a second tool. The dashboard is where a route's WAF is
edited, and it could not offer a draft.

## Decision

A WAF middleware has a switch, `schema_learning` (off by default). With it on,
the route learns the shape of each request it forwards and the origin answers
2xx or 3xx.

**What is learned is not traffic.** Method, path and query parameters go to
gwaf's learner, which keeps per parameter which grammars every value has fit
and the longest length seen. No value is retained, so there is nothing here to
redact and nothing a reader of the draft can recover about a client. That is
the difference from the request sample, and why the two have different
permissions.

**A draft enforces nothing.** It is read from the management API and shown in
the route's WAF form. Using it copies it into the form's document field, which
the operator then reads and saves like any document. The form does not offer a
draft over a document it already holds, and does not offer one while the route
is set to refuse requests outside its document: a draft describes the traffic
seen so far, and refusing by it unread would refuse what was not seen.

**What it learns from is what the application accepted.** A request the WAF
refused is never learned from, and neither is one the origin answered 4xx or
5xx. gwaf's draft is loose by construction (nothing required, nothing strict,
no ranges) and one odd value widens a field for good, so traffic can make a
draft more permissive and cannot make it refuse something it was shown.

**Learning never makes a request wait.** The learner is behind a lock that the
request path only tries. A request that finds it held is skipped: a draft is
built from thousands of requests and does not need each one. Reading the
drafts does wait for the lock, and only a dashboard reader pays that.

**Everything is in memory and bounded.** At most 64 routes learn at once, and
a route past that is counted and reported, not silently ignored. Each route is
within gwaf's limits: 256 operations, 32 parameters each, 128-byte names. A
restart forgets it.

**The API.** `GET /v1/waf/schema-drafts` answers each learning route's draft
and its counts, to a caller who may read middlewares. `DELETE
/v1/waf/schema-drafts/{route}` starts a route again, for write on middlewares.
`GATEON_WAF_SCHEMA_LEARNING=true` turns learning on for route WAFs that do not
set it. The gateway-wide WAF never learns: it fronts every API at once, and a
document drafted from all of them describes none.

The code is `internal/security/waf/schemalearn`.

## Cost

A learning route allocates one small status writer and one closure for each
request it forwards, parses the query string once more, and takes an
uncontended lock. A route that does not learn pays two comparisons. Learning
is meant to be turned on for a capture and turned off, and the form says the
draft is lost on restart.

## Upgrade and rollback

No migration, no proto change, nothing on disk. `schema_learning` is one more
key in a WAF middleware's string map, written only when an operator sets it; a
build that does not know the key reads the ones it does and ignores it. A
draft put in the document field is an ordinary `openapi_spec`, which the
previous release already compiles.

## Consequences

- Only the query string is learned. Headers and bodies are not, so a draft
  says nothing about them and gwaf does not check what a draft does not say.
- A path that looks like an identifier is templated: `/orders/17` becomes
  `/orders/{id}`. A static segment that happens to be numeric is templated too,
  and reading the draft is where that is caught.
- Drafts are per process. Behind several gateways each has its own.
- The dashboard has no control to discard a draft. The API does, and turning
  learning off and on does not clear what was learned; a restart does.

## Rejected

- **Applying a draft automatically.** A document nobody read, enforced against
  traffic it has not seen, is an outage with a security feature's name on it.
- **Persisting drafts.** It would need a table and a migration for data that
  is cheap to relearn, and an older build would have to tolerate the table.
- **Learning from every request, refused ones included.** A draft that had
  seen the attacks would declare them part of the API.
