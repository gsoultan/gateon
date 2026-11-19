# 97. The gateway keeps a sample of forwarded requests for tuning

Date: 2026-11-17

## Status

Accepted. `sec` drives (request data leaves the request path); `mem`
challenges what the sample may hold; `conc` challenges what the request path
pays; `arch` co-signs where the code lives.

## Context

gwaf tunes from a corpus of benign requests. `gwaf tune` suggests the
narrowest exception for each false positive it measures, and `gwaf tune
-schema` drafts an OpenAPI document for an API nobody described. Its design
(gwaf CONCEPT §12) splits the work on purpose: the analysis belongs to the
toolchain, and reading *your* traffic belongs to the embedder, because there
is no universal access-log format. Its example names the embedder's half:

```
$ gateon export-waf-corpus > corpus.jsonl
$ gwaf tune -corpus corpus.jsonl
```

That command did not exist. A gateon operator who wanted to tune wrote the
corpus by hand, and a hand-written corpus measures the imagination of whoever
wrote it.

The data is the problem. A corpus is real requests, and the gateway's rule is
that what it records carries no credential (ADR 0041, `internal/security/redact`).
An access-log export would also be a second copy of everything the access log
holds, written somewhere new.

## Decision

A WAF middleware has a sample rate, `corpus_sample_rate` (0, the default, is
off). At a rate of N, one in N of the requests the WAF forwards is kept if the
origin then answers 2xx or 3xx.

**What is kept is the least tuning needs.** Method, path, query parameters and
request headers. No body, no client address, no time. A header whose name or
value says credential is left out. A query parameter that does is kept under
its name, because an exception is scoped to a name, with its value masked.
A request that does not fit in 4 KiB or 48 parameters and headers is left out
whole: a truncated value is one the client never sent.

**What is kept is a claim of benign, as far as the gateway can make one.** A
request the WAF refused never reaches the sample. One the origin answered 4xx
or 5xx does not either. On an Audit Only route a request the WAF would have
refused is forwarded, and is kept if the origin accepts it: that is the false
positive tuning exists to find, and it is also what an attack an application
answers 200 to looks like. The gateway cannot tell those apart and does not
pretend to. `gwaf tune` refuses a corpus in which too many requests match at
High or Certain confidence, and that refusal is the check.

**It lives in memory, in a ring of fixed size.** `WAFCorpusEntries` per tier:
512, 2048 and 8192 entries, so at most 2, 8 and 32 MiB, and nothing when no
route samples. `GATEON_WAF_CORPUS_ENTRIES` overrides it, capped at 65536. The
newest entry displaces the oldest, and a restart empties it. Nothing is
written to disk on the request path, and there is no second store of traffic
to retain, encrypt, back up or forget.

**The request path pays one atomic add.** All but one request in N do nothing
else. The sampled one builds its entry before the proxy rewrites headers,
wraps the response writer to learn the status, and stores a pointer. There is
no lock and no channel.

**Reading it takes the permission to change the rules.** `GET /v1/waf/corpus`
answers JSON Lines to a caller with write on the WAF rules, not to anyone who
may view diagnostics. `gateon export-waf-corpus [API URL] [--token TOKEN]`
writes it to standard output, and says so when the sample is empty instead of
writing an empty file.

The code is `internal/security/waf/corpus`: the two WAF packages are at their
file limits, and the sample is its own concern.

## Consequences

- An upgrade request is never sampled. It has no status to judge it by.
- The sample is one process's. Behind several gateways, export from each.
- A rule that fires on a credential cannot be tuned from the sample, because
  the credential is not in it. That is the right way round.
- Bodies are not kept, so a false positive in a request body is still tuned
  from the audit log by hand. Keeping bodies is a larger decision about
  personal data than this one, and is not taken here.
- `corpus_sample_rate` is route configuration, so a sample rate is visible in
  the route's config and its audit trail like any other setting.

## Rejected

- **Exporting the access log.** It holds client addresses and times the
  toolchain does not need, in a format that would have to be converted, and it
  would make a credential-bearing copy of traffic the default path to tuning.
- **Writing the sample to the database.** A synchronous write on the request
  path, or a queue with a writer and a retention policy, for data whose whole
  life is "until the operator exports it".
- **Keeping only requests no rule matched.** It would make the sample safe and
  useless: the requests worth tuning are the ones a rule matched.
