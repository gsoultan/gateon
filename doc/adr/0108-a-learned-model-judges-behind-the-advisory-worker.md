# 108. A learned model judges behind the advisory worker

Date: 2026-11-28

## Status

Accepted. `sec` drives: request data reaches a model on another host, and
what the model says can be held against a client. `arch` co-signs where the
code lives and that no trust boundary moves. `mem` and `perf` challenge what
the gateway pays (nothing), `qa` challenges that the rows a model is taught
on and the rows it is asked with cannot drift apart, and `ops` challenges a
new key and a new address.

## Context

ADR 0104 gave the gateway a second opinion, asked after the request is
answered. The reference worker runs the gateway's rules with every family on
at paranoia 4, and that ADR says what it costs: at that level it flags
ordinary requests on some applications, so `record` is the default and
nobody can sensibly turn on `reputation`.

Paranoia 4 has the signals and lacks the judgement. One low-confidence match
is usually noise; three families matching one request, with half its bytes
percent-encoded, rarely is. A threshold on an anomaly score cannot weigh that;
a small model taught on labelled requests can.

mimir-server (github.com/gsoultan/mimir-server) already teaches and serves
such models: gradient-boosted trees and forests over a table
(`table-boost`, `table-auto`), predictions batched per model, Shapley
explanations of each answer, versions with shadow trials, drift and accuracy
alerts, and API keys of a viewer limited to one model. What it lacks is a
row: something that turns a gateway's sample into columns, the same way when
it teaches and when it is asked.

ADR 0104 rejected a learned model *in the gateway*: it does not fit beside
the proxy in 2 GB, cannot explain itself, and one that learns from live
traffic can be taught by an attacker. None of those is true of a model on
another host, asked by the worker, taught only on curated rows.

## Decision

**The advisory worker can judge by a model on mimir-server.**
`gateon advisory-worker --judge mimir --mimir-url URL --mimir-model ID
[--threshold 80]`, with the API key in `GATEON_MIMIR_API_KEY`. The gateway
does not change: it sends the same samples to the same worker address, with
the same queue, deadline and bounds (ADR 0104).

**One package builds every row.** `internal/security/waf/features` turns a
sample into 28 columns: how many rules of each family the strict rules match
(scanning detect-only at the worker's paranoia level, so every rule that
matches counts, not just the one that would refuse), the highest confidence
reached, the anomaly score, how many rules the gateway itself matched and why
the sample was sent; then the request's shape (method, path depth and length,
extension, number of parameters and headers, longest value, its entropy, the
share of percent-encoded and of symbol bytes, double encoding, dot segments,
control bytes) and three header signals (what kind of user agent, whether
Accept is missing, whether there is a Content-Type). `gateon
export-waf-features` and the worker both call `Extract`, so a model is never
asked with a row built differently from the ones it learned.

**No column holds the client's text.** Every value is a number or a word from
a closed list, and a fuzz target fails the build if a client can make it
otherwise. A model cannot memorise a payload, and an operator can read every
column it was taught on. The sample carries no client address and no time
(ADR 0097, ADR 0104), so there are no per-client columns either; how a client
behaves across requests stays the reputation system's question.

**The labels are curated, never the model's own.** `gateon
export-waf-features --attacks FILE --clean FILE` writes a labelled CSV for a
mimir dataset. Attack rows come from files the operator names: gwaf's attack
and drill corpora, and findings someone has read. Clean rows come from gwaf's
false-positive corpus and `gateon export-waf-corpus`, with two filters,
because an Audit Only route forwards an attack that the origin answers 200
and the gateway cannot tell the two apart (ADR 0097): a clean request the
strict rules match at High or Certain confidence is left out, and at most
`--per-template` (20) clean rows are kept of one method, path and set of
parameter names, so whoever floods one shape into the corpus does not
outweigh every other. The export says how many of each it left out.

**The model's word is weighed like the rules' word.** The worker asks for the
chance of `attack`; at or above `--threshold` it returns a verdict labelled
`learned`, scored with that chance, and a reason naming up to three columns
that moved it, from mimir's explanation (at most eight explanations a batch,
and only columns this package defines). Below the threshold it says nothing,
even when paranoia 4 would have flagged the request: precision is the point.
The verdict goes through ADR 0104 unchanged: `record` by default, a
reputation score capped at 60 in `reputation` mode, never a refusal.

**A model that does not answer costs precision, not the second opinion.**
mimir is asked four samples at a time, each call within two seconds and the
batch within seven, inside the gateway's ten. A sample mimir did not answer,
answered with an error, a redirect, or more than 64 KiB, is judged by the
rules as the reference worker judges it. The worker logs once when mimir stops
answering and once when it starts again.

**Reaching mimir is held to the worker's own rules.** The address is https,
or http to this host, with no credential, query or fragment; redirects are
not followed; the key is environment only and is sent to that address alone.
The key should be a viewer's, limited to the one model.

## Cost

The gateway: nothing. No code on the request path changed, and nothing
allocates, waits or is stored that ADR 0104 did not already bound.

The worker, on its own host: a second gwaf engine (the detect-only scanner)
beside the reference one, and one `Extract` per sample. The scanner's scan
dominates; `BenchmarkExtract` measures the pair.

mimir: one prediction per offered sample, batched by mimir per model, and
at most eight explanations per batch.

## Upgrade and rollback

No migration, no proto change, nothing on disk, and nothing the gateway
reads. `--judge` defaults to `rules`, which is the reference worker as
before. Rolling the worker back stops the model's verdicts; entries of type
`waf_advisory` already in the Security Hub stay as they are.

## Consequences

- The model is as good as its labels. Its value over paranoia 4 is fewer
  false positives at the same recall, and that has to be measured on a
  holdout it never learned from — recall on the attack corpus, false
  positives on the clean one, both reported, never one alone — before
  `reputation` mode is considered. mimir's shadow trial is the place to try a
  new version against live samples first.
- A model taught on what gwaf matches mostly learns gwaf. It does not find a
  new attack class; it ranks the weak signals gwaf already has. A finding an
  operator confirms should still become a gwaf test.
- Every sample is written by a client, so a client can try to steer the score
  down. That is why the verdict never refuses and is capped in reputation
  mode.
- mimir keeps each question's fields for 30 days for feedback. They are
  columns, not requests, but they describe what clients asked; mimir should
  run on a host the operator controls.
- Columns are a contract with every model already taught. Renaming or
  removing one makes older models read it as empty; adding one is safe, and
  a model learns it on its next teaching.
- There is no way yet to send an operator's "confirmed" or "not an attack"
  back from the Security Hub. That needs a proto change and a migration and
  is its own decision.

## Rejected

- **Asking mimir from the gateway.** It would put a second remote host on
  the gateway's side of the boundary, and gain nothing the worker cannot do
  after the response is sent.
- **Payload text as columns** (n-grams, tokens, an embedding). The model
  could memorise strings, a column could no longer be read, and every
  question mimir keeps would hold what the client wrote.
- **Teaching from the gateway's verdicts alone.** The model would learn the
  rules it is meant to second-guess, and an attack an Audit Only route
  forwarded would be taught as clean.
- **mimir-server-sdk.** Two Connect JSON calls over raw HTTP, as ADR 0070
  does for language models, keep a new module out of the gateway's build.
