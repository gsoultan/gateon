# 8. Response inspection must control its own content encoding

Date: 2026-08-26

## Status

Accepted. Narrows ADR 0004, which replaced the WAF engine but carried the
response-phase design across unchanged.

## Context

Gateon's data-leak rules run at `PhaseResponseBody`: card numbers, private keys,
cloud credentials, webhook URLs. They are enterprise-tier or an explicit `dlp:
true` opt-in, they buffer the response to a ceiling, and they block or truncate
when they match.

They never matched.

`httputil.ReverseProxy` forwards the client's `Accept-Encoding` verbatim — it
strips hop-by-hop headers and nothing else — and Go's `http.Transport` only
transparently decompresses a response when *it* added that header itself. Every
browser sends `Accept-Encoding: gzip, deflate, br`. So the origin compressed, the
transport passed the compressed bytes through untouched, and the WAF handed its
rules a DEFLATE stream.

There is no grammar in a DEFLATE stream. `\bAKIA[0-9A-Z]{16}\b` matches nothing
in it, `-----BEGIN PRIVATE KEY-----` matches nothing in it, and the response was
reported clean while the browser decompressed and rendered the credential. One
request header disabled the entire control, for the default case rather than an
edge one.

The engine already closes this on the request path, and says why:

> Decompression comes first, because everything downstream — content-type
> dispatch, field parsing, every detector — operates on the body the application
> will receive. A compressed body inspected as-is is opaque […] That is the
> entire firewall disabled by one header.
>
> — `gwaf/transaction.go`, `recordBody`

`Transaction.decompress` is called at exactly one site, on the request body.
`tx.contentEncoding` is only ever assigned inside `AddRequestHeader`.
`WriteResponseBody` appends raw chunks to the arena and `ProcessResponseBody`
resolves them verbatim. The response path had no equivalent.

The router comment claiming the WAF "sees uncompressed data (running before
Gzip)" is true of gateon's *own* compress middleware, which runs outside the WAF
and compresses on the way out. It says nothing about the origin, which is where
compression actually comes from.

Two ways to fix it, and the choice matters:

1. **Strip `Accept-Encoding` upstream entirely.** The transport then adds gzip on
   its own behalf and decompresses transparently, so the WAF sees plaintext with
   no decoder in gateon at all. But the response forwarded to the client is then
   uncompressed unless the compress middleware happens to be attached to that
   route — enabling DLP would silently switch off compression for every client.
2. **Decode in the response writer.** Compression to the client is preserved
   exactly, but it needs decoders, and brotli — which every browser offers — is
   not in the standard library. Adding a decompressor to the request path is a
   supply-chain decision, not a bug fix.

Neither alone is right: (1) re-prices bandwidth for every existing install, (2)
leaves the hole open for the encoding browsers actually prefer.

## Decision

**Response inspection negotiates the encoding it can read, rather than accepting
whatever the origin chooses.**

Outbound, when response inspection is on, the client's `Accept-Encoding` is
narrowed to an encoding this build can undo — gzip when the client offers it,
deflate failing that, `identity` when the client will take neither. The client's
own value is restored before the handler returns, so access logs, telemetry and
fingerprinting still see the request the client actually sent.

Inbound, the held body is inflated once under a ceiling and the *inflated* bytes
go to the engine, while the **original** bytes are forwarded to the client
unchanged. Compression to the client survives, `Content-Length` stays true, and
the rules see what the browser will render.

Three supporting constraints:

- **An undecodable response is not a clean one.** An origin that ignores the
  negotiated header, a chained `Content-Encoding`, or a stream that will not
  inflate is recorded as uninspected. The distinction between "read and found
  clean" and "could not be read" has to survive, or the operator is told they
  have coverage they do not have.
- **Inflation is bounded.** A compressed body is an amplifier; inflating one
  without a ceiling is an unbounded allocation chosen by the origin. Output is
  capped at the same limit that bounds the hold-back buffer, and hitting the cap
  is reported as truncation rather than swallowed.
- **Only bodies a rule could match are inspected.** Images, fonts, video,
  archives and `octet-stream` stream through with no buffer and no scan. An
  unknown or absent content type is inspected, because a body an origin declined
  to label is where a leak hides best.

Brotli and zstd are handled by not asking for them. That is a stated limit, not a
silent one: a client that offers only brotli gets `identity` on the origin hop.

## Consequences

**A default changes.** A route with response inspection enabled now sends a
different `Accept-Encoding` upstream than the client sent. Origins see gzip where
they used to see brotli. Anything keying behavior off that header on the origin
side — a CDN in front of the origin, a cache varying on it — sees the narrowed
value. This applies only to routes where inspection is on, which is enterprise
tier or an explicit opt-in.

**Bandwidth on the origin hop can rise.** A client offering only brotli forces
`identity` between gateway and origin. Browsers all offer gzip, so in practice
this is limited to bespoke clients.

**Inspection now costs CPU it previously did not.** It was cheap because it was
doing nothing. Inflating a gzipped body is real work, paid per inspected
response. The content-type gate is what keeps the total below where it was:
against a 256 KiB `image/png`, the response path went from 5.39 ms and 2065 KiB
to 19.4 µs and 260 KiB (`BenchmarkWAFResponseBinary`, n=6). An inspected
`text/html` body of the same size is unchanged in time and 12% lighter, the
hold-back buffer now coming from a pool.

**A dead branch became live and had to be fixed.** `bufLimit <= 0` was
unreachable while every inspected response was buffered. The content-type gate
reaches it, and it committed the header without marking the response flushed —
so `Flush` no longer reached the client and `finish` wrote the status line twice.
Covered by `TestWAF_UninspectedResponseStreams`.

**Archives stay uninspected.** A credential inside a ZIP or a PDF is a real leak
and this does not catch it. Archive inspection is a different control with a
different cost; pretending a regex over compressed bytes covers it would be the
worse answer.

**The gap this closes was invisible to every test.** The suite exercised the
response path with uncompressed bodies, so it passed throughout. The regression
test drives the origin the way a browser does — it compresses because the request
asked it to — which is the only shape in which the defect appears.
