# 74. Brotli encoders are bounded in cost and count, and the dashboard is served precompressed

Date: 2026-10-17

## Status

Accepted.

## Context

The compress middleware built every brotli encoder at the library's default
quality and window, and chose br whenever a client offered it. Once an encoder
has seen more than 64 KiB it holds about 11 MiB live. A gzip encoder holds about
1 MiB. Nothing bounded how many brotli encoders ran at once. In this package's
own measurement, 200 concurrent br requests for the dashboard's largest bundle
(418 KiB) held 2.2 GiB. An earlier review measured 901 MiB on the built gateway.
The management listener admits 500 requests at once, and the 2 core / 2 GB
target cannot hold that.

The management chain puts the compress middleware in front of the embedded UI.
UI assets need no authentication. So any client could start these encoders, and
the work was wasted: the dashboard build already writes a `.br` and a `.gz` next
to every asset, and the handler never used them.

## Decision

**One brotli encoder costs a bounded amount.** Encoders are built at quality 5
with a 2^18 (256 KiB) window. Measured on the largest UI bundle:

| Settings | Live per encoder | Size of output | Time |
| --- | --- | --- | --- |
| library default | 11.1 MiB | 27.0% | 14.7 ms |
| q5, LGWin 18 (chosen) | 2.6 MiB | 27.3% | 12.7 ms |
| q4, LGWin 18 | 2.1 MiB | 29.2% | 8.6 ms |
| gzip default | 1.0 MiB | 31.0% | 5.0 ms |

Quality 4 saves CPU, but its output is barely smaller than gzip's. At that point
brotli no longer pays for its memory. Raising the window above 18 cost 0.5 MiB
per step and made this input no smaller.

**Only so many brotli encoders run at once in the process.** The limit is one
counting semaphore shared by every route and the management listener, because
the memory it protects belongs to the process.

- The count is `TierDefaults.CompressMaxBrotliEncoders`: 8 on minimal, 32 on
  standard and 128 on enterprise. That is about 21, 84 and 336 MiB at most.
  `GATEON_COMPRESS_MAX_BROTLI_ENCODERS` overrides it. The limit cannot be
  turned off, and a value that is not a positive integer is ignored with a
  warning.
- Taking a slot never waits. A br response that finds no free slot is sent gzip
  if the client accepts gzip, and unencoded if not. The client pays a few
  percent more bytes and no extra latency. This differs from ADR 0069, which
  waits and then sheds load. Here there is a cheap answer that is still
  correct, so there is nothing to shed.
- The slot is taken when the response is chosen for compression and returned
  when the writer is closed.
- `gateon_middleware_compress_brotli_fallbacks_total` counts the fallbacks.

**The dashboard serves the files its build already compressed.** If an asset
has a `.br` or `.gz` variant and the client accepts that encoding (`q=0`
refuses it), the variant is served with its own `Content-Encoding`,
`Content-Length` and `Vary: Accept-Encoding`. The compress middleware passes an
encoded response through untouched. The plain answer also carries `Vary` when
a variant exists, so a shared cache cannot hand the plain answer to a client
that should get br, or the reverse. A request for an encoded variant ignores
`Range` and gets the whole file. `index.html` is rewritten with the CSP nonce
on every request, so it is never served from its precompressed copy, and it
is small.

## Considered and rejected

**Waiting for a slot, like ADR 0069.** A wait costs every client latency while
a flood is running, and gzip is always available instead.

**Turning brotli off on the management chain.** The UI path no longer encodes
on the fly at all, so this would gain nothing there. The proxy path would still
need the bound.

## Consequences

- 200 concurrent requests for the largest UI bundle, through the management
  chain's compress middleware and the UI handler, held 13.5 MiB live, down from
  2.2 GiB. No encoder ran.
- On the proxy path, the same 200 concurrent br requests held 242 MiB at the
  minimal tier's 8 slots and 277 MiB at standard's 32, down from 2.2 GiB. Most
  of what remains is gzip's 1 MiB per response.
- Under load, a br-capable client can get gzip. Brotli's output is also about
  1% larger than at the library default.
