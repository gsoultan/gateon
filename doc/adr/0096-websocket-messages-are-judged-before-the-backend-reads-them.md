# 96. WebSocket messages are judged before the backend reads them

Date: 2026-11-16

## Status

Accepted. `sec` drives (a new deny decision on a path that had none); `net`
challenges what is done to the connection; `mem` challenges what one
connection may hold; `conc` challenges the lock; `arch` co-signs where the
code lives.

## Context

A WebSocket upgrade is one HTTP request followed by a connection the proxy
relays byte for byte (`pkg/proxy/websocket.go`). Every control in the
middleware chain runs on that one request. The messages that follow carry what
a request body carries, the same JSON with the same SQL, template expressions
and paths in it, and were forwarded unread. The Security Hub said so
("WebSocket messages are not inspected") and offered nothing to do about it.

Whose job this is follows from gwaf's ownership test: gwaf says whether one
body is an attack; the framing of a connection belongs to whoever owns the
connection. So gateon reads the frames and gwaf judges each message.

Three things make this harder than calling the engine on each read:

- **A message is not a read and not a frame.** A payload split across two
  frames is one message to the backend. Judged per frame, `UNI` and `ON SELECT`
  pass separately.
- **The opcode and the message length are the client's to write.** A check
  that skips binary frames, or forwards what is past a limit, is opt-out by
  request, which is what invariant 7 exists to stop on the HTTP side.
- **Compression.** `permessage-deflate` deflates each message with a
  dictionary carried between messages. A compressed message cannot be judged.

## Decision

A WAF middleware takes `websocket_inspection` (`true`; default off) and
`websocket_message_limit` (bytes; 0 uses the profile default).

1. **The seam is `Hijack`.** With inspection on, the WAF wraps the response
   writer of a request that carries an `Upgrade` header, which is the condition
   the proxy takes a connection on. The connection the proxy receives from
   `Hijack` reads through `internal/security/wsinspect`, so the tunnel relays
   to the backend only bytes that were cleared. The proxy is unchanged.
   Bytes `net/http` had already read from the client are moved behind the
   inspection, not left in the reader beside it.
2. **Messages are reassembled, then judged whole,** as the body of the request
   that opened the connection: same method and path, so the route's exceptions
   apply, and no query string, which was judged with the upgrade. Text and
   binary are judged alike.
3. **A refused message closes the connection** with close code 1008 and never
   reaches the backend. It is recorded and held against the client like a
   refused request, with "In a WebSocket message" in the entry.
4. **A message past the limit closes the connection** with 1009. Forwarding the
   remainder would make padding a bypass.
5. **Compression is not negotiated.** The request's `Sec-WebSocket-Extensions`
   is removed before the backend sees it. A frame that sets an extension bit
   anyway is a protocol error (1002), as is an unmasked frame, a bad opcode or
   broken fragmentation.
6. **Audit Only records and relays.** A refused message is recorded and
   forwarded; a message past the limit is forwarded unread and counted.
7. **Off by default.** Turning it on stops a route offering compression and
   closes connections that send large messages. That re-prices a working
   route, so an operator chooses it per route, or with
   `GATEON_WAF_WEBSOCKET_INSPECTION=true` for the gateway-wide WAF (which has
   no field for it; adding one is a proto change and a migration that can
   follow) and every route WAF that sets nothing.

## Consequences

- **Memory.** A connection holds nothing between messages (buffers over 4 KiB
  are dropped once drained). While a message arrives it holds the message once
  if it is one frame, and at most 2.25 times the limit if it is fragmented
  (wire bytes, a quarter more for headers, and the unmasked payload). Buffers
  grow as bytes arrive, never from a declared length. The limit defaults per
  tier: 16 KiB minimal, 64 KiB standard, 256 KiB enterprise
  (`TierDefaults.WAFWebSocketMessageLimit`,
  `GATEON_WAF_WEBSOCKET_MESSAGE_LIMIT`), and is never more than the request
  body limit, past which the engine reads nothing. Worst case is that figure
  times the connections held mid-message, which the entrypoint connection caps
  and the tunnel's idle timeout bound. A client sending empty fragments for
  ever is cut by the same bound (they cost header bytes, which are counted).
- **Latency.** One engine transaction per message on the tunnel's
  client-to-backend goroutine. A fragmented message is delivered when its last
  frame arrives, not as it streams.
- **A lock, off the request path.** Writes to the client take a mutex so the
  one close frame the inspection may send does not interleave with the tunnel's
  writes. It has one writer in normal operation.
- **The route carries WebSocket only.** Every hijack on an inspected route is
  parsed as WebSocket; the `Upgrade` header is the client's to write and does
  not choose whether its bytes are read. Another upgraded protocol on the same
  route is closed.
- **Not covered.** Messages the backend sends are relayed uninspected.
  WebSocket over HTTP/2 (RFC 8441) is not proxied by gateon at all, so there
  is one transport and it is covered. The blind-spot card keeps its
  WebSocket entry and now says what the setting does and does not cover.
- **The OpenAPI document** of a route describes the upgrade, not its messages.
  A message matches the same operation and is held to nothing the upgrade was
  not; `TestWebSocket_MessagesAreNotHeldToTheRouteDocument` holds that for the
  day the engine starts requiring query parameters.
- Metrics: `gateon_middleware_waf_websocket_closed_total{route,reason}` with
  reason `refused`, `oversize` or `protocol`; refusals also appear in the WAF
  block counters under phase `websocket`.
- `wsinspect` has a fuzz target over arbitrary client bytes: no panic, the
  inspector never sees more than the limit, the backend never receives more
  than was sent.
