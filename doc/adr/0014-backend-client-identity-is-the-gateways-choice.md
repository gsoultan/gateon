# 14. The backend client identity is the gateway's choice

Date: 2026-09-25

## Status

Accepted. Co-signed `arch` ↔ `sec`: it moves a trust boundary — which party
decides the identity the gateway authenticates to a backend as.

## Context

A service's `tls_client_config` can carry several client identities, and
`cert_selection_strategy` picks one per request: `STATIC` presents the one
`cert_file`, `BY_HOST` chooses by the request's host, `BY_HEADER` by a header's
value. The certificate is what a backend using mTLS decides who is calling from.
Whoever chooses it chooses who the gateway claims to be.

Four things were wrong with how it was chosen:

1. **`BY_HEADER` read the request's headers, which are the client's.** A client
   sending `X-Tenant: admin` made the gateway authenticate to the backend as the
   admin identity, on a route with nothing on it that ever set `X-Tenant`.
2. **`BY_HOST` read `X-Forwarded-Host`, and fell back to `req.Host`.** On the
   ordinary proxied path this was safe by accident: `httputil.ReverseProxy` with
   a `Rewrite` strips the client's forwarding headers, and the rewrite writes the
   inbound host back. The fallback was the outbound request's `Host` — the
   backend's own address. Anything that selected from the inbound request would
   have let the client name the host.
3. **Identity transports were cached by identity id.** Ids are optional and
   unchecked, so two identities without one shared a transport, and it presented
   whichever certificate was built first for both.
4. **Protocol upgrades dialled with the static config.** A service with
   per-request identities presented no client certificate on any WebSocket.

## Decision

**The match headers of a `BY_HEADER` service are the gateway's to set.** The
route chain removes a client's copies ahead of the route's own middlewares —
immediately after recovery, access logging and metrics — so only a middleware on
the route can choose the identity: a claim mapping (`map_claim_*`), forward-auth's
`auth_response_headers`, or a `headers` rule (`set_request_*`). This is the
contract a mapped claim header already has (`MapClaimsToHeaders` and
`stripMappedHeaders` in `internal/middleware/auth`), applied to one more header.

`pkg/proxy` owns the selector, so it names the headers
(`ProxyHandler.ClientIdentityHeaders`); `internal/router` owns the chain, so it
installs the guard (`internal/router/client_identity.go`). The guard is not
installed at all for a service that selects any other way.

**There is no trusted-proxy exception.** A peer trusted for `X-Forwarded-For` —
a CDN, a tunnel — forwards arbitrary client headers verbatim. Trusting it to
report the client's address does not make its `X-Tenant` the gateway's. An
upstream that asserts identity should do it through forward-auth, whose response
the gateway does trust.

**`BY_HOST` chooses by the host the router matched**, which the entrypoint
records in the request state (`RequestState.StrippedHost`). The identity is
therefore always one belonging to a host whose route policy the request passed.
It is still the client that picks the host, because picking the host is picking
the route: on a route whose rule does not constrain `Host`, the client picks
among the service's host identities. Constrain the route's host when that
matters.

**Identity transports are keyed by the identity's position**, not its id.

**Upgrades choose the identity the same way** as any other request.

## Consequences

- A backend no longer receives a client's copy of a match header: it is
  removed, not only ignored for selection. A backend reading that header as the
  caller's claim was the exposure this closes.
- A deployment where something in front of the gateway set the match header has
  to set it on the route instead — with forward-auth, a claim mapping, or a
  `headers` rule. Listed in `doc/upgrading.md`.
- Cost: one `Header.Del` per match header per request, only on routes whose
  service selects `BY_HEADER`. Nothing on any other route.

## Related

- `doc/upgrading.md`, "A client can no longer choose the certificate the gateway
  presents to a backend".
- ADR-0011, which made the same call for reputation: a key the client can choose
  is not an identity.
