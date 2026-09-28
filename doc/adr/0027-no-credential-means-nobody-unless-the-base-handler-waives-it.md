# 27. No credential means nobody, unless the base handler waived it

Date: 2026-09-28

## Status

Accepted. `sec` and `arch`: it moves the line between the handler that
authenticates a management request and the checks that authorize it.

## Context

The management API is served three ways: REST on the mux, ConnectRPC, and gRPC
and gRPC-Web. One handler authenticates all three, the base handler
(`CreateBaseHandler`): on the management entrypoint it runs PasetoAuth on every
API path except the few that must work before a session exists (setup, sign-in,
the second factor, health), and on a data-plane entrypoint it refuses the API
unless the operator made it public. The permission checks run later, inside the
API: `handlers.RequirePermission` and `callerClaims` for REST,
`authorizeProcedure` in the Connect and gRPC interceptors.

Those checks read a request with no claims as "authentication is disabled for
this deployment" and allowed it. That was an inference from an absence, and it
held only for requests that had passed the base handler. One path did not: the
HTTP dispatcher of a plaintext TCP entrypoint (`buildPlainHTTPHandler`) handed
HTTP/2 gRPC and gRPC-Web straight to the internal gRPC server, ahead of the base
handler. Such a request carried no claims, so the interceptor allowed every
procedure. Anyone who could reach a plaintext TCP entrypoint could call the
management API with no credential: `UpdateGlobalConfig`, the users, the routes.
The same dispatch also meant a gRPC route on such an entrypoint was never
proxied; the gateway's own gRPC server answered it.

The HTTP entrypoints were not affected: their gRPC dispatch
(`HandleProxyOrLocal`) runs inside the base handler.

## Decision

- **Every request on a TCP entrypoint's HTTP dispatcher goes to the base
  handler**, gRPC and gRPC-Web included. The base handler already proxies a
  request a route matches, gRPC routes too, and falls back to the internal API
  only where it decides to.
- **No claims means nobody.** A permission check allows a request with no claims
  only when the base handler marked it as needing none
  (`middleware.WithAuthNotRequired`). The base handler marks three branches and
  no others: sign-in (still rate limited), the paths that must work before a
  session exists, and the case where authentication is off for the deployment on
  an entrypoint other than the management one. Without the mark, a request with
  no claims is refused as unauthenticated: 401 on REST, `Unauthenticated` on
  Connect and gRPC.
- **The mark cannot be forged.** It is a context value under an unexported
  struct type in the auth package. No header, path or other request property
  sets it; only the base handler's branches do.
- **A handler that authenticates for itself says so.** The log stream verifies
  a token from its query string, because a WebSocket cannot send a header. It
  reads the caller through `callerOrSelfAuthenticated`, for which "no claims" is
  a cue to verify, not a pass. It still denies unless its own verification
  succeeds.

## Consequences

- A future dispatcher that skips the base handler fails closed: its requests
  arrive with neither claims nor the mark, and are refused.
- A test that calls a handler directly to model "authentication is off" has to
  mark the request (`authWaived` in the handler tests). The unmarked model was
  the assumption that let this through.
- A gRPC route on a plaintext TCP entrypoint is proxied like any other route.
- Any new branch in the base handler that serves the API without authenticating
  must mark the request. If it does not, the API refuses the request; it no
  longer lets it through.
