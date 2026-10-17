# 72. A credential route forwards its requests only where an administrator chose

Date: 2026-10-17

## Status

Accepted. Extends ADR 0038.

## Context

ADR 0038 holds an operator (role operator, not admin) away from the credential an
administrator stores in a `headers` or `rewrite` middleware: binding one to a
route, repointing a route that carries one, and repointing that route's service
all need an administrator. All three rules are about *the route's backend*,
because that is where such a middleware delivers what it sets.

Some middlewares send the request somewhere else as well, to a destination of
their own configuration:

- **forward auth** copies every request header to its `address` when
  `auth_request_headers` is empty, after the credential middleware has already
  set `Authorization` on the same request;
- **OAuth2 introspection** (`auth` with type `oauth2` or `oauth2_introspection`)
  posts the request's bearer token to its `introspection_url`;
- a **wasm** guest reads any request header and can carry it out through what
  it records.

So an operator could change an admin's route from `[cred]` to
`[cred, forwardauth(address=attacker)]` and receive the administrator's bearer
token, with the service untouched. `AuthorizeRouteSave` allowed it: the
credential binding was kept, nothing was repointed. Changing the address of a
forward-auth middleware an admin had already put on such a route, or turning a
middleware there into one, reached the same place through the middleware save,
which the guard did not see at all.

## Decision

**On a route that carries a credential-injecting middleware, only an
administrator decides which middlewares after it send the request elsewhere,
and where they send it.** The same `routebind.Guard` holds it, in the same
domain saves REST, Connect/gRPC and config import share:

- A route save is refused when it runs a forwarder after a credential-injecting
  middleware where the stored route did not already run that forwarder after
  that credential. Adding one is covered, and so is reordering: a forwarder that
  runs first has not seen the credential, so moving it later is the same
  capture. A credential newly added before an existing forwarder was already
  refused by ADR 0038's binding rule.
- A middleware save (new rule, `AuthorizeMiddlewareSave`, run after the stored
  secrets are restored) is refused when the result is a forwarder whose type,
  configuration or wasm module differs from what is stored, and any route that
  names its id carries a credential. A route may name an id no middleware has
  yet, so creating it under that id counts. A rename is allowed.

The forwarder set is decided by type in `forwardsRequestOffRoute`. The JWT and
OIDC validators are not in it: they fetch keys from their issuer and send it
nothing from the request. The oidc proxy sends its own client secret, which ADR
0034 already binds to its issuer.

The refusal is the existing `ErrRequiresAdmin`: `403` on REST, `PermissionDenied`
on Connect/gRPC.

## Consequences

- An operator can no longer reconfigure a forward-auth, introspection or wasm
  middleware bound to any credential-carrying route, including one placed before
  the credential, which on its own cannot see it. The middleware check ignores
  order on purpose: it is simpler to reason about, a later reorder is gated
  anyway, and the cost of being stricter is asking an administrator.
- The forwarder set is a list, so a future middleware that sends the request to
  a destination of its own must be added to it. Its residue is the same as ADR
  0038's: a credential under a header name that gives nothing away is not
  recognised as one.
