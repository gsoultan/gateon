# 39. The second sign-in step proves the first

Date: 2026-10-02

## Status

Accepted. `arch` and `sec`: it moves a trust boundary, the one between the two
halves of a sign-in.

## Context

A sign-in to an account with two-factor authentication is two requests. `POST
/v1/login` checks the password and answers `twoFactorRequired` (or, when an
administrator has required 2FA and the account has not enrolled,
`twoFactorSetupRequired`) without a session. `POST /v1/auth/2fa/verify` then
takes the second factor and issues the session.

The second request took `{id, code}` and nothing else. It is on the base
handler's list of paths served before authentication, because at that point
there is no session to present, and `Manager.Verify2FA(id, code)` never asked
whether a password had been checked. So the password step was not part of the
sign-in at all: an account id plus one current TOTP code, or one recovery code,
was a complete sign-in. Account ids are not secrets -- any viewer reads them in
the audit log ("Failed 2FA verification for user: <id>"). The second factor had
replaced the password instead of being added to it.

This was masked for as long as every 2FA session was issued with an empty role
(review finding M1), which every permission check refused. Fixing M1
(7e0240f9) made it a live administrator takeover for anyone holding one leaked
recovery code or a shoulder-surfed code.

The same endpoint also counted every wrong code towards the account's lockout,
for any caller who knew the id: five requests locked the administrator out for
fifteen minutes (finding M6's shape, reached without even a password guess).

## Decision

- **A correct password on an account that owes a second factor earns a
  challenge**, and the second step requires it. The challenge is a PASETO
  v4.local token under the session key that names the account (`sub`), says what
  it is for (`purpose: 2fa-challenge`), lasts five minutes
  (`ChallengeLifetime`) and carries the account's session binding (ADR 0005), so
  a password, role or disabled change, or a sign-out, voids one in flight the
  way it voids a session.
- **A challenge is never a session, and a session is never a challenge.** Every
  challenge is encrypted with a PASETO implicit assertion
  (`gateon/v1/2fa-challenge`), so it does not decrypt without it: not by
  `VerifyToken`, not by a route's PASETO middleware an operator configured with
  the session key. `VerifyToken` also refuses any token that carries a purpose
  claim, which a session never does. A session, encrypted without the
  assertion, does not decrypt as a challenge.
- **`Authenticate`'s contract is unchanged** -- `(token, user, err)`, with no
  token when a second factor is owed. The challenge rides on the error:
  `*SecondStepError` wraps `ErrTwoFactorRequired` or `ErrTwoFactorSetupRequired`,
  so `errors.Is` reads it as before, and `auth.ChallengeFrom(err)` returns the
  challenge. Its `Error()` omits the challenge, so logging the error never
  writes one down. `ApiService.Login` is the only caller and puts it in
  `LoginResponse.two_factor_challenge` (new tag 5).
- **The requirement lives in `Manager.Verify2FA(challenge, id, code)`**, before
  the account is read, so no transport and no caller can reach a session around
  it. Today the step has one transport, REST; there is no Connect or gRPC
  procedure for it, and one added later would be authenticated
  (`publicAuthPaths` is exact-match) and reach the same method. A missing,
  expired, wrong-purpose, other-account or stale challenge is refused with one
  error, `ErrInvalidChallenge`, answered as 401 with the code
  `two_factor_challenge_invalid`.
- **A refused challenge is not counted towards the lockout, and the lockout is
  not consulted before it.** Only a caller who has shown the password reaches
  the code, and only wrong codes count. Nobody can lock an account out through
  this endpoint by knowing its id.
- **Self-service enrolment needs a challenge too, and `Setup2FA` issues it.**
  The design brief assumed the dashboard's own enrolment (Settings, signed in)
  reached verify as an authenticated request and could be left alone. It does
  not: `/v1/auth/2fa/verify` is a public path, the base handler does not
  authenticate it, and the handler's "authenticated caller" branch is reached
  only by tests that inject claims. Every verify in production is
  unauthenticated. Rather than add optional authentication to a public path,
  `Setup2FA` -- which already requires the current password -- returns a
  challenge in `Setup2FAResponse.challenge` (new tag 4), and the dialog carries
  it to verify. One rule, no exception: the code step always needs proof of the
  password, from sign-in or from setup.
- **A required enrolment uses the challenge from the sign-in that answered
  `twoFactorSetupRequired`**; `POST /v1/auth/2fa/enroll` is unchanged.
- **The dashboard keeps the challenge in component state only**, never the auth
  store or web storage (invariant 2), sends it with the code, and on
  `two_factor_challenge_invalid` returns to the password with "Your sign-in took
  too long". The enrolment dialog now calls verify with `fetch` rather than
  `apiFetch`: the endpoint is public, so its 401 is about the code or the
  challenge, and `apiFetch` read it as "signed out" and ended the session the
  user was adding a factor to -- which a mistyped code already did before this
  change.

## Consequences

- An account id and a code no longer sign anyone in. A leaked recovery code is
  worth nothing without the password.
- The challenge is not single-use. It is spent with a code, which is the
  secret, and its holder already has the password; a single-use record would be
  server state keyed by request data for no gain. It expires in five minutes and
  dies with any change to the account.
- Five minutes bounds the sign-in and the enrolment. Someone who takes longer
  to find their authenticator, or to scan the QR code, is sent back to the
  password (or, enrolling, to start setup again).
- **Scripts and API clients that sign in with 2FA must pass the challenge**:
  read `twoFactorChallenge` from the `/v1/login` answer and send it as
  `challenge` with the code. Self-service enrolment through the API must send
  the `challenge` from the setup answer. A verify without one is refused.
- Challenges are minted under the session key, so rotating it ends sign-ins in
  progress, as it ends sessions.

## Alternatives considered

- **Optional authentication on `/v1/auth/2fa/verify`**, so the enrolment dialog
  is an authenticated caller and skips the challenge. Rejected: it makes a public
  path's behaviour depend on a credential it does not require, and keeps a route
  to a session that a challenge does not guard.
- **A server-side record of pending sign-ins.** Rejected: it needs a bound and
  an eviction, does not survive a restart or reach another node, and buys
  nothing a signed, bound, five-minute token does not.
