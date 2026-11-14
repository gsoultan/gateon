# 88. Every account signs in with a second factor

Date: 2026-11-13

## Status

Accepted. `sec` drives (this moves the management plane's trust boundary: a
password alone no longer reaches a session); `arch` co-signs the boundary and
the new `authtest` package; `api` co-signs the two RPCs and migration 72; `ux`
co-signs the sign-in page, the profile and the users page.

## Context

Two-factor authentication existed, and was optional. An account had it if its
owner enrolled from the profile, or if an administrator flagged it
(`two_factor_pending`) and it enrolled at its next sign-in. Every other account
signed in with its password, and an administrator could cancel the flag again.
The owner asked for it to be mandatory, with no way to turn it off.

Reproducing the flows turned up four defects:

- **gRPC could not finish a sign-in.** The second step existed only as
  `POST /v1/auth/2fa/enroll` and `POST /v1/auth/2fa/verify`. The `Login` RPC
  answered an enrolled account with a challenge that no RPC took. With the
  second factor mandatory, that would have been every sign-in.
- **Re-enrolling turned the second factor off.** `Setup2FA` on an account
  that already had one stored the new secret with `two_factor_enabled = false`
  before any code was checked. Closing the dialog there left the account
  signing in with its password alone, and its working authenticator and
  recovery codes were dead.
- **A TOTP code could be replayed** for as long as it was valid, its step and
  one either side (review L1, open since 2026-10-16).
- **The users page offered controls that changed nothing true.** "Cancel
  requirement" cleared a flag. Once enrolment is mandatory, the flag does not
  decide anything.

## Decision

### The rule lives where every session is minted

`auth.Manager` decides, so REST, gRPC and the dashboard get the same answer:

- `Authenticate` never issues a session. A correct password on an enrolled
  account owes `ErrTwoFactorRequired`. On any other account it owes
  `ErrTwoFactorSetupRequired`, flagged or not. Both carry the ADR 0039
  challenge.
- `EnrollPending2FA` enrols any account that has no second factor. It still
  re-checks the password under the sign-in lockout, and it still refuses an
  enrolled account, which with the password alone would replace the factor.
- `issueToken` refuses an account without a second factor, whatever path
  calls it.
- The session binding (ADR 0005) gains a sixth input, written only when the
  account has **no** second factor. An enrolled account's digest is
  byte-for-byte the previous release's, so the upgrade signs out nobody who
  already had 2FA. Every password-only session the previous release issued
  stops matching, and is refused on its next request.

There is no setting. A switch would be one more path to a password-only
sign-in, and the per-account flag already shows which accounts were reset.

### Existing accounts enrol at their next sign-in

Nobody is locked out by the upgrade. The sign-in page already ran the
enrolment for flagged accounts, and now runs it for every account that has no
second factor: password, then the QR code and recovery codes, then the first
code, which issues the session. The one window this leaves is the
pre-existing one: until an account enrols, its password alone enrols it.
Administrators should sign in soon after upgrading.

### Recovery

- Each account has ten single-use recovery codes, shown at enrolment.
- An administrator can reset another account's factor (ADR 0057). That
  account enrols again at its next sign-in.
- An account can replace its own authenticator from its profile. The
  replacement travels inside the re-enrolment challenge: the encrypted secret
  and the hashed recovery codes, under the session key. Nothing is written
  until `Verify2FA` confirms a code from the new authenticator. Abandoning the
  dialog changes nothing. This also makes true the users page's advice to
  "set yours up again from your profile".
- There is no host-side reset yet for a sole administrator who has lost both
  the authenticator and the recovery codes. That is follow-up work.

### gRPC has the second step

`ApiService/Enroll2FA` (new message `Enroll2FARequest`) and
`ApiService/Verify2FA` mirror the REST steps. Both are exact-match public
paths, are `publicProc` in the RBAC table, and spend from the sign-in budget
(ADR 0053). `Verify2FA` withholds the token from a browser, as `Login` did.
Connect still serves neither, as it serves no `Login`.

### A code signs in once

Migration 72 adds `users.two_factor_last_step`. `spendTOTP` finds which step
in the window a code belongs to. It accepts the code only if a conditional
`UPDATE ... WHERE two_factor_last_step < step` matches the row. Only one
request, on one replica, can win that update. A second presentation of the
code, or of any earlier one, is refused and counts towards the lockout.

### Tests sign in the way people do

`internal/auth/authtest` is imported only by `_test.go` files, so none of it
reaches the binary. It gives other packages `SignIn` (password, enrolment the
first time, then a code) and `PasswordStep` (for tests about the first
factor). Its `Code` never hands out a spent step. The Playwright suite and the
Go e2e tests have helpers that do the same.

## Consequences

- The upgrade signs out every account that has no second factor, once. They
  sign in again and enrol.
- A first sign-in now costs three requests from the per-address sign-in
  budget (login, enrol, verify) instead of one. The default of ten a minute
  still covers it with room for typos.
- Signing in twice within the same thirty seconds needs the next code.
  Authenticator apps show a new code at most thirty seconds later.
- `two_factor_pending` is kept, and only tells a reset account from one that
  never enrolled.
