# 57. Setup keeps what the configuration already decided, an administrator can reset another account's second factor, and audit verification says what it cannot see

Date: 2026-10-04

## Status

Accepted. `api` drives (three proto changes, one per finding, generated
together); `sec` co-signs the setup-status answer, which is public before an
administrator exists, and the second-factor reset, which removes a credential;
`ux` co-signs the wizard, the users page and the audit result.

## Context

Three findings left open after PR #10:

- **The setup wizard's database step switched a configured database to
  SQLite.** The wizard always submits a database, SQLite `gateon.db` by
  default. On a gateway whose `global.json` already names one -- the Helm
  chart's `externalDatabase`, or a hand-written file -- the auth service is up
  before setup runs (`inits.InitGlobalConfig` opens it), so Setup created the
  administrator in the configured database and then wrote the wizard's over
  the configuration. The next start opened `gateon.db`, found no
  administrator, and refused to run ("the user database has no
  administrator"): a crash loop on every restart. Reproduced with the
  pre-fix binary against Postgres. With the session key from
  `GATEON_SESSION_KEY` (ADR 0056) the wizard also showed a generated key that
  Setup never used.
- **MGMT-N5: no API reset another account's second factor.** An
  administrator could require an account to enrol, but once it had enrolled
  the only remedy for a lost authenticator was deleting the account.
  `auth.Manager.Disable2FA` existed, cleared the factor, left every session
  alive and the account password-only, and nothing called it.
- **TRUTH-NEW-11: deleting the newest audit entries still showed a green
  "The audit log verifies".** A hash chain cannot show that entries were
  removed from its end: what is left still verifies.

## Decision

### Setup keeps the databases that are already open

When the auth service is up at setup time, the databases are fixed: the
management database is the one it opened (`db.AuthDatabaseURL` of the live
configuration) and the logging database is the audit log's
(`db.AuditDatabaseURL`), both opened at start from the same configuration.
`ApiService.Setup` -- one implementation behind REST, Connect and gRPC --
refuses a request naming a different management or logging database, before
anything is written, with a message naming the database that stays (engine
and location, never the credentials) and what to change instead. A request
naming the same database (any spelling of one SQLite file) or none completes
on it. On a first run with no `global.json` the auth service is not up yet,
and the wizard's choice is applied as before.

Refusing rather than silently ignoring the wizard's database: a scripted
`POST /v1/setup` that names a database means it, and should hear that it was
not used.

### The wizard is told what Setup keeps

`IsSetupRequiredResponse` gains, while setup is required:
`database_configured`, `database_driver`, `session_key_from_environment`
(public: booleans and an engine name), and `database_description` /
`logging_database_description` (host, port and database, or the SQLite
file) **only** for a request whose `setup_token` matches. The question is
served before authentication for the life of the process; a configuration
database's address is not for whoever reaches the management port first.

The token travels in the request body, so the RPC is forwarded on Connect
(it was unimplemented there); the REST `GET /v1/setup/required` the
dashboard polls carries no token and gets the public fields. Because the RPC
now checks a token, it spends from the per-client public-auth budget
(ADR 0053) like Setup: unbudgeted, it was a way to guess an operator-chosen
`GATEON_SETUP_TOKEN` that skipped Setup's budget.

The wizard asks once, with the token, when the operator leaves the account
step. With a configured database the Database and Logging steps show the
database in use and offer no choice; with the session key from the
environment the Security step shows no generated key. Setup is sent neither.
When the question fails the wizard asks as it always did, and Setup still
refuses a different database.

### An administrator can reset another account's second factor

`ResetUserTwoFactor` (gRPC and Connect; REST `POST /v1/users/{id}/2fa/reset`)
in one statement removes the TOTP secret and recovery codes, sets
`two_factor_pending` -- the account must enrol a new authenticator at its next
sign-in rather than being left password-only -- and advances the session
epoch, so every session ends; the session-binding cache is dropped here and on
the peers. Administrator only (users write on the transport, `requireAdmin` in
the service), audited as `reset_2fa` under the administrator, `NotFound` for
an unknown account, and refused for the caller's own account: that is
self-service re-enrolment from the profile, which asks for the password, and a
session alone must not be able to strip the factor that protects it. The
users page's two-factor control on an enrolled account opens a confirmation
naming the account and what the reset does. `Disable2FA` is replaced.

### Audit verification checks a tail anchor, and says what it cannot see

The audit manager keeps a tail anchor: the newest entry it has stored, or
found newest when it started. It moves only after an entry is stored (an
anchor the log does not hold yet would read as a deleted one) and only
forward (concurrent writers can finish out of order). When a verification
range that runs to now is complete with no break, `VerifyRange` looks the
anchor up by id; if it is gone, and retention cannot have removed it (it is
newer than the retention cutoff), the response says `tail_missing`, `intact`
is false, and the failure is itself audited. The response names the anchor's
time either way.

What this cannot detect, and the dashboard says so beside every green result:
entries removed from the end while the gateway was stopped, or before it last
started -- the anchor is then read from the log as it is. The off-host copy of
the audit log stays the record to trust after an incident.

## Consequences

- A Helm install with `externalDatabase` set up through the dashboard no
  longer crash-loops; the wizard says which database it is using.
- An old dashboard (cached before the upgrade) still submits SQLite on a
  configured gateway; it now gets a refusal naming the database to keep
  instead of a broken install. Reloading the page fixes it.
- The setup-status RPC is budgeted with sign-in: a script polling
  `IsSetupRequired` over gRPC or Connect more than the budget allows gets
  `ResourceExhausted`; `GET /v1/setup/required` is unchanged.
- A tail cut made while the gateway runs is reported until the next start; a
  cut made across a restart is not. Nothing new is stored: the anchor lives
  in memory.

Proof: `internal/api/setup_configured_database_test.go`,
`internal/auth/reset_two_factor_test.go` (SQLite and Postgres),
`internal/api/auditrecord/reset_two_factor_test.go`,
`internal/server/handlers/reset_two_factor_test.go`,
`internal/audit/tail_anchor_test.go`, `internal/api/audit_tail_test.go`, the
bun tests for `setupWizard`, `twoFactorReset` and `auditVerify`, and the
Playwright specs `configured-run.spec.ts` and the reset test in
`two-factor-sign-in.spec.ts`. The crash loop was reproduced, and its fix
proven, with the built binary against Postgres.
