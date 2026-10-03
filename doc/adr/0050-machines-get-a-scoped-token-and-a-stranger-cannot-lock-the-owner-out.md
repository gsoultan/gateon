# 50. Machines get a scoped token, the audit log is kept and checked, and a stranger cannot lock the owner out

Date: 2026-10-03

## Status

Accepted. `sec` co-signs with `ops` (the scrape credential and the audit
default change what an install ships with and how it is monitored) and `data`
(migration 67, the audit window queries). Each decision moves a trust
boundary: who may read `/metrics`, who may sign in while the account is being
guessed at, which passwords may be set, and whether the record of all of it can
be checked.

## Context

The 2026-10-02 management-plane review (M3, M6, M8, M10, M11) and the
production runbook found:

- **`/metrics` accepted only a user's eight-hour session.** The runbook's
  workaround was a viewer account for Prometheus, its password on disk, and a
  systemd timer signing it in every four hours. The viewer account could read
  everything any viewer can in the dashboard, and a stopped timer was a scrape
  gap.
- **M6: anyone could lock the administrator out.** Failures were counted per
  username in `users.failed_attempts`: five wrong passwords from anywhere locked
  the account for fifteen minutes, the owner's right password from their own
  address included. Five requests every fifteen minutes kept them out for good;
  the per-address login limit (5/min) is above that rate.
- **M8: the audit log was off by default and never checked.** A default install
  recorded nothing. `VerifyChain` existed and had no caller, so the HMAC chain
  was computed and never read.
- **M3 (remainder): `ChangePassword` with no caller acted.** "No claims" was read
  as "authentication is off, anything goes", so an anonymous request reset the
  password of whatever account id it named.
- **M10: usernames could be enumerated by timing.** An unknown username answered
  in 1-8 ms, a real one in about 55 ms (bcrypt); and only a real account could
  ever answer "account locked".
- **M11: there was no password policy.** `a` was accepted; `""` stored an empty
  hash.

Looking at M6 turned up a sixth: the password step cleared the stored failure
count on every correct password, and that count is also what limits guesses at
the second factor. Whoever held the password could sign in again after every
fourth wrong TOTP code and never reach the lock.

## Decision

**API tokens for machines.** An administrator issues a named token with one or
more read-only scopes; `metrics:read` is the only scope today. The token is
`gateon_tok_` and 43 base64url characters (256 random bits). Only its SHA-256
is stored (`api_tokens`, migration 67): the secret is high-entropy, so a slow
hash adds nothing, and a fast one keeps a scrape to one indexed lookup. The
secret is returned once, by `CreateApiToken`; the list shows a hint, who made
it, when it was last used (written at most once a minute) and when it expires
(optional, at most ten years). At most 50 exist. Revoking deletes the row, so
the next request is refused; nothing caches an accepted token.

It is accepted in exactly one place: a `Bearer` token on `/metrics` on the
management plane, checked before the session check, with the `metrics:read`
scope. Everywhere else it reaches the session check, which does not know the
format and refuses it -- every other path, and REST, Connect and gRPC alike --
and it never reaches an API handler, so it carries no claims and no role. The
proxy withholds it from every backend (ADR 0041) by shape: the prefix is
gateon's own, so no application's credential has it, and recognising it needs no
lookup on the request path. Managing tokens (`ListApiTokens`, `CreateApiToken`,
`RevokeApiToken`; `/v1/api-tokens`) is mapped to the `users` resource and
requires an administrator, as user management does.

**Failures are counted per account and source, with a per-account backstop
that admits the owner.**

- Per (account, source prefix) -- an IPv4 /24 or an IPv6 /64, the unit an
  attacker holds: five failures lock that pair for fifteen minutes. Nobody else
  is affected.
- Per account, across sources: twenty failures within fifteen minutes put the
  account under attack for fifteen minutes, and every attempt refused under it
  renews that. While it holds, only a source the account has signed in from
  before may try; the eight most recent are kept in `users.login_sources`
  (migration 67), so a restart does not forget them. A source that does not
  parse is never known.
- A correct password clears its pair and not the account's count, so the owner
  signing in does not hand a spread attack a fresh twenty.

A single source gets five guesses per fifteen minutes; any number together get
twenty before only the owner's sources may try. The counts are in memory,
in bounded LRUs (16,384 pairs and 4,096 accounts each): one table for accounts
that exist, keyed by id, and one for names that do not, so a flood of invented
usernames cannot evict a real account's count. They are per instance: each node
of an HA pair counts on its own.

The stored count (`failed_attempts`, `locked_until`) is now only the second
factor's and the re-authentication prompt's (password change, 2FA setup). The
password step neither reads nor clears it. That closes the TOTP brute force
above, and it means a session in hostile hands -- script in the dashboard -- can
lock the prompt but not the owner's sign-in, and a stranger guessing at the
sign-in form cannot lock the owner out of either.

**Unknown usernames answer like real ones.** They are counted and locked the
same way, and pay for a bcrypt comparison against a dummy hash at the
production cost (`DefaultCost`), as does an account with no stored hash.

**A password policy, checked before anything is written.** At least 12
characters (counted as characters, not bytes); at most 72 bytes (bcrypt's limit,
which Go refuses rather than truncates); not containing the username (when it
has three or more characters); not one character repeated or a simple run; not
on a short embedded list of the most common long passwords. No breached-password
service is called: the check is offline and sends nobody a hash. It is enforced
in `auth.Manager` -- account creation (which now requires a password), an edit
that sets one, `ChangePassword`, and `ChangeOwnPassword` before the current
password is checked, so a refused new one does not spend a guess -- and in
`Setup` before anything is written. Refusals are `InvalidArgument` (REST 400)
naming the rule. Existing passwords keep working; the rule applies when one is
set.

**`ChangePassword` needs an authenticated caller,** whatever the transport and
whatever the deployment's authentication setting. With no claims it is
`PermissionDenied`.

**The audit log is on, and signed, for new installs, and can be verified.**

- `Setup` turns `audit.enabled` and `audit.sign_entries` on and generates a
  signature key, and puts them in force at once.
- An existing install keeps what it has. A stored `"enabled": false` is the zero
  value and is not written to `global.json`, so an operator who switched audit
  off cannot be told from one who never chose; turning it on for them would
  override a deliberate decision, and keep doing so on every restart. Instead
  the gateway logs a warning at startup when its audit log is off, or on and
  unsigned.
- `VerifyAuditChain` (`GET /v1/audit/verify`), administrators only, checks the
  chain over a window of at most 5,000 entries (default 1,000), oldest first,
  chained to the entry stored just before the window, and answers intact or the
  first entry that breaks the chain and why; `next_after_id` continues. A
  window's time bounds are compared in the zone the entries were written in --
  SQLite keeps a timestamp as text and Postgres's `TIMESTAMP` keeps the wall
  clock without its offset, and a UTC bound against local text selected the
  wrong entries. Entries written in one clock tick are put in chain order before
  they are checked. A verification that finds a break writes an audit entry
  saying so.
- An unsigned entry now ends the chain: the next signed entry starts from `""`,
  which is what a restart already read back. The writer used to carry the last
  signed hash across unsigned entries, so the same log verified after a restart
  and not before it.

**The dashboard.** An API Tokens page (administrators, lazy-loaded) lists,
creates -- showing the secret once, with a Prometheus job that reads it from a
file -- and revokes, naming the token. The audit page has a Verify integrity
action for administrators, a bounded window per click with Continue. The
password forms check and state the rule. Every refusal is a fixed sentence.

## Consequences

- Prometheus is configured with a token in a file, once. The runbook's viewer
  account and timer can be removed (see the upgrade note for the replacement
  paragraph).
- A stranger can no longer lock an administrator out. During a spread attack a
  legitimate user signing in from a source the account has never used is
  refused until the attack stops for fifteen minutes; the answer is to sign in
  from a known network, or wait. That is the price of keeping brute force at
  twenty guesses per fifteen minutes however many addresses the attacker has.
- Lockout state is per instance and in memory: a restart clears it, and an HA
  pair allows each node's budget. The known sources are in the database and
  survive both.
- Every test, seed and e2e account that set a password shorter than twelve
  characters had to change; the e2e accounts' password is now
  `e2e-horse-battery-42` and the dev seed's `gateon-dev-passphrase`.
- Existing installs with audit off stay off until an administrator turns it on.
  Their logs from before signing was on, and any written while it was off, do
  not verify; verification from a time after them does.
- An install run as several nodes writing one audit database has one chain per
  node interleaved, which does not verify as one chain. Not addressed here.
- The audit chain's trust anchor is still the signature key in the
  configuration; an attacker who holds it can rewrite the whole chain.
