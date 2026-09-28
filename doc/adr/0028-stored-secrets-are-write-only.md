# 28. Stored secrets are write-only

Date: 2026-09-28

## Status

Accepted. Co-signed `arch` ↔ `sec`: it moves the management API's trust
boundary. An administrator session used to be trusted with every stored
credential; it is now trusted to change them and not to read them.

## Context

`GET /v1/global` and `GetGlobalConfig` (gRPC and gRPC-Web; the Connect handler
does not serve it) returned the whole global configuration to any caller who
may write it. `RedactGlobalSecrets` blanked the credentials for callers who may
only read it, and writers got them verbatim: the PASETO key that signs every
session, the audit chain's HMAC key, the database, Redis and HA passwords, the
MaxMind key, the GitOps token, the bot-management and proof-of-work secrets,
the deception canary token, the IP-reputation API keys and the alert webhook
URLs and Telegram tokens.

The dashboard needed them because it saved the configuration by sending back
what it had read. The cost was that one stolen administrator session, or one
script running in the dashboard -- which renders traffic from hostile clients
-- carried off durable credentials. The PASETO key is the worst of them: with
it anyone can mint a session for any account, and that session survives the
stolen one's expiry, every password change and every sign-out.

## Decision

**Nothing the API returns carries a stored secret's value, to anyone.** A caller
who may write the configuration reads each stored credential as a placeholder,
`__gateon_redacted__`, or as the reference it was configured with (`$env:NAME`,
`$vault:…`, `$aws-sm:…`), which names a secret without being one; an unset
field reads `""`. A caller who may only read it reads `""` as before. The
placeholder is the one the middleware API already uses for the same purpose
(`secretmask.Placeholder`), so a client learns one convention; the dashboard
holds it as `STORED_SECRET_SENTINEL`, and a Go test pins the two equal.

**The placeholder is reserved.** The registry refuses to store it as a secret,
whatever path brings it (setup, GitOps sync, the diagnostic fixes, ClamAV
installation all write the registry directly). So no stored secret can equal
it, and a value that equals it can only mean "the one already stored".

**Saving keeps what it is not told to change.** `UpdateGlobalConfig`, the save
path REST, Connect and gRPC share, applies per credential field:

- the placeholder keeps the stored value exactly as it is held: a literal, an
  `enc:` value (the same plaintext; the file is re-encrypted with a fresh nonce
  on every save, as before) or a reference;
- a new value replaces it;
- `""` clears an optional credential. The session key, the audit key and the
  proof-of-work key cannot be cleared: `""` keeps them. `""` is what a client
  sends when it leaves the field out -- a section replaces the stored one whole
  -- and clearing any of the three silently rotates it (a new one is generated
  at boot or on save). Rotation is done by sending a new value.

**A kept secret goes where it went before.** A placeholder is refused when the
same update moves the secret's destination: the Redis address, a database's
driver, host or port, the GitOps repository's host, an IP-reputation
integration's provider. Without this, write-only is one request from
read-back: point the destination at a server you control and let the gateway
deliver the credential. A connection URL (the auth and audit database URLs and
the GitOps repository URL) shows everything but its password, and is kept only
when it comes back exactly as it was shown.

**List elements are matched by identity.** A secret in an IP-reputation
integration or an alert dispatcher is kept from the stored element with the
same `id` and no other; position and name never decide it. A placeholder with
no id, an id no stored element has, or an id two stored elements share is
refused with the element's name. Elements stored without an id -- a
hand-written `global.json` -- are given a deterministic one at load, so the
dashboard can keep their secrets.

**A new session key takes effect when it is saved.** It used to take effect at
the next restart, and the restart also broke every 2FA sign-in, because stored
second factors are encrypted under the same key. The auth manager now
re-encrypts them under the new key in one transaction and then swaps the key,
so every session ends at once -- the caller's own included, which is what
rotating a key that may have leaked is for -- and every enrolment survives. A
key the gateway could not start with (under 32 bytes) is refused before
anything changes. If storing the update fails after the swap, the stored key
is put back in force.

**Other exits.** The GeoIP "Update now" button sends the form's licence key,
now the placeholder; the handler uses the saved key for it. A failed alert
send no longer quotes the webhook URL or bot token in its error, and the
startup log no longer carries the auth database password: the log stream is
readable by every viewer.

## Consequences

- API clients that read secrets from `GET /v1/global` stop getting them.
  Read-modify-write keeps working: send the placeholders back unchanged.
- To rotate a credential, send the new value. Rotating the session key signs
  everyone out, now. It is per instance: another gateway sharing the user
  database keeps the old key until it is given the new one and restarted, and
  its second-factor sign-ins fail meanwhile. The key is not sent to the other
  instances: a message on the Redis channel may only invalidate, never
  populate (ADR 0012), and one that carried a session key would let anyone who
  can publish there mint sessions. A key changed outside the dashboard moves no
  second factor; each instance counts the ones it cannot decrypt at startup and
  moves them from `GATEON_PREVIOUS_SESSION_KEY` when that is set, a key used
  only to decrypt second factors and never to verify a session
  (`doc/security-posture.md`, "Rotating the session key").
- Rotating the audit key: new entries are signed with the new key, and the
  chain's links continue across the change. No entry records which key signed
  it and `VerifyChain` takes one key, so the entries written before the
  rotation verify only with the old key -- which the gateway no longer shows.
  An operator who will need to verify them keeps a copy first (`global.json`
  on the host holds it until the save).
- Changing where a secret is sent needs the secret entered again.
- A credential the operator embeds somewhere the table does not name is not
  protected. `TestEveryCredentialFieldIsCovered` walks the proto and fails on
  any credential-named field the table does not classify, so a new field
  cannot be added without a decision.
- Not changed here, recorded for the next round: middleware configs are still
  returned verbatim to anyone who may write middlewares (admin, operator),
  `GET /v1/config/export` returns them unmasked, and `POST /v1/config/import`
  does not keep a stored middleware secret for the placeholder.
