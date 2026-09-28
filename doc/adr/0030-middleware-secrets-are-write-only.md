# 30. Middleware secrets are write-only

Date: 2026-09-28

## Status

Accepted. Co-signed `arch` ↔ `sec`: it moves the management API's trust
boundary for middlewares the way ADR 0028 moved it for the global
configuration. A caller who may write middlewares used to be trusted with every
credential in them; it is now trusted to change them and not to read them.

## Context

Middlewares are served by REST (`GET`/`PUT /v1/middlewares`) and by gRPC and
gRPC-Web (`ListMiddlewares`, `UpdateMiddleware`); the Connect handler does not
serve them. A caller without write permission -- a viewer -- read each secret as
the placeholder `__gateon_redacted__`. A caller with it -- an administrator, an
operator, anyone when authentication is off -- read the live objects verbatim:
basic-auth passwords, JWT, PASETO and HMAC keys, OAuth introspection and OIDC
client secrets, turnstile, bot-management and proof-of-work secrets, the canary
token and every API key. The reasoning was that someone who can replace a
secret gains nothing by reading it. They gain the secret: a replaced credential
breaks the clients that hold it, which somebody notices; a read one is used
quietly, and outlives the stolen session or the script in the dashboard -- which
renders traffic from hostile clients -- that took it.

The same data left by three more doors. `PUT /v1/middlewares` answered with the
saved middleware, secrets restored. `GET /v1/config/export` (read on config:
administrators and operators) wrote every middleware unmasked into a file meant
to be passed around, and the import preview echoed whatever it was sent. And
values the headers and rewrite middlewares set -- `Authorization: Bearer …`,
`X-Api-Key`, `?access_token=` -- reached even viewers, because the name-based
secret check looks at the config key (`set_request_Authorization`), which names
no credential.

Saving was worse than reading. `secretmask.Preserve` restored a placeholder only
when it was a whole value, so a basic-auth user list sent back as
`alice:__gateon_redacted__` stored the placeholder as Alice's password, and
`__gateon_redacted__-and-more` was accepted as a JWT key. Import never restored
anything.

## Decision

**Nothing the API returns carries a stored middleware secret, to anyone.** A
caller who may write middlewares reads each secret as the placeholder -- the one
ADR 0028 uses, `secretmask.Placeholder` -- a reference (`$env:`, `$vault:`,
`$aws-sm:`) as the reference, and an unset secret as `""`. A caller who may
only read reads the placeholder for references too, and for every value the
headers and rewrite middlewares set, whatever the header or parameter is
called. This holds for the list over REST and gRPC, the `PUT` answer, the
export, the import preview and the validate preflight. Code:
`internal/config/mwsecret` (`Mask`, `MaskForReader`, `Restore`).

**What counts as a secret.** A config key `secretmask.IsSecret` names
(`secret`, `secret_key`, `client_secret`, `password`, `canary_token`, anything
containing `secret`, `password`, `passphrase`, `private_key`, `api_key`,
`credential`, or `token`/`*_token`); the basic-auth `users` list, one secret per
user; the apikey middleware's `key_<APIKEY>` entries, where the key *name* is
the secret; and a value the headers middleware sets (`add_`/`set_` ×
`request_`/`response_`) or the rewrite middleware adds as a query parameter
(`query_`) when the header or parameter name counts as a credential.

**The header and parameter rule** (`secretmask.IsCredentialName`): the names
`Authorization`, `Proxy-Authorization`, `Cookie` and `Set-Cookie`, and any name
containing `token`, `secret`, `passw`, `key`, `auth`, `session`, `credential`,
`signature`, `bearer` or `jwt`, case-insensitively. It errs towards masking --
`WWW-Authenticate` and `Sec-WebSocket-Key` are caught, which costs a writer a
"Stored" badge where a value would have done. Its residue: a credential in a
header whose name gives nothing away (`X-Upstream: <token>`), a credential in a
body the transform middleware writes, and a literal in a CEL policy are not
recognised. A writer who puts one there is not protected; a viewer still reads
no header or query value at all.

**Saving keeps what it is not told to change.** `mwsecret.Restore` runs inside
the domain service's `SaveMiddleware`, the one path REST, gRPC and config import
share. Per secret:

- the placeholder keeps the stored value exactly as it is held -- a literal, an
  `enc:` value or a reference;
- a new value replaces it;
- `""` clears it. A secret the middleware cannot run without is then refused by
  the build check every save already makes (the factory builds the config
  before it is stored), naming it -- *refused, not kept*. For a middleware, `""`
  is never an omitted field: the config is a map, a key that is left out is
  removed like any other, and the dashboard sends every key. And `""` is how an
  operator hands a secret over to its `GATEON_JWT_SECRET`, `GATEON_HMAC_SECRET`,
  `GATEON_PASETO_SECRET` or `GATEON_OAUTH2_CLIENT_SECRET` fallback, which keeping
  would silently override.

The placeholder anywhere else -- a field that holds no secret, a value that
merely contains it, a middleware no stored one has the id of -- is refused,
named. A refused save changes nothing.

**List elements are matched by identity.** A basic-auth user keeps the stored
password of the stored user *with the same name*: reordering and removing users
keeps the right passwords, and a renamed user is a new user whose password has
to be entered. An API key is its own identity, so it is shown as
`key_<placeholder>_<fingerprint>`, labelled with its tenant; sent back that way
it keeps the stored key with that fingerprint, whatever the label now says.
Position is never an identity (a JSON object has no order, and a shortened list
would hand one element's secret to another), and neither is the tenant label,
which several keys may share. A marker no stored key matches is refused, naming
its tenant. The fingerprint is keyed -- HMAC-SHA256 under a key derived from
`GATEON_ENCRYPTION_KEY` when it is set, otherwise random per process -- because
an unkeyed hash would let anyone who reads middlewares test guesses offline,
and a hand-typed key (`partner-2024`) falls to that at once.

**A kept secret is used as it was entered for, and goes where it went before.**
The placeholder is refused when the same save changes the middleware's type or,
for the auth middleware, its kind of authentication (`jwt`, `basic`, `oauth2`,
…), and when it changes where the middleware sends its secret: the OAuth
introspection URL (`auth`/`oauth2`), the OpenID issuer (`oidc`, whose token
endpoint is discovered from it) and the forward-auth address. (The forward-auth
middleware stores no secret of its own today -- it forwards the client's
credentials -- so its binding covers any secret-named value its config
acquires; turnstile's secret goes to Cloudflare's fixed address and every other
stored secret stays in the gateway.) The comparison is
of the whole trimmed value, not a parsed host, so no difference between two URL
parsers can slip a new destination past it. Without the binding, write-only is
one request from read-back: point the introspection URL at a server you run,
keep the placeholder, and let the gateway deliver the client secret.

**The placeholder is reserved.** Both middleware stores (the file registry and
the database) refuse a config that holds it in any key or value, whichever path
brings it -- the API, an import, the seed from a middlewares file, a sync. The
factory refuses to build one too: a middlewares file written by hand, or seeded
from an export, reaches the factory without a store, and built, a jwt middleware
would accept any token signed with a string printed in the source. The router
serves the refusal it serves for any security middleware it cannot build.

**Export and import.** The export writes placeholders (and references as
references), masked for the caller exactly as a read is. An import into the same
gateway keeps the stored secret of the middleware with the same id, type and
destination; a placeholder for a new middleware, a changed type or a moved
destination is refused, naming the middleware and the field, while the rest of
the import proceeds as before. The preview (`?dry_run=true`) runs the same check
on copies and lists what would be refused under `refused`, and echoes what it
was sent masked. Validate returns only errors, which name fields, never values.

**There is no export that includes secrets.** A backup of middleware secrets is a
backup of the host's database or `middlewares.json` (encrypted at rest with
`GATEON_ENCRYPTION_KEY` where set), taken where the credentials already live. An
export that carried them would be a second, portable copy of every credential,
produced by an API call that one stolen session can make.

## Consequences

- API clients that read middleware secrets from `GET /v1/middlewares`,
  `ListMiddlewares` or the export stop getting them. Read-modify-write keeps
  working: send the placeholders back unchanged.
- Changing a middleware's type, its kind of authentication, its introspection
  URL, OIDC issuer or forward-auth address needs its secrets entered again.
  Renaming a basic-auth user needs that user's password again.
- Without `GATEON_ENCRYPTION_KEY`, API-key fingerprints last as long as the
  process: a dashboard form opened, or an export taken, before a restart cannot
  keep API keys -- they are refused by tenant and must be entered again. Gateways
  that share the key agree on fingerprints, so a load-balanced management API
  works across them.
- An import into a *different* gateway whose middleware ids happen to match
  keeps that gateway's own secrets for the placeholders. Ids are the only
  identity there is; "the same gateway" cannot be checked.
- Viewers no longer read any value the headers or rewrite middlewares set, so
  the dashboard shows them "Stored" for security headers too.

### Residue, recorded for a decision

- **A credential header or query value goes to the route's backend.** The
  headers and rewrite middlewares send what they set to whatever backend the
  route using them points at, and an operator may write routes and services. So
  an operator can attach an existing headers middleware to a route whose backend
  they run and receive the stored `Authorization` value. Binding it would need
  the route graph (every route using the middleware, and the services behind
  them) checked on every route and service save. Not done here.
- **References are resolved in every middleware field, with no allow-list.** The
  factory resolves `$env:NAME`, `$vault:…` and `$aws-sm:…` in any config value
  (`internal/middleware/factory.go`, `config.ResolveSecretStrict`). A caller who
  may write middlewares and routes -- an operator -- can create a headers
  middleware that sets `set_response_X-Leak: $env:NAME` and read any environment
  variable of the gateway process through a request to a route using it: the
  encryption key, database and cloud credentials, and every global secret that
  is configured as a reference. The same goes for any Vault or AWS secret the
  gateway can read, sent through an OAuth introspection URL of the caller's
  choosing. That defeats write-only for everything held by reference, and is an
  operator-to-administrator escalation. It predates this ADR, which does not
  make it worse; it needs an owner decision on which references a middleware may
  name (an allow-list, a prefix such as `GATEON_MW_`, or references only in
  secret fields bound to their destination).
