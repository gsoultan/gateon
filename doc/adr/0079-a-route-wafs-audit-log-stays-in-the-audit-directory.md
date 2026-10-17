# 79. A route WAF's audit log stays in the audit directory

Date: 2026-10-17

## Status

Accepted. Co-signed `arch` ↔ `sec`: it moves a trust boundary -- which files
an operator may make the gateway write -- that ADR 0040 recorded as open
residue. Driver `sec`, Challenger `net`.

## Context

A WAF middleware's `audit_log_path` named the file its audit log is appended
to. The WAF created the file's directory (`os.MkdirAll`) and opened the file
`O_CREATE|O_APPEND`, as given. ADR 0040 made the *global* WAF's
`audit_log_path` a Boundary setting, an administrator's to change, and noted
that the route-level key was the same write, reachable by anyone with
`middlewares:write` -- an operator.

So an operator could set a route WAF's `audit_log_path` to
`/var/lib/gateon/global.yaml`, `../../anything`, a cron directory or any other
file the gateway's user can write, and every request through the route
appended a JSON line of attacker-influenced request data (the request line, the
matched bytes) to it. Reproduced in a test: a route WAF pointed at a
`global.yaml` appended an audit record to it on the first blocked request.

## Decision

**A route WAF's `audit_log_path` is a file under `<data-dir>/audit/waf/`**, the
directory its default `<route>_audit.log` already lives in and the one the
dashboard describes. A relative name (`myroute.log`, `team/myroute.log`) is
read inside it. An absolute path is accepted only when it is already inside it
(the default path, written out). Any `..` element, an absolute path anywhere
else, and the directory itself are refused.

1. **Refused at save.** `Factory.checkSave` -- the save path REST, gRPC and
   config import reach through the domain service -- refuses such a value
   with an error naming the key and the directory, before `Create` would make
   a directory or open a file.
2. **Not used at build.** A config stored before this keeps building, so its
   route keeps serving (the ADR 0043 rule for a refusal added at save): the
   value is logged at WARN and the route writes its default file instead.
3. **Opened confined.** A value that passes is opened through an `os.Root` on
   the audit directory, so a symlink -- in a parent directory or as the file
   itself -- cannot lead out of it. A symlink escape is logged and falls back
   to the default file, as a stored bad value does.

**The global WAF's `audit_log_path` keeps full freedom.** It is a Boundary
setting (ADR 0040, `internal/authz/globalbound`): only an administrator can
set it, and an administrator may legitimately want the audit log on another
volume. A route that sets no path of its own inherits it unconfined, as
before; the confinement applies to the value the route itself wrote, which is
read before the global value is merged in.

## Consequences

- An existing route WAF whose `audit_log_path` is outside the audit directory
  writes `<data-dir>/audit/waf/<route>_audit.log` after upgrade, with a WARN
  naming the stored value, and cannot be saved unchanged. See
  `doc/upgrading.md`.
- A route that wants its audit log on another volume asks an administrator to
  set the global path, or mounts that volume under the audit directory.
- The dashboard field now says what it accepts.
