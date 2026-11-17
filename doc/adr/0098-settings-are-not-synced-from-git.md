# 98. Settings are not synced from Git

Date: 2026-11-17

## Status

Accepted. `arch` drives (a writer of the global configuration is removed, and
with it a trust boundary: who may change the gateway's settings); `sec`
co-signs. `ops` challenges what an existing install sees on upgrade.

Resolves the open question ADR 0080 left: what a synced repository is trusted
to say. Nothing, because there is no longer a synced repository.

## Context

GitOps (`management.gitops`) cloned a Git repository on a timer, read one JSON
file from it and, when that differed from the stored global configuration,
stored it in place of the whole thing. It had no ADR of its own.

- **It bypassed the checks a save goes through.** A save from the dashboard,
  REST or gRPC runs `validateGlobalSave`, the Boundary authorization of ADR
  0040 and the stored-secret rules of ADR 0028, and writes an audit entry. A
  sync called the registry's `Update` directly: none of the validation, no
  audit entry, and the whole configuration -- `auth`, `rbac`, `audit` and
  `management` included -- replaced by whoever could push to the repository.
  ADR 0040 named that as a delegation an administrator chose; ADR 0080 left it
  open.
- **Nobody could see it.** It was off by default and the dashboard never showed
  it. It was enabled only through the API or a `gitops` block in
  `global.json`, so an operator reviewing the dashboard could not tell a
  repository was steering the gateway, and an attacker who enabled it once had
  a channel that outlived a password reset.
- **It synced the least useful part.** Only the global settings. Routes,
  services, certificates and middlewares were never synced, so it could not
  manage a gateway declaratively, which is what GitOps usually means.
- **It carried weight.** go-git and a dozen modules that only it needed, one
  of them a second OpenPGP implementation, for a feature nothing used.

Making it safe would have meant running a sync through the same validation,
authorization and audit as a save, plus a host-key story for SSH (the reason
`ssh_private_key` was dropped in August). That is a feature to design, not a
fix, and there is no user asking for it.

## Decision

GitOps is removed. No code path fetches settings from Git.

- `internal/config/gitops.go`, its supervisor reconcile, the go-git dependency
  tree and the `management.gitops` stored-secret entries are deleted.
- `ManagementConfig.gitops` (tag 11) and `GitOpsConfig` are removed from the
  proto. The tag and the name are `reserved`, so neither can be reused with a
  different meaning.
- **An existing config keeps working.** `global.json` and `global.yaml` are
  decoded with `encoding/json` and `yaml.v3`, which skip a key the message no
  longer has: a file with a `management.gitops` block loads, the rest of it is
  in force, and nothing syncs. Because skipping quietly would leave an operator
  believing a repository still governs the gateway, `GlobalRegistry.load`
  checks the raw file for retired keys and logs a warning naming
  `management.gitops` and this ADR. The next save writes the file without it.
- On the API, REST and Connect decode JSON with `DiscardUnknown`, as they do
  for every other removed setting, and binary gRPC keeps a removed tag as an
  unknown field that is never read or stored. A client still sending the block
  changes nothing.

## Consequences

- Global settings change only through a save (dashboard, REST, gRPC), the
  Diagnostics fixes, ClamAV install mode, first-run setup, and the operator's
  own files at boot. Each of these but the boot files is reached through the
  authenticated management API or the setup token.
- An operator who manages `global.json` with their own deployment tooling
  (a mounted file, `GLOBAL_CONFIG_FILE`) is unaffected: that is the operator
  writing a file, not the gateway fetching one.
- If declarative management comes back, it is a new design that covers routes
  and services too and runs every change through the same checks as a save.
- `retiredGlobalSections` in `internal/config/global.go` is the place to name
  the next removed section whose silence would mislead.
