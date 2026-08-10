# Contributing to Gateon

Thanks for considering it. Gateon is a security gateway, so the bar for a
change is a little higher than "it works on my machine" — most of what follows
is about making that bar visible rather than making it hard.

## License

Gateon is [MIT licensed](LICENSE). By contributing, you agree your work is
released under the same terms. There is no CLA to sign.

Do not paste in code you did not write. If you adapt something permissively
licensed (MIT, BSD, ISC, Apache-2.0), name the source and its license in the
pull request. Copyleft code (GPL, LGPL, AGPL) and source-available code (SSPL,
BUSL, Elastic License) **cannot be accepted** — either would relicense the
project out from under everyone using it under MIT today.

## Every source file carries a header

Two lines, at the very top, before the package clause:

```go
// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT
```

`//` for Go, proto, TypeScript and TSX; `#` for shell. `LICENSE` at the repo
root does not travel with a file that gets vendored into another module, copied
into a container layer, or pasted into an issue — this line does.

It is enforced, not suggested: `golangci-lint`'s `goheader` checks Go, and
`make check-invariants` checks Go, `.proto` and `ui/src` (CI runs the latter).
Generated files are exempt — they inherit the header from the `.proto`, so fix
the `.proto` and `make proto` propagates it.

## Setting up

```bash
go build -o gateon ./cmd/gateon        # backend
cd ui && bun install && bun run build  # dashboard
```

`make build` does both and syncs the dashboard into the embedded asset
directory. Without that sync, a local build quietly ships a stale dashboard.

## Before you open a pull request

```bash
make test-race        # tests with the race detector
make lint-new         # lints only what you changed, not pre-existing debt
make sec              # govulncheck + staticcheck + gosec + invariants
cd ui && bun run build   # must produce no chunk-size warning
```

`make lint` runs over the whole tree and reports pre-existing findings — use
`make lint-new` as the gate, and fix surrounding debt only in code you touched.

## What gets a change merged

Gateon uses a **developer profile** model rather than a generic review
checklist: each area of the codebase has an owner with an explicit budget and
an explicit veto. The full roster — who owns what, what each will refuse, and
what proof they require — is in [`CLAUDE.md`](CLAUDE.md) and
[`.junie/agents.md`](.junie/agents.md). Worth skimming the row for the area
you are touching before you start.

The rules that come up most often:

- **A bug fix ships a test that fails before and passes after**, with the root
  cause stated in one sentence. A symptom patched with no root cause is not a
  fix.
- **No new per-request allocation on the proxy path** without a benchstat
  before/after. No `fmt.Sprintf` on the hot path; nothing route-derivable
  recomputed per request.
- **Every cache, buffer, queue and metric label states an upper bound.**
  Anything keyed by attacker-supplied input (IP, path, header, JA3) needs a
  bound and an eviction policy.
- **Never make a fast path skip a check.** Make the check cheaper, or tier the
  expensive half. A fast path that skips a check is a vulnerability.
- **The dashboard renders hostile traffic.** Gateway-observed strings are
  escaped, never rendered as markdown or raw HTML, and no credential goes near
  `localStorage`.
- **Every new view has loading, empty and error states**; every destructive
  control names its exact target.
- **Proto changes go through `make proto`** with matching store changes and a
  new migration in the same commit. Never hand-edit a generated file.
- **Structural changes need an ADR** in [`doc/adr/`](doc/adr/).

## Commit messages

Explain **why**, in prose. The subject is a sentence, not a label. A body that
only restates the diff is not worth writing — the diff is already there.

Do not add AI co-authorship trailers of any kind.

## Reporting a vulnerability

Do not open a public issue. Follow [`SECURITY.md`](SECURITY.md).
