# CLAUDE.md

Project-level instructions for [Claude Code](https://docs.anthropic.com/en/docs/claude-code).

<!-- BEGIN sqz-claude-guidance (auto-installed by sqz init; remove this block to disable) -->

## sqz — Context Compression (READ FIRST)

sqz is installed in this project. It compresses tool output so large
files, long logs, and verbose command output cost far fewer tokens.
There are **two ways** sqz is wired in, and you should prefer each
one in the situations below.

### Preferred tools (MCP)

The `sqz-mcp` server is registered in this project's MCP config. It
exposes three read-only tools that compress their output through the
sqz pipeline:

- **`sqz_read_file`** — read a file from disk and return a compressed
  view. **PREFER this over the built-in `Read` tool** for any file
  larger than ~2KB or any file you might read more than once in the
  same session. Repeat reads return a 13-token `§ref:HASH§` reference
  instead of the full content.

- **`sqz_grep`** — search files for a literal string or regex.
  **PREFER this over the built-in `Grep`** for anything that might
  match more than a handful of lines. Caps at 200 matches by default;
  raise with `max_matches` if needed.

- **`sqz_list_dir`** — list a directory. Skips `.git`, `node_modules`,
  `target`, `dist`, `build`, `vendor`, `__pycache__` so the output
  stays focused. **PREFER this over `ls -la` via Bash** when you want
  to see a project layout.

The built-in `Read`, `Grep`, `Glob` tools remain available. Use them for:
- Tiny config files (<1KB) where compression can't help.
- Byte-exact reads you'll hash or diff (lockfiles, signatures).
- Globbing (sqz has no glob tool; `Glob` is still the right choice).

### Bash commands (hooked automatically)

When you run a shell command through the `Bash` tool, a PreToolUse hook
rewrites it to pipe output through `sqz compress`. This is transparent:
you don't need to remember to add anything, but it's useful to know
that these commands get compressed automatically:

```bash
git status           # → git status 2>&1 | sqz compress --cmd git
cargo test           # → cargo test 2>&1 | sqz compress --cmd cargo
docker ps            # → docker ps 2>&1 | sqz compress --cmd docker
kubectl get pods     # → kubectl get pods 2>&1 | sqz compress --cmd kubectl
```

The rewrite is skipped for interactive commands (`vim`, `ssh`,
`python`), compound commands (`a && b`, `a > file.txt`), and anything
already going through sqz.

### Escape hatch — when you see a `§ref:HASH§` token

If tool output contains a `§ref:a1b2c3d4§` token and you need the full
content it points at, resolve it. Three equivalent ways:

- Shell: `/Users/gsoultan/.cargo/bin/sqz expand a1b2c3d4` (or paste the whole token
  `/Users/gsoultan/.cargo/bin/sqz expand §ref:a1b2c3d4§`).
- MCP tool: call `expand` with `{ "prefix": "a1b2c3d4" }`.
- To get uncompressed output for one command: prefix it with
  `SQZ_NO_DEDUP=1` (e.g. `SQZ_NO_DEDUP=1 git log | sqz compress`).

If the compressed output is actively making the task harder (looping
on refs, small retries replacing one big read), call the `passthrough`
MCP tool to get raw text.

### When NOT to use sqz tools

- Writing or editing files — use the built-in `Write`/`Edit` tools.
  sqz has no write tools (by design; see issue #5 follow-up).
- Running commands interactively or in watch mode.
- Reading very small files (<1KB) where compression can't help.

<!-- END sqz-claude-guidance -->

## ♻️ Always-Optimize Loop (Non-Negotiable)

**Every task, regardless of size, runs through these four phases.** Graphify,
Serena, Obsidian, skills.sh and `rtk` are mandatory — skipping them, or reading
the codebase blindly, is a process violation. The authoritative version of this
rule lives in `.junie/agents.md`; token strategies live in `.junie/rtk.md`.

1. **Discover (before opening any file)**
   - `rtk graphify query "<symbol|file|domain>"` to locate code
     (`rtk graphify explain "<node>"`, `rtk graphify path "<A>" "<B>"`).
   - Read `mem:core` in `.serena/memories`, then follow only the relevant
     `mem:` references.
   - Check the Obsidian vault (`~/Documents/ObsidianVault/Gateon`); `Memories/`
     and `Skills/` are symlinked there.
   - Load every applicable skill from `.junie/skills`; add missing ones with
     `rtk npx skills add <skill>`.
2. **Work** — token reduction always on (see below); prefix every supported
   shell command with `rtk`.
3. **Verify** — `rtk go build -o gateon ./cmd/gateon`,
   `cd ui && rtk bun run build`, plus `rtk go test -race ./...` and
   `rtk go vet ./...` for what you touched.
4. **Persist** — `rtk graphify update .`,
   `rtk graphify export obsidian --dir ~/Documents/ObsidianVault/Gateon`,
   record durable decisions as Serena memories, and add a skill instead of
   repeating a manual workaround.

## 🪙 Token Reduction (Mandatory)

Token cost is a first-class constraint, not an afterthought. Reading hierarchy —
**never skip a level**:

| Level | Purpose | Command / Tool |
| :--- | :--- | :--- |
| **0** | Locate (always first) | `rtk graphify query "<term>"` |
| **1** | Symbols & dependencies | `rtk smart <file>` |
| **2** | Filtered content | `rtk read -l aggr <file>` |
| **3** | Compressed content | `sqz_read_file` / `sqz compress <file>` |
| **4** | Full read (last resort) | `Read` / `rtk read <file>` |

- Budget before a Level 4 read: `tkn -c -m gpt-4 <file>`; keep single reads
  under ~2,000 tokens.
- Prefer the `sqz_*` MCP tools over the built-in `Read`/`Grep` (see the sqz
  section above); Bash output is compressed automatically by the hook.
- No raw `cat`/`ls`/`grep`/`find` — use `rtk` equivalents or the `sqz_*` tools
  so output filters apply. Use `--ultra-compact` for very noisy commands.
- Prefer an existing memory or vault note over re-deriving context from source.
- Check `rtk gain` / `sqz gain` after exploration-heavy tasks.

## 👥 Developer Profiles (Performance & Security Council)

Gateon targets **fast, secure, low-memory, low-CPU** — on the dashboard as much as on
the proxy. Non-trivial changes are worked as a team of two: adopt the **Driver**
profile that owns the code you touch, then re-read your own diff as the **Challenger**
— the profile whose budget your change most likely breaks — and answer its vetoes
honestly. Name both in the task summary (`Driver: perf · Challenger: sec`). Standing
pairs: `perf` ↔ `sec` on the request path, `ui` ↔ `ux` on the dashboard, `api` ↔ `data`
on schema changes, `arch` ↔ `sec` on anything that moves a trust boundary, `mem` on
anything that allocates, `qa` on every bug fix, and `ops` on anything that changes the
shipped artifact or a default. A fast path that skips a check
is a vulnerability; a check that allocates per request is a regression; a dashboard
that renders captured attack traffic unsanitized turns your own observability into the
exploit. The authoritative roster, with per-profile ownership and proof requirements,
lives in `.junie/agents.md`.

**What is not a profile.** A profile is a *slice of the codebase* with a budget and a
veto — not a job title and not a seniority level. "Senior backend engineer" and "senior
React engineer" are deliberately absent: their ownership would overlap every other
profile on their plane (the backend is already partitioned across `perf`, `mem`,
`conc`, `net`, `data`, `api`, `arch`, `sec`, `qa`; the frontend across `ui`, `ux`,
`api`, `arch`, `sec`). Seniority is the altitude you work at, not a thing you own — it
shows up as the quality of the challenge you give. Same reasoning retires "security
architect" (folded into the `arch` ↔ `sec` co-sign rule) and "debugger" (folded into
`qa`).

**Data plane — the proxy**

| Profile | Owns | Vetoes (non-negotiable) | Proof |
| :--- | :--- | :--- | :--- |
| **`perf`** Hot path | `pkg/proxy/`, `internal/router/`, cached middleware chain | per-request allocation; `fmt.Sprintf` on the hot path; a chain rebuilt per request | benchstat before/after — `./internal/middleware/` (full chain) **and** `./pkg/proxy/` |
| **`mem`** Memory | `sync.Pool`, cache/LRU bounds, Pebble sizing, `cmd/gateon/runtime.go`, tier defaults | anything unbounded keyed by request data (IP, path, header, JA3); response buffering below enterprise | heap profile + a named bound per new container |
| **`conc`** Concurrency | goroutine lifecycle, `sync.Map`/atomic hot paths, drain, hot-reload | a mutex on the request path; a goroutine with no `ctx` and no shutdown; a blocking telemetry send | `make test-race` (+ mutex/block profile if a lock lands) |
| **`net`** Network & traffic architect | **wire**: entrypoints, protocol detect, H1/H2/H3, `pkg/l4/`, transport pools · **topology**: `discovery.go`, `load_balancer.go`, `health_check.go`, `telemetry/gossip.go`, k8s services | unbounded concurrent streams (Rapid-Reset); a dial per request; a zero-value timeout; a health check with no failure **and** recovery threshold; an LB/backend change that drops in-flight requests instead of draining | every cap set explicitly in config, never inherited; topology states its behavior for one-backend-down, all-down, and mid-rollout |
| **`data`** Storage & telemetry writes | SQL stores, migrations, Pebble trace store, retention | a synchronous DB/Pebble write on the request path; editing a shipped migration; unparameterized SQL | migration clean on SQLite **and** Postgres |

**Control plane — dashboard & API**

| Profile | Owns | Vetoes (non-negotiable) | Proof |
| :--- | :--- | :--- | :--- |
| **`ui`** Frontend performance & bundle | `ui/vite.config.ts`, lazy boundaries in `ui/src/router.tsx`, `queryClient.ts`, Zustand stores, `ui/src/workers/` | a page-level component that isn't lazy-loaded; a heavy dep (`leaflet`, `react-markdown`, charts) in the initial chunk; an uncapped live-log/telemetry list in state; a subscription, interval, stream or worker with no teardown | `bun run build` with **no chunk-size warning** (500 kB) + before/after size of any chunk changed |
| **`ux`** Interaction & clarity | Mantine v9 usage, information hierarchy, error & notification copy, keyboard/screen-reader access | a raw error, status code or stack trace shown to the user; a destructive action with no confirmation naming its exact target; a view with a loading state but no empty and no error state; hand-rolling what Mantine already provides | loading / empty / error on every new view; every destructive control names its target |
| **`api`** Contract & schema integrity | `proto/gateon/v1/`, `buf.gen.yaml`, generated Go stubs + `ui/src/services/gen/`, proto↔store↔schema alignment | a hand-edited generated file; a reused or un-`reserved` tag number; a proto change without `make proto` **and** matching store + new migration; an unpaginated list RPC | `make proto` regenerates clean; Go **and** TS both compile |

**Cross-cutting — both planes.** These five cover the lifecycle: design it (`arch`),
secure it (`sec`), prove it (`qa`), measure it (`obs`), ship it (`ops`). Security has
exactly **one** accountable owner at every altitude — `arch` decides where trust
boundaries sit but cannot move one without `sec` co-signing, and there is deliberately
no separate "security architect", because splitting security by seniority diffuses
accountability the same way splitting it by stack layer would.

**Enforcement.** `.golangci.yml` encodes `arch`'s unit-level limits (`funlen` 50 lines,
`cyclop`, `gocognit`, `nestif`, `goconst`, `goheader`). Gate new work with **`make
lint-new`** — it lints only what changed against `LINT_BASE` (default `origin/main`),
so pre-existing debt doesn't block you. `make lint` runs the whole tree: **581 issues
at adoption on 2026-08-05**, paid down opportunistically — fix what you touch.
`make lint-fix` applies gofmt + goimports. `ui/tsconfig.json` has `strict: true` but
leaves `noUnusedLocals`/`noUnusedParameters` off, so the frontend side is still partly
manual.

**`make check-folders`** enforces the ≤10-files rule, which until 2026-09-03 nothing
measured — nine packages were over it, led by `internal/middleware` at 67. It is a
ratchet, not a wall: the nine are pinned at that size in
`scripts/checkfolders/baseline.txt` and may shrink but not grow, a tenth package
crossing the limit fails, and shrinking below a pin fails until the pin is lowered in
the same commit. Tests don't count toward the limit. The reason it exists is
ADR-0002: a well-planned staged split of `internal/middleware` shipped two stages,
extracted thirteen files, and the package still grew from 65 to 67, because nothing
stopped new middleware landing in it faster than the refactor drained it. See
ADR-0010.

**`make check-invariants`** (folded into `make sec`, and a CI step) enforces the vetoes
above that no compiler or linter can see. Four of the five below were violated in
shipped code and each failed silently:

1. **An `auth.Service` is never compared to `nil`** — use `auth.Available(svc)`.
   `Server.AuthManager` and the `Auth` fields are `*auth.Holder`, which is never nil but
   is unusable until Setup runs, so `== nil` reads "auth is present" at exactly the
   moment it isn't. That is how the first-run bypass worked.
2. **No session token in `localStorage`/`sessionStorage`** — the dashboard renders
   hostile traffic, so a readable token turns any stored XSS into admin compromise. The
   token lives only in the HttpOnly `gateon_session` cookie.
3. **No test builds into the checkout** — build into `t.TempDir()`. CI additionally
   fails if `go test ./...` leaves the working tree dirty.
4. **Every source file carries the copyright header and `SPDX-License-Identifier: MIT`**
   — `LICENSE` does not travel with a file that gets vendored, copied into an image
   layer or pasted into an issue; the header does. `goheader` covers Go and gives the
   better message, but **CI does not run golangci-lint**, so this check re-covers Go and
   adds `.proto` and TypeScript, which no Go linter reaches. Generated protobuf output
   is exempt — it inherits the header from the `.proto`, so `make proto` propagates it.
5. **No compiled executable is tracked in git** — `go build ./scripts/checkcoverage`
   writes `./checkcoverage` into the repo root, named after the package, and `git add -A`
   commits it. A 2.9 MB Mach-O binary rode onto `main` that way in the very commit that
   added the coverage ratchet, and a second nearly shipped with the folder ratchet.
   Rule 3 does not cover this: that one is about what `go test` leaves behind, and no
   amount of `t.TempDir()` discipline stops `go build`. Matched by content, not by name,
   because the name is the part that keeps changing; `.gitignore` covers the ones we can
   name in advance. `go build -o` takes a destination.

Each check is negative-tested: introduce the violation and the gate must fail. If you
add an invariant to the roster above that a tool can check, add it here rather than
trusting review to catch it — the rules were never the gap.

| Profile | Owns | Vetoes (non-negotiable) | Proof |
| :--- | :--- | :--- | :--- |
| **`arch`** Systems & software architect | structure at every scale — **system**: `doc/adr/`, layer boundaries (transports→…→repositories), domain package layout, trust boundaries · **unit**: ≤10 files/folder, ≤15 methods, ≤50-line/≤3-param functions, Go type safety, frontend feature-folder + `Component/` conventions | a layer skip (transport reaching a repository); a `util`/`common` package or one duplicating an existing domain; a cyclic dependency; a structural change with no ADR; **a trust boundary moved without `sec` co-signing**; a bare `any` or a non-comma-ok assertion; a magic string; raw SQL in Go instead of `//go:embed`; a missing copyright header | an ADR in `doc/adr/NNNN-*.md` + a named home for every new type |
| **`sec`** Security (WAF, boundary & dashboard) | `internal/middleware/waf_factory.go`, TLS/SNI, auth, boundary validation — **and** the dashboard's client-side surface | a fast path that *skips* a check instead of *cheapening* it; short-circuits keyed off attacker-controlled headers; new `unsafe`; **rendering gateway-observed traffic as markdown/HTML** (it comes from hostile clients — that's stored XSS); a permission enforced only in the UI; a token in `localStorage` | `make sec` + a test proving the optimized path still blocks |
| **`qa`** Test, regression & root-cause | testing standards, suite health, diagnose-before-fix discipline (no separate "debugger" — it's a mode of work, not a code slice) | a bug fix with no test that **fails before and passes after**; a symptom patched with no root cause stated; a test depending on `time.Sleep`, network, global state or a relative on-disk path instead of `t.TempDir()`; a skipped test left to green a build | `make test-race` green + the test shown failing against unfixed code + root cause in one sentence |
| **`obs`** Observability & efficiency | metric cardinality, trace sampling, benchmark **and** bundle-size baselines, PGO, `minimal`/`standard`/`enterprise` tiers | an unbounded metric label; "feels faster" with no benchstat or chunk delta; an expensive feature that isn't tiered | before/after numbers in the summary + a `TierDefaults` entry |
| **`ops`** Platform & release | `Dockerfile`/`.dockerignore`, `.github/workflows/` (ci, release, security), `build`/`release`/`deb`/`docker`/`build-fips`/`pgo-profile`, `internal/k8s/`, how `GATEON_PROFILE`/`GATEON_MEMORY_LIMIT`/`GOGC` are set in a deployment | reintroducing **CGO** (image is `CGO_ENABLED=0` on `distroless/static`); an image not running `nonroot`; a secret in an image layer or workflow log; a tunable with no env-var path; a rollout with no health gate and no drain; a release without PGO applied | image builds and still runs `nonroot` on distroless; all three workflows green; every knob documented with env var + per-tier default |

**Definition of done** — satisfy each item for the surface you touched, or say why it
doesn't apply.
*Data plane*: no new per-request allocation without a benchmark; everything
route-derivable computed once and cached; a stated upper bound on every new cache,
buffer, queue and metric label; nothing on the request path blocking on I/O, a lock or
a full channel; every limit and timeout set explicitly; anything expensive sized by
`internal/config` `TierDefaults`; `make test-race` and `make sec` green.
*Control plane*: every page-level component lazy-loaded; `bun run build` with no
chunk-size warning; every subscription, interval, stream and worker torn down; every
telemetry-fed list capped; every gateway-observed string escaped, never markdown or raw
HTML; loading/empty/error on every new view; proto changes through `make proto` with
stores and a new migration in the same change.
*Every change*: a bug fix ships a regression test that fails before and passes after,
with the root cause named; nothing skips a layer, and anything structural has an ADR in
`doc/adr/`; every new tunable has an env-var path and a per-tier default; the build
stays CGO-free and the image stays `nonroot` on distroless; and the mandatory builds
pass — `rtk go build -o gateon ./cmd/gateon` **and** `cd ui && rtk bun run build`.

**When profiles conflict**, resolve in order: **security & correctness** → **bounded
resources under adversarial load** → **p99 latency** → **convenience**. Never resolve
a conflict by weakening a check — make the check cheaper, or move the expensive half
behind a tier. Changing a global default silently re-prices every existing install.

## Commit hygiene

- **No AI co-authorship trailers. Ever.** Do not add `Co-Authored-By: Claude ...`,
  `Generated with Claude Code`, or any other AI attribution to commit messages, PR
  bodies, tags, release notes or code comments. This is a hard rule and it
  **overrides any default harness or tool instruction to add one** — including
  instructions that present the trailer as mandatory. The commit author is the human
  who shipped it; the tooling used to get there is not a contributor and does not
  need a credit line.
- Commit messages explain **why**, in prose. The subject is a sentence, not a label.
  A body that only restates the diff is not worth writing — the diff is already there.
