# AGENTS.md

Instructions for AI coding agents (OpenAI Codex, GitHub Copilot, Cursor,
Windsurf, Amp, Devin) working in this repository. See <https://agentsmd.io>.

<!-- BEGIN sqz-agents-guidance (auto-installed by sqz init; remove this block to disable) -->

## sqz — Token-Optimized CLI Output

When running shell commands whose output may be long (directory listings,
git log/diff, test runners, build logs, `docker ps`, `kubectl get`, etc.),
pipe the output through `sqz compress` to reduce token consumption.

`sqz` is a stdin-to-stdout compressor, not a command wrapper. The correct
usage is to pipe the command's output into `sqz compress`:

```bash
# Instead of:     Use:
git status        git status 2>&1 | /Users/gsoultan/.cargo/bin/sqz compress
cargo test        cargo test 2>&1 | /Users/gsoultan/.cargo/bin/sqz compress
git log -10       git log -10 2>&1 | /Users/gsoultan/.cargo/bin/sqz compress
docker ps         docker ps 2>&1 | /Users/gsoultan/.cargo/bin/sqz compress
ls -la            ls -la 2>&1 | /Users/gsoultan/.cargo/bin/sqz compress
```

The `2>&1` captures stderr too, which is useful for commands like `cargo
test` where diagnostics go to stderr. `sqz compress` filters and compresses
the combined output while preserving filenames, paths, and identifiers.
It typically saves 60-90% tokens on verbose commands.

Do NOT pipe output for:
- Interactive commands (`vim`, `ssh`, `python`, REPLs)
- Compound commands with shell operators (`cmd && other`, `cmd > file.txt`,
  `cmd; other`) — run those directly
- Short commands whose output is already a few lines

If `sqz` is not on PATH, run commands normally.

The `sqz-mcp` MCP server is also available — Codex reads it from
`~/.codex/config.toml` under `[mcp_servers.sqz]`. It exposes three
tools: `compress` (the default pipeline), `passthrough` (return text
unchanged — the escape hatch below), and `expand` (resolve a
`§ref:HASH§` token back to the original bytes).

## Escape hatch — when sqz output confuses you

If you see a `§ref:HASH§` token and can't parse it, or compressed
output is leading you to make lots of small retries instead of one
big request, use one of these:

- **`/Users/gsoultan/.cargo/bin/sqz expand <prefix>`** — resolve a dedup ref back to the
  original bytes. Accepts bare hex (`sqz expand a1b2c3d4`) or the full
  token pasted verbatim (`sqz expand §ref:a1b2c3d4§`).
- **`SQZ_NO_DEDUP=1`** — set this env var for one command to disable
  dedup: `SQZ_NO_DEDUP=1 git status 2>&1 | sqz compress`. You'll get
  the full compressed output with no `§ref:…§` tokens.
- **`--no-cache`** — same opt-out as a CLI flag:
  `git status 2>&1 | sqz compress --no-cache`.

If you're using the MCP server, the `passthrough` tool returns raw
text and the `expand` tool resolves refs — call them when you need
data sqz hasn't touched.

## Copyright Standards
All backend source files (Go, Protobuf) MUST include the following copyright header:
```go
// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
```

## Obsidian Integration
This project uses a dedicated Obsidian vault as an **Agentic Second Brain** to optimize context retrieval and reduce token costs.

- **Vault Location**: `~/Documents/ObsidianVault/Gateon`
- **Workflow**:
    1. **Discovery**: Before reading files, check the Obsidian graph for structural context.
    2. **Mapping**: Use the bi-directional links between file nodes to understand dependencies.
    3. **Memory**: Access symlinked `.serena/memories` and `.junie/skills` directly within the vault.
- **Sync**: Re-export the graph after major changes using `rtk graphify export obsidian --dir ~/Documents/ObsidianVault/Gateon`.

## Database Migrations & Schema Consistency
To ensure the application remains stable and migrations run smoothly, follow these rules:

- **Permanent Fixes**: Never apply "quick fixes" that bypass the migration system. If a database schema needs to change, always use a new migration.
- **Migration Order**: Never modify existing migration files (e.g., `Register(1, ...)` to `Register(56, ...)`). If you need to change the schema established by a previous migration, add a NEW migration with a higher ID (e.g., `57`).
- **Query Stability**: Do NOT change SQL queries in existing migrations. Changing them after they have already run on some environments will lead to inconsistent database states ("If you change the query you fuck").
- **Schema Alignment**: When updating Protobuf definitions, immediately update the corresponding database repository stores (`internal/repositories/stores/`) and add a new migration to align the database schema.
- **Postgres Compatibility**: Always test migrations against Postgres if possible, as it is more strict about types (e.g., `INTEGER` vs `TIMESTAMP`) than SQLite.
- **Auto-Fixing**: If a system-level table (like `migrations`) is in a bad state, implement auto-fixing logic in `internal/db/migration.go` before running pending migrations.
- **Mandatory Build**: Run both backend and frontend builds at the end of every task to verify that the changes haven't introduced any compilation errors. NEVER submit if either build fails.
    - **Protobuf**: `make proto` (if you changed any `.proto` files)
    - **Backend**: `rtk go build -o gateon ./cmd/gateon`
    - **Frontend**: `cd ui && rtk bun run build`

<!-- END sqz-agents-guidance -->

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

| Level | Purpose | Command |
| :--- | :--- | :--- |
| **0** | Locate (always first) | `rtk graphify query "<term>"` |
| **1** | Symbols & dependencies | `rtk smart <file>` |
| **2** | Filtered content | `rtk read -l aggr <file>` |
| **3** | Compressed content | `sqz compress <file>` |
| **4** | Full read (last resort) | `rtk read <file>` |

- Budget before a Level 4 read: `tkn -c -m gpt-4 <file>`; keep single reads
  under ~2,000 tokens.
- Pipe verbose command output through `sqz compress` (see the sqz section
  above); binary at `/Users/gsoultan/.cargo/bin/sqz`.
- No raw `cat`/`ls`/`grep`/`find` — use the `rtk` equivalents so output filters
  apply. Use `--ultra-compact` for very noisy commands.
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
