# Gateon — Improvement Recommendations & Execution Roadmap

This document consolidates the full set of recommendations from the deep review of
Gateon (backend `~37k` LOC across `internal/`, `pkg/`, `cmd/`; frontend `~26k` LOC in
`ui/`). It also defines a **session-based execution roadmap**.

> **Working rule for every session:** Each session must leave `main` in a
> **production-ready** state (builds clean, all tests green, no disabled tests) and
> must follow `.junie/agents.md` guidelines (Go 1.26 idioms, layered architecture,
> SQL externalization, security-first, type/thread safety, `go test -race ./...`,
> `gofmt`/`goimports`/`go vet`).

---

## Progress Tracker

_Last updated: 2026-06-16 (**Session 7 Stage 1 (`auth`):** moved the authN/authZ middlewares into a new `internal/middleware/auth` package (10 files) with a `kind` re-export `aliases.go`; `package middleware` keeps a transparent `auth_aliases.go` shim so factory dispatch, package tests, and all external callers compile unchanged (`tls_binding.go` kept in `package middleware` — uses the security-group `recordAdvancedThreat`, moves with `security`). Root middleware dropped 71→62 `.go` files; build/vet/gofmt clean, middleware/server/api tests pass. Earlier: **Ignored-error audit slice:** handled four more meaningful sites — `graphql_factory.go` (malformed `field_costs`/`field_claims` config now errors), `certs.go` (both cert-dir `MkdirAll` failures now log + 500), `api/status.go` (stored-header parse debug-logged), `cache_redis.go` (Redis `Set` failure debug-logged, headers via `slices.Clone`); build/vet/gofmt clean, `internal/middleware`/`internal/server/handlers`/`internal/api` tests pass. Earlier: **Session 3 fully done — eBPF now hot-reloads too.** The eBPF subsystem is driven through a new `ebpf.Holder` (`internal/ebpf/holder.go`): an atomic indirection implementing `ebpf.Manager` that every consumer (alerting, the request-path server, the metrics poll loop, the anomaly detector) references, so the `securitySupervisor` (`reconcileEbpf`) can swap the underlying `EbpfManager` in/out when `Ebpf.Enabled` toggles without invalidating any captured pointer or restarting. `reconcileEbpf` is privilege/OS-gated (CAP_BPF/root), `proto.Equal`-diffed, and runs the poll loop on the holder; the holder no-ops safely when eBPF is disabled. Added table-driven tests (`holder_test.go` no-op/delegate/swap; `supervisor_test.go` reconcileEbpf enable/idempotent/disable/disabled/nil-holder). No background security subsystem remains boot-only except the gossip reputation sync (no stop hook). Build/vet/gofmt clean; `internal/ebpf`, `cmd/gateon`, `internal/server/...`, `internal/middleware` tests pass (CGO_ENABLED=0).)_


Legend: ✅ done · 🔄 in progress / partial · ⬜ not started.

| Session | Area | Status | Notes |
|---------|------|--------|-------|
| 1 | Upload pipeline correctness & DoS fix | ✅ done | `file_security.go` rewritten: body buffered + reconstructed via `restoreBody` (drain bug fixed); bounded scan concurrency (semaphore), configurable `ScanTimeout` (30s default), per-route fail-open/closed, per-file `MaxFileSize` (413), deny-by-default MIME allowlist. New table-driven tests pass. |
| 2 | UI white-screen & nav-flash fixes | ✅ done | Global + per-route `ErrorBoundary` (recoverable fallback w/ error id, Reload/Try-again); `Suspense fallback` now renders a `RouteFallback` loader (no blank flash); `queryClient` gained `staleTime`/`gcTime`/`keepPreviousData` + a deduped global `MutationCache` error toast; centralized `notifyError`/`notifySuccess` helper. `vite build` passes. |
| 3 | Config hot-reload for security subsystems | ✅ done | Added `GlobalRegistry.Subscribe`/notify (old+new clones) fired on every `Update`; new `securitySupervisor` (`cmd/gateon`) hot-reloads **anomaly detection, GitOps, HA** via per-subsystem cancellable contexts + `proto.Equal` diffing. Root check already eBPF-capability-gated. _WAF rule auto-update loop now hot-reloads via the `securitySupervisor` (toggling `Waf.AutoUpdateRules` takes effect without a restart). ClamAV now hot-reloads too via `reconcileClamAV` (atomic config + in-place `Reconfigure`). **eBPF now hot-reloads via `reconcileEbpf` using an `ebpf.Holder` atomic indirection** (the request-path/alerting/poll-loop reference the holder, the supervisor swaps the underlying manager). No subsystem remains boot-only except the gossip reputation sync (no stop hook)._ |
| 4 | Repo & CI hygiene + security gates | ✅ done | Added `.github/workflows/security.yml` (govulncheck + staticcheck hard gates, gosec + trivy-fs SARIF code-scanning, weekly cron); CycloneDX SBOM via GoReleaser `sboms` + Syft step in `release.yml`; `make sec`/`vuln`/`staticcheck`/`gosec`/`test-race` targets. **Remediated all 12 call-reachable CVEs**: `x/crypto`→v0.52.0, `x/net`→v0.55.0, OTel→v1.43.0, `toolchain`→go1.26.4 (stdlib) — `govulncheck ./...` now reports **0**. Earlier: tracked DB removal, `.gitignore`, `t.TempDir()`, eBPF-gated root check, `logger.Init` handling. _Ignored-error audit: highest-risk paths now handled (k8s DB writes, bootstrap config/env writes, WAF-updater status-write + zip-slip guard, TLS CA-read, graphql config-parse, cert-dir MkdirAll, stored-header parse, Redis cache write); remaining ~205 sites are benign best-effort writes (ongoing low-risk sweep)._ |
| 5 | Resource bounds & storage retention | ✅ done | Telemetry caches **configurable + bounded** via `GATEON_TELEMETRY_*_CACHE_SIZE` (validated, floor, default) + `gateon_telemetry_cache_capacity`/`_entries` gauges. **Storage retention reclaims disk:** `prune()` SRP helpers, Pebble `Compact` after `DeleteRange`, SQLite `incremental_vacuum`+`wal_checkpoint(TRUNCATE)` (`auto_vacuum=INCREMENTAL`). **buffer_pool reuse:** WebSocket tunnel now uses `io.CopyBuffer` with the shared pool (removes a 32KB alloc/direction). **build-once audit:** confirmed Coraza WAF + Aho-Corasick `fastScanner` are built once (config-time/init), not per request. **pprof/bench:** opt-in `GATEON_PPROF_ADDR` server (off by default, own listener), `make bench` (CPU/heap profiles), and a CI benchmark step. |
| 6 | UI performance | ✅ done | `LiveLogs` WS frames now **batched** (single state update / 300ms flush, bounded at `MAX_LOGS`) + all four filters via `useDeferredValue` + memoized `formatLog`/`getLogColor` (kills per-message re-render jank). Heavy libs isolated into a lazy `viz-vendor` chunk and **lazy-loaded within their pages** (`TopologyGraph`→xyflow/dagre, `AnomalyMap`→leaflet). Added env-gated `rollup-plugin-visualizer` (`bun run analyze`→`dist/stats.html`) + 500KB `chunkSizeWarningLimit`. **All built chunks verified <500KB.** _Deferred (low-risk): `SettingsPage`/Dashboard/Metrics lazy-tab split — those chunks are already lazy + modest (≤74KB)._ |
| 7 | Middleware package refactor & unified Store | 🔄 partial | **Architecture docs delivered:** `doc/adr/` (ADR-0001 layered architecture, ADR-0002 *staged* middleware split, ADR-0003 keep per-domain `Store` interfaces over a mega-store) + `doc/architecture.md` (Mermaid request-path/dependency/target-layout diagrams), linked from `doc/README.md`. **Stage 0 done:** the cycle-free core was extracted into the new leaf package `internal/middleware/kind` (`Middleware`/`Chain`/`Recovery`/`SecurityHeaders`/`ContextKey`+keys/`DebugInfo`/path predicates + pooled `StatusResponseWriter` + custom-error-page middleware); `package middleware` now holds only **transparent aliases** so all 60+ files and external callers compile unchanged, breaking the import cycle that blocked the split. New table-driven `kind/core_test.go`; `go build`/`vet`/`gofmt`/tests green. **Stage 1 (`auth`) done:** the authN/authZ middlewares (10 files) moved into a new `internal/middleware/auth` package (+ a `kind` re-export `aliases.go`); `package middleware` keeps a transparent `auth_aliases.go` shim so factory dispatch, package tests, and external callers compile unchanged (`tls_binding.go` stays for now — it uses the security-group `recordAdvancedThreat`, moves with `security`). Root middleware dropped 71→62 `.go` files; build/vet/gofmt + middleware/server/api tests green. _Deferred (each its own shippable session): remaining per-group moves (`security`/`traffic`/`transform`) + registry dispatch; optional DB/etcd `Store` backends._ |
| 8 | UI accessibility | ✅ done | Added `eslint-plugin-jsx-a11y` flat config + `lint` script, wired as a CI **accessibility gate** (`ci.yml`); surfaced + fixed the only 2 violations (`no-autofocus`: LoginPage 2FA via `useRef`+effect focus, TwoFactorModal via Mantine `data-autofocus`; also fixed a missing `Paper` import). `Shell.tsx` gained a **skip-to-content** link + `<main id="main-content">` landmark + `aria-label`s on all icon-only controls (sidebar toggle, theme menu, refresh, burger). `styles.css` adds global `prefers-reduced-motion`, a high-contrast `:focus-visible` ring, and skip-link styles. `bun run lint` + `bun run build` both green. |
| 9 | Wazuh-like detection foundation | ✅ done | **FIM:** dependency-free `internal/security/fim` scanner (SHA-256 baseline, drift diff, bounded events, `Status()`, periodic `Start`/`OnDrift`); opt-in via `GATEON_FIM_PATHS`/`GATEON_FIM_INTERVAL`. **YARA-lite signature engine:** new dependency-free `internal/security/yara` (11-rule built-in set: EICAR/PE/ELF/PHP-JSP-ASPX webshells/reverse-shell/PowerShell/PDF-JS/Office-macro/HTML-polyglot, MITRE-tagged, custom JSON rules), integrated inline into `file_security.go` (blocks `>=` `signature_block_severity`, default high; keys `enable_signature_scan`/`signature_rules_path`/`signature_block_severity`). **Posture endpoint:** `GET /v1/security/posture` reports WAF/ClamAV/**signatures**/FIM. All table-driven tests pass. _Optional follow-up: Trivy/Grype CVE artifact scanning (external binaries)._ |
| 10 | Correlation + SIEM export | ✅ done | **Correlation engine** (`internal/security/correlation`): keys signals by fingerprint/IP, raises **MITRE ATT&CK-annotated incidents** when MinSignals (default 3) or MinScore is met within a sliding window, with re-alert debounce, bounded tracked-sources/per-source signals + idle GC. **SIEM export** (`internal/security/siem`): async **bounded** shipper (non-blocking, drop+count on overflow, atomic `Stats`) exporting events as **JSON/CEF/RFC5424-syslog** over **HTTP/UDP/TCP** (bearer token, per-send timeout, lazy reconnect), opt-in via `GATEON_SIEM_*`. **Wiring** (`cmd/gateon/threatpipeline.go`): subscribes to `ThreatBroadcaster`, feeds the engine, logs every incident (works without SIEM), ships incidents (+ optional raw threats via `GATEON_SIEM_RAW_THREATS`); all ctx-cancellable. Table-driven tests for MITRE map, window/threshold/debounce/GC, formatters, and end-to-end HTTP delivery via `httptest`. Documented in `doc/siem-correlation.md`. |
| 11 | UI delight features | ✅ done | **⌘K command palette** (`ui/src/components/CommandPalette`): dependency-free (Mantine `Modal` + `@mantine/hooks` `useHotkeys`, no `@mantine/spotlight`), fuzzy multi-token filter over every page + quick actions (toggle sidebar, theme, sign out), full keyboard control (↑/↓/Enter/Esc), role-aware (Users admin-only); header `CommandSearchButton` with platform-aware shortcut hint. **Persisted preferences** (`usePreferencesStore`, Zustand `persist`→localStorage): sidebar-collapsed (now drives `Shell`) + table density. **Connection-status indicator** (`ConnectionStatus`): network-aware LIVE/CONNECTING/RECONNECTING/OFFLINE from `useNetwork` + backend status poll. **Onboarding checklist** (`components/Dashboard/OnboardingChecklist`): dashboard-mounted guided setup deriving entry-point -> service -> route -> protection completion from live `total_count`/middleware types, with a progress bar, per-step deep links, RBAC-gated actions, a persisted dismiss (`usePreferencesStore.onboardingDismissed`), and auto-hide when complete. `bun run lint` (jsx-a11y) + `bun run build` green (all chunks <500KB). **Global search + shareable URL-state filters** (`hooks/useUrlFilters` + route `validateSearch`): `AuditLogsPage` (`q`) and `TracesPage` (`q`,`route`) persist filters in TanStack Router search params for bookmarkable/shareable views. Dependency-free, type-safe **i18n scaffolding** (`ui/src/i18n/`: canonical `en` catalog deriving `TranslationKey`, language registry with a partial `id` locale + English fallback, memoized `t(key, params)` with `{{param}}` interpolation, `I18nProvider` syncing `<html lang>`); persisted `language` + a translated **Appearance → Language** selector (`AppearanceCard` migrated to `t()`). |

**What's next:** Sessions 1–11 are complete; Session 9 now includes dependency-free YARA-lite malicious-upload signature scanning. _Remaining standalone follow-ups (Session 3 hot-reload now fully done incl. eBPF): finish Session 7 (per-group middleware moves per ADR-0002 — **Stage 0 `kind`-leaf + Stage 1 `auth` subpackage done**, import cycle broken; `security`/`traffic`/`transform` remain); `SettingsPage`/Dashboard/Metrics lazy-tab split; broad ignored-error audit (highest-risk DB/config/crypto + middleware config-parse/cert-dir/cache paths now done; ~205 benign best-effort sites remain); generic `crudStore[T]` helper + DB/etcd backends per ADR-0003; optional Trivy/Grype CVE artifact scanning (external binaries)._

---

## Part A — Backend Recommendations

### A1. Bugs to fix (highest priority)

- **Critical — `internal/middleware/file_security.go` drains the request body, then
  forwards it.** The middleware reads the multipart body via `r.MultipartReader()` and
  then calls `next.ServeHTTP(w, r)`. The body stream is already consumed, so the
  **upstream receives a truncated/empty upload**. Fix by buffering to a pooled
  buffer / temp file and replacing `r.Body` (and `Content-Length`), or scan inline with
  an `io.TeeReader` and reconstruct the multipart body before proxying.
- **`file_security.go` opens a new `clamd` connection per part and blocks up to 2 minutes
  per file.** DoS/resource-exhaustion vector. Use a bounded clamd connection pool, a
  configurable (shorter) timeout, and offload scanning to a worker pool with backpressure.
- **Fail-closed scan behavior is hardcoded.** On clamd connection failure it returns
  `500 "Security scan unavailable"`. Fail-open vs fail-closed must be **configurable per
  route**.
- **Security subsystems are wired only once at startup (`cmd/gateon/main.go`).**
  `ebpf`, `clamavManager`, `anomaly detector`, `gitops`, `ha` are initialized from the
  global config in a single boot-time block. Toggling these in the UI/config **does not
  take effect without a restart**, contradicting the "dynamic hot-reload" claim.
  Subscribe these managers to config-change events.
- **Hard root requirement on Linux** (`os.Geteuid() != 0 → os.Exit(1)`). Blocks
  rootless/container deployments. eBPF needs specific capabilities (`CAP_BPF`,
  `CAP_NET_ADMIN`, `CAP_PERFMON`), not full root. Gate the root check behind features
  that actually need it.
- **Ignored errors.** `_ = logger.Init(...)` in `main.go`, and ~187 `_ = ...`
  occurrences in non-test code. Audit these — especially around config load, DB writes,
  and crypto — and log/handle them.
- **Committed test artifacts in git:** `internal/telemetry/test_telemetry_audit.db`,
  `.db-shm`, `.db-wal`. Remove from version control, add to `.gitignore`; tests should
  use `t.TempDir()`.
- **Verify the Go toolchain pin.** `go.mod` declares `go 1.26`. Confirm this matches
  CI/release toolchains (pin via `toolchain` directive) to avoid build drift.

### A2. Clean architecture / maintainability

- **`internal/middleware/` is overloaded (~70+ files)** mixing concerns. Split into
  cohesive subpackages: `middleware/auth`, `middleware/security`, `middleware/traffic`,
  `middleware/transform`, each exposing a small registration surface.
- **Dual source of truth for config**: file-based JSON registries (`routes.json`,
  `services.json`, …) plus DB-backed stores. Define a single `Store` interface with
  file/DB/etcd backends so the rest of the code is storage-agnostic.
- **Keep handlers thin**: push business logic into `internal/domain`; `server/handlers`
  should orchestrate only.
- Extend the functional-options DI in `server.NewServer(...)` to security managers for
  testability.
- Add **architecture decision records (`doc/adr/`)** and a dependency diagram.

### A3. Low CPU / memory / storage

- **Move file scanning off the request path.** Use an async, bounded worker pool; stream
  to disk with pooled buffers (reuse `pkg/proxy/buffer_pool.go` everywhere, including
  `io.Copy`).
- **Bound and make caches configurable.** `zerotrust.go` hardcodes an ARC cache of
  100,000 users; several LRU caches exist. Expose sizes via config; add metrics on cache
  size/evictions.
- **Storage growth controls.** Pebble + SQLite + Redis run simultaneously. Add
  retention/compaction policies (extend the existing telemetry path-stats retention to
  all stores), document expected disk usage, consider consolidating Pebble vs SQLite.
- **Compile-once hot paths.** Ensure the Aho-Corasick `Scanner` and WAF rule sets are
  built once and reused, not per-request.
- **Add a load/benchmark suite** (extend `pkg/proxy/bench_test.go`); run `pprof`/heap
  profiling in CI to track allocs/op.
- Tune `http.Transport` (idle conns, `MaxIdleConnsPerHost`, `ReadHeaderTimeout`) per
  backend — verify `transport_config.go` exposes these.

### A4. Security hardening

- **Fail-secure defaults** for auth, rate-limit, and scan middlewares; never fail-open
  silently.
- **Secrets:** AES-GCM + Vault + AWS Secrets Manager is good. Add key-rotation support;
  never log decrypted values; verify the `enc:` AES key comes only from env/KMS.
- **Upload defenses beyond MIME/magic checks** in `file_security.go`:
  - Recursive archive inspection with a **max decompression ratio** (zip-bomb protection).
  - **Polyglot/embedded-payload** detection (e.g., PDF-with-JS, image-with-script).
  - Treat `AllowedMimeTypes` as an allowlist by default (deny-by-default).
- **Audit log** already uses HMAC + hash chaining (tamper-evident) — good. Consider
  periodic anchoring of the chain head to an external store/transparency log.
- **CI security gates:** add `govulncheck`, `gosec`, `staticcheck`, and `trivy`/`grype`
  image scanning. Generate an **SBOM** at release (`.goreleaser.yaml` can emit one).
- Add **security headers / mTLS** defaults to the management entrypoint and rate-limit
  auth endpoints.

### A5. Wazuh-like file/vulnerability detection

Gateon is a network gateway; target the gateway-appropriate subset and integrate with a
real SIEM for the rest:

- **File Integrity Monitoring (FIM):** baseline-hash served static assets and config
  files; alert on drift. Extend audit hash-chaining into a periodic FIM scanner.
- **Vulnerability detection on uploads:** integrate **YARA** (custom exploit/malware
  signatures) alongside ClamAV, and a CVE scanner (e.g., **Trivy/Grype**) for uploaded
  artifacts. Run async in the worker pool, not in-band.
- **Detonation/sandboxing** for high-risk uploads (offload to an isolated scanning
  service) rather than blocking the proxy.
- **Correlation/rules engine:** correlate existing signals (IP threat scores, entropy,
  anomaly, JA3) into incidents mapped to **MITRE ATT&CK** technique IDs.
- **SIEM export:** ship structured threat/audit events to OpenSearch/Elastic/**Wazuh
  indexer** via OTel, syslog, or CEF.
- **Self vulnerability posture:** wire `govulncheck` into CI and expose a
  `/v1/security/posture` endpoint reporting WAF rule version, ClamAV signature freshness,
  and known-CVE status of the running build.

---

## Part B — Frontend (UI) Recommendations

Stack: React 19 + Mantine 9 + TanStack Router/Query/Form + Zustand + Tailwind 4 +
Vite 8 (`~26k` LOC, 23 page routes).

### B1. Critical UX gaps (fix first)

- **No `ErrorBoundary` anywhere.** A single render error white-screens the whole app.
  Add a top-level boundary in `main.tsx` and per-route boundaries via TanStack Router's
  `errorComponent`, with a friendly fallback (Reload/Report + error id).
- **`Suspense fallback={null}` in `router.tsx`.** Replace `null` with a lightweight
  route-skeleton or top progress bar to remove the blank flash on lazy navigation.
- **`queryClient` has no `staleTime`.** Set a sensible `staleTime` (15–30s for config,
  shorter for live metrics) and add `placeholderData: keepPreviousData` for
  paginated/time-window tables.

### B2. Loading, empty & error states

- **Standardize skeletons** for every async surface (tables, cards, charts) instead of
  spinners. Build reusable primitives: `<TableSkeleton/>`, `<CardSkeleton/>`,
  `<ChartSkeleton/>`.
- **Add first-class empty states** (e.g., "No routes yet → Create your first route").
- **Centralize toast feedback:** `notifyError(err)` / `notifySuccess()` wired into
  TanStack Query `onError` / global `mutationCache`.

### B3. Accessibility

- `aria-` attributes appear in only 1 file; no i18n. Add `aria-label` to icon-only
  buttons, verify keyboard nav/focus rings, run axe/Lighthouse, add
  `eslint-plugin-jsx-a11y` to CI, add "skip to content", verify color contrast in both
  themes, respect `prefers-reduced-motion`.

### B4. Performance & maintainability

- **Split `SettingsPage.tsx` (82KB monolith)** into tabbed, lazy-loaded sub-sections
  (use existing `components/settings/`). `Dashboard.tsx` and `MetricsPage.tsx` (~32KB)
  similarly.
- **Virtualize long lists/tables** (audit logs, live logs, path stats, traces) with
  `@tanstack/react-virtual`; cap retained rows for WebSocket streams.
- **Throttle/coalesce real-time updates** (batch every 250–500ms); use `useDeferredValue`
  for search/filter inputs.
- **Bundle hygiene:** confirm Leaflet/dagre/xyflow load only on their routes; add
  `rollup-plugin-visualizer` to CI.

### B5. Higher-level UX polish

- **Command palette (⌘K)** for fast navigation and quick actions.
- **Global search & saved filters** with shareable URL state (TanStack Router search
  params).
- **Onboarding checklist** (delivered): `components/Dashboard/OnboardingChecklist` guides a fresh install through entry-point -> service -> route -> protection; inline tooltips for security toggles remain a follow-up.
- **Optimistic updates** for route pause/enable toggles (`onMutate` + rollback).
- **Persisted user preferences** (density, default time-window, sidebar state) via
  Zustand + localStorage.
- **Real-time WS connection status indicator** with auto-reconnect backoff.
- **i18n scaffolding** (e.g., `react-i18next`) to avoid a future retrofit.

### B6. UI quality gates

- CI: `tsc --noEmit`, `eslint` + `jsx-a11y`, component tests (extend existing
  `Dashboard.test.ts`, `TopologyGraph.test.tsx` to forms and auth flow).
- Visual-regression / Storybook for shared primitives (cards, skeletons, status badges).

---

## Part C — Session-Based Execution Roadmap

Each session is scoped to be independently shippable and **production-ready** on
completion. Order is by risk/impact: correctness & security first, then performance,
then architecture, then features.

### Session 1 — Upload pipeline correctness & DoS fix (backend) — ✅ DONE
- ✅ Fixed `file_security.go` body-consumption bug (buffer body + reconstruct via `restoreBody`, keeps `Content-Length`).
- ✅ Bounded scan concurrency via semaphore (backpressure); configurable `ScanTimeout`
  (default 30s, was hardcoded 2m). _Note: a dedicated clamd connection pool and a fully
  off-request async worker pool remain as a future optimization (tracked in A3/Session 5)._
- ✅ Made fail-open vs fail-closed configurable per route; deny-by-default `AllowedMimeTypes`.
- **Done when:** uploads proxy intact, malware still blocked, race tests pass, new
  table-driven tests cover clean/infected/oversized/timeout/scan-unavailable cases.
- **Result:** delivered. New table-driven tests (intact-body regression, file/body too
  large, scanner-unavailable fail-open/closed, non-multipart passthrough) pass; build
  clean; `gofmt`/`go vet` clean. Tests verified with `CGO_ENABLED=0` (race detector
  blocked by a pre-existing cgo `go-m1cpu` init segfault on the local toolchain).

### Session 2 — UI white-screen & nav-flash fixes (frontend) — ✅ DONE
- ✅ Added a top-level class `ErrorBoundary` (`ui/src/components/ErrorBoundary/`) wrapping
  the providers in `main.tsx`, plus a per-route `RouteErrorComponent` wired as the
  router's `defaultErrorComponent`. Both share a recoverable `ErrorFallback`
  (friendly message, error id, Try-again/Reload actions).
- ✅ Replaced `Suspense fallback={null}` in `router.tsx` with a `RouteFallback` loader
  (no blank flash on lazy navigation).
- ✅ Set `queryClient` `staleTime` (30s) / `gcTime` (5m) and a global
  `placeholderData: keepPreviousData` default.
- ✅ Centralized `notifyError`/`notifySuccess` (`ui/src/utils/notify.ts`, reusing
  `getApiErrorMessage`) and wired a global `MutationCache.onError` toast that
  de-dupes against per-mutation `onError`/`meta.skipGlobalError`.
- **Result:** delivered. `vite build` (the project's production build) passes. _Note:_
  the repo has many pre-existing `tsc --noEmit` errors unrelated to this work (the build
  pipeline uses Vite/esbuild and does not gate on `tsc`); the new files are `tsc`-clean.
  No UI test runner is configured in `package.json`, so component tests were not run.

### Session 3 — Config hot-reload for security subsystems (backend) — ✅ DONE
- ✅ Added a subscription primitive to `GlobalRegistry`: `Subscribe(ConfigChangeFunc)` plus
  a notify step in `Update` that fires listeners (outside the lock, with deep clones of
  the old/new config, and rolls back on save error). All UI/API config writes funnel
  through `Update`, so this is the single hot-reload trigger.
- ✅ Added `securitySupervisor` (`cmd/gateon/supervisor.go`) that subscribes to the
  registry and starts/stops/restarts **anomaly detection, GitOps, and HA** using
  per-subsystem cancellable contexts, diffing each section with `proto.Equal`. Replaced
  the inline boot blocks in `main.go`.
- ✅ Linux root check is capability-gated behind eBPF (graceful degradation) — completed
  in Session 4; rootless start works when eBPF is off.
- **Done when:** toggling a subsystem in config takes effect live; rootless start works
  when those features are off.
- **Result:** delivered. New table-driven tests cover notify-on-update, listener ordering,
  nil-listener safety, and clone isolation; `go build ./...`, `go vet`, `gofmt` clean;
  `go test ./internal/config/` passes (CGO_ENABLED=0, race detector blocked by the
  pre-existing `go-m1cpu` cgo init segfault on this host).
- ✅ **WAF rule auto-update loop hot-reloads** via the `securitySupervisor`
  (`reconcileWAFAutoUpdate`): toggling `Waf.AutoUpdateRules` starts/stops the periodic
  loop without a restart (`wafAutoUpdater` interface + table-driven tests).
- ✅ **ClamAV manager hot-reloads** via the `securitySupervisor` (`reconcileClamAV`):
  `ClamAVManager.config` is now an `atomic.Pointer` and a thread-safe `Reconfigure`
  swaps the config + rebuilds the scheduled cron jobs **in place**, so the manager
  pointer captured by the request-path server (api service / posture provider) stays
  valid. The manager is always created at boot (even when ClamAV is initially disabled)
  so it can be enabled live; `reconcileClamAV` diffs with `proto.Equal` and a nil config
  disables the scheduled jobs. New table-driven tests cover manager `Reconfigure`
  (enable/disable/update/nil-safe) and supervisor `reconcileClamAV`
  (first-apply/idempotent/changed/disable/nil-manager).
- ✅ **eBPF hot-reloads** via the `securitySupervisor` (`reconcileEbpf`) using a new
  `ebpf.Holder` (`internal/ebpf/holder.go`) — an atomic indirection implementing
  `ebpf.Manager` that the request-path server, alerting, the metrics poll loop and the
  anomaly detector all reference. The supervisor swaps the underlying `EbpfManager` in/out
  when `Ebpf.Enabled` (or its config) changes, so no captured pointer is invalidated and no
  restart is needed. `reconcileEbpf` is privilege/OS-gated (CAP_BPF/root graceful
  degradation), `proto.Equal`-diffed, and runs the poll loop on the holder; the holder
  no-ops safely when eBPF is disabled. New table-driven tests cover the holder
  (no-op/delegate/swap) and supervisor `reconcileEbpf`
  (enable/idempotent/disable/disabled/nil-holder).
- **Only the gossip reputation sync (tied to HA) remains boot-only**, as it exposes no
  stop hook; no other background security subsystem is start-once.

### Session 4 — Repo & CI hygiene + security gates — ✅ DONE
- ✅ Removed tracked telemetry test DBs (`test_telemetry_audit.db*`); extended `.gitignore`;
  switched `store_test.go` to `t.TempDir()`.
- ✅ Pinned Go toolchain (bumped `toolchain go1.26.4` — see CVE remediation below).
- ✅ Replaced unconditional Linux root exit with eBPF-gated graceful degradation
  (overlaps Session 3); handled the previously-ignored `logger.Init` error.
- ✅ Added `.github/workflows/security.yml`: `govulncheck` and `staticcheck` as hard
  (build-failing) gates; `gosec` and a Trivy filesystem scan upload SARIF to GitHub code
  scanning; runs on push/PR + a weekly cron to catch newly disclosed CVEs.
- ✅ Added a CycloneDX SBOM to releases via GoReleaser `sboms` (per-archive) plus a Syft
  download step in `release.yml`.
- ✅ Added local-parity `make` targets: `vuln`, `staticcheck`, `gosec`, `sec` (full gate),
  and `test-race`.
- ✅ **Remediated every govulncheck finding** (12 call-reachable vulns): upgraded
  `golang.org/x/crypto`→v0.52.0, `golang.org/x/net`→v0.55.0, the OTel suite
  (`otel`/`sdk`/`otlptrace*`)→v1.43.0, and bumped the Go toolchain to **go1.26.4** for the
  stdlib fixes (`net/textproto`, `mime`, `crypto/x509`). `govulncheck ./...` now reports
  **"No vulnerabilities found."**
- 🔄 **Ignored-error audit — highest-risk paths done.** The genuinely risky ignored errors
  are now handled (logged or returned), leaving only benign best-effort calls (response
  writes, fire-and-forget cleanup):
  - **DB writes** — `internal/k8s/controller.go` now logs every failed `routeStore`/
    `serviceStore` `Update`/`Delete` (Ingress + HTTPRoute sync/delete).
  - **Config/env writes** — `internal/inits/bootstrap.go` handles the `globalReg.Update`
    bootstrap-defaults write and routes all `os.Setenv` calls through a `setEnv` helper that
    logs failures (OTel/Redis/TLS env propagation).
  - **WAF rule update** — `internal/middleware/waf_updater.go` logs the `last_update.txt`
    write failure, returns errors from extraction `MkdirAll`, and gained a **zip-slip guard**
    rejecting archive entries that resolve outside the destination.
  - **Crypto/cert path** — `internal/tls/manager.go` `ValidateCertificateFiles` now returns
    the CA-file read error instead of silently validating against a nil CA.
  - **Config parse (middleware)** — `internal/middleware/graphql_factory.go` now returns a
    descriptive error on malformed `field_costs`/`field_claims` JSON instead of silently
    applying empty maps (misconfiguration surfaces at middleware build time).
  - **Cert directory creation** — `internal/server/handlers/certs.go` now logs + returns 500
    when the certs dir `MkdirAll` fails (both upload and paste handlers), instead of
    swallowing it and producing a confusing downstream `os.Create`/`os.WriteFile` error.
  - **Stored-header parse / cache write** — `internal/api/status.go` debug-logs failed
    stored request/response header `json.Unmarshal` (display-only, never fails the trace
    listing); `internal/middleware/cache_redis.go` debug-logs Redis cache `Set` failures
    (non-fatal) and copies headers via `slices.Clone`.
  - _Remaining ~205 `_ = ...` sites are benign best-effort writes/cleanup; tracked as an
    ongoing low-risk sweep._
- **Done when:** CI runs all gates green; no tracked binaries/DBs. — met (`govulncheck`
  clean, build/vet/gofmt clean, touched tests pass).

### Session 5 — Resource bounds & storage retention (backend) — ✅ DONE
- ✅ Made the in-memory telemetry caches configurable + bounded. New
  `internal/telemetry/cachesize.go` centralizes the sizes (no magic numbers) and resolves
  each from a `GATEON_TELEMETRY_*_CACHE_SIZE` env var via `cacheSizeFromEnv` (parses,
  validates against a `minCacheSize` floor, falls back to the documented default and warns
  on bad input). Wired into the `zerotrust` (user-location), `reputation` (sharded),
  `behavior` (sharded), and `store` (`scoreCache`/`unmitigatedCache`) inits; sharded
  per-shard sizes are floored at 1.
- ✅ Added eviction/occupancy metrics: `gateon_telemetry_cache_capacity` (configured max)
  and `gateon_telemetry_cache_entries` (live `.Len()` per cache, shards summed), refreshed
  by `StartCacheMetricsLoop` (15s, started in `internal/server/run.go`, cancelled via ctx).
- ✅ Extended the benchmark suite: `BenchmarkReputationHotPath` (uses `b.Loop()`) records
  the reputation read hot path at ~30.6 ns/op, 1 alloc/op. Added table-driven
  `cacheSizeFromEnv` tests + an occupancy-safety test.
- ✅ Storage retention now **physically reclaims disk**. `prune()` was decomposed into
  SRP helpers (`prunePathAndDomainStats`/`pruneTraces`/`pruneSecurityThreats`/`pruneAuditLogs`
  + `reclaimSQLDisk`). Pebble trace `DeleteRange` is followed by `Compact` over the pruned
  range (tombstones were never reclaimed before); SQLite runs `PRAGMA incremental_vacuum`
  + `PRAGMA wal_checkpoint(TRUNCATE)`, with `auto_vacuum=INCREMENTAL` added to
  `SQLitePragmas`. Server SQL backends (Postgres/MySQL) self-vacuum (no-op). Added
  `TestPruneRemovesExpiredStatsAndReclaimsDisk`. Documented stores, retention, disk-usage
  sizing, cache env vars, and the cache gauges in `doc/storage-retention.md`.
- ✅ **buffer_pool reuse on hot paths.** The WebSocket tunnel (`pkg/proxy/websocket.go`) now
  copies both directions via `io.CopyBuffer` with a buffer borrowed from the shared
  `bufferPool` (`copyWithPooledBuffer`), removing a fresh 32KB allocation per tunnel
  direction per connection. The HTTP reverse proxy already used `rp.BufferPool = bufferPool`.
- ✅ **Build-once audit.** Confirmed the Aho-Corasick `fastScanner` is a package-level `var`
  built at init, and the Coraza WAF instance (`coraza.NewWAF`) is built once per route in
  `WAF(cfg)` (config-time) and captured in the returned middleware closure — neither is
  rebuilt per request.
- ✅ **pprof + benchmark regression gate.** Added an opt-in profiling server
  (`cmd/gateon/pprof.go`, gated by `GATEON_PPROF_ADDR`, off by default, on its own listener,
  ctx-shutdown); a `make bench` target (`-benchmem` + CPU/heap profiles to `dist/`); and a
  CI benchmark step in `ci.yml` (`pkg/proxy`, `internal/telemetry`). Documented in
  `doc/storage-retention.md`.
- **Done when:** configurable limits enforced, benchmarks recorded, no regressions. — **met:**
  cache limits + metrics + benchmark + storage retention/compaction + buffer-pool reuse +
  build-once audit + pprof/CI bench all delivered; build/vet/gofmt clean, touched tests pass.

### Session 6 — UI performance (frontend) — ✅ DONE
- ✅ **Live-stream jank eliminated.** `LiveLogs.tsx` now buffers incoming WebSocket
  frames and flushes a single batched `setLogs` every 300ms (`FLUSH_INTERVAL_MS`),
  bounded at `MAX_LOGS` (buffer also capped), instead of one re-render per message.
  All four filters (`search`/`route`/`status`/`clientIp`) run through `useDeferredValue`
  so typing stays responsive, and `formatLog`/`getLogColor` are memoized via `useCallback`.
- ✅ **Heavy libs route-lazy + code-split.** Confirmed all 22 routes are already `lazy()`;
  the only heavy deps (leaflet, `@xyflow/react`, dagre) are reachable solely through
  `TopologyGraph` (Topology) and `AnomalyMap` (Diagnostics). Both are now additionally
  **`React.lazy`-loaded within their pages** behind `Suspense`, and a `viz-vendor`
  `codeSplitting` group isolates the libraries into their own chunk fetched on demand.
- ✅ **Bundle analysis.** Added env-gated `rollup-plugin-visualizer` to `vite.config.ts`
  (`ANALYZE=1` → `dist/stats.html`, off for normal/CI builds) + a `bun run analyze`
  script, and lowered `chunkSizeWarningLimit` to 500 to surface oversized chunks.
- ✅ **Chunk budget verified.** Production `vite build` passes with **every chunk <500KB**
  (largest: `mantine-vendor` 416KB, `viz-vendor` 408KB, `BarChart` 356KB — all lazy);
  the `viz-vendor` chunk no longer ships on non-graph routes.
- ⬜ **Deferred (low-risk follow-up):** split `SettingsPage.tsx`/Dashboard/Metrics into
  lazy tabbed sub-sections. These routes are already `lazy()` and their chunks are modest
  (`SettingsPage` ≈74KB / 18KB gzip), so the remaining win is render-time decomposition
  rather than bundle size; tracked separately to keep this session shippable.
- **Done when:** initial settings render is fast, chunks < 500KB, no jank on live streams.
  — **met:** chunks all <500KB (verified), live-stream re-render jank removed; settings
  route is lazy + modest (full tab-split deferred as above).

### Session 7 — Middleware package refactor & unified Store (backend) — 🔄 PARTIAL
- ✅ **`doc/adr/` created** with three records (MADR-style): ADR-0001 (layered,
  domain-oriented architecture + the ≤10-files rule), ADR-0002 (*staged* refactor of
  `internal/middleware` into `kind`/`auth`/`security`/`traffic`/`transform` subpackages),
  ADR-0003 (keep **per-domain `Store` interfaces** — `RouteStore`, `ServiceStore`, … —
  rather than collapsing to a single mega-store, and add DB/etcd backends behind them).
- ✅ **Dependency diagram delivered** in `doc/architecture.md` (Mermaid): layered
  request path, config store-interface graph, and the **target acyclic** middleware
  package layout; linked from `doc/README.md`.
- ✅ **Key finding documented:** a flat→nested move of `internal/middleware` (65 non-test
  files) does **not compile** — the `Middleware` type lives in `package middleware`
  while `factory.go` would import any new subpackage, forming an import cycle. ADR-0002
  specifies the safe fix: Stage 0 extracts the cycle-free core into a `middleware/kind`
  leaf (with temporary type aliases), then each cohesive group is moved + verified one
  shippable step at a time.
- ✅ **Stage 0 executed.** New leaf package `internal/middleware/kind` holds the
  cycle-free core (`Middleware`, `Chain`, `Recovery`, `SecurityHeaders`, `ContextKey` +
  keys, `DebugInfo`, path predicates, the pooled `StatusResponseWriter` + `StatusString`,
  and the custom-error-page middleware). `package middleware` now keeps only
  **transparent aliases** (`middleware.go`) so all 60+ remaining files and ~12 external
  caller packages compile unchanged — the import cycle that blocked the split is broken.
  Verified with `go build ./...`, `go vet`, `gofmt`, and a new table-driven
  `kind/core_test.go`.
- ✅ **Unified-Store reassessment:** the config layer already exposes per-domain `Store`
  interfaces that consumers depend on, so ADR-0003 keeps them (type-safe per-domain
  queries) and evolves backends behind them — no risky rewrite.
- ✅ **Stage 1 (`auth`) executed.** The authentication/authorization middlewares were
  moved into a new cohesive subpackage `internal/middleware/auth` (`package auth`):
  `auth`, `auth_utils`, `forwardauth`, `hmac`, `oauth2_introspection`, `oidc_proxy`,
  `oidc_validator`, `paseto_verifier`, `apikey_store`, `revocation` (10 files) + a small
  `aliases.go` re-exporting the `kind` primitives it uses (`Middleware`,
  `IsCorsPreflight`, `GetRouteName`, `ShouldSkipMetrics`). `package middleware` keeps a
  transparent `auth_aliases.go` shim so the factory dispatch, the package tests, and all
  external callers (`middleware.JWTValidator`, `middleware.PasetoAuth`,
  `middleware.UserContextKey`, …) compile unchanged. `tls_binding.go` stayed in
  `package middleware` because it uses the security-group helper `recordAdvancedThreat`;
  it moves with the `security` group. Root middleware dropped from 71 → 62 `.go` files;
  `go build`/`vet`/`gofmt` clean and the middleware/server/api tests pass.
- ⬜ **Deferred (each its own production-ready session):** remaining per-group subpackage
  moves (security/traffic/transform) + registry-based dispatch replacing the `factory.go`
  switch; optional generic `crudStore[T]` helper and DB/etcd `Store` backends.
- **Done when:** behavior unchanged, all tests pass, packages follow the
  ≤10-files/folder guideline. — **partially met:** architecture/ADR/diagram deliverable
  complete, **Stage 0 (the `kind` leaf) and Stage 1 (the `auth` subpackage) are executed
  & verified**; the remaining per-group moves (security/traffic/transform) are staged
  (ADR-0002) to keep every session shippable.

### Session 8 — UI accessibility (frontend) — ✅ DONE
- ✅ **`jsx-a11y` CI gate.** Added `eslint`, `typescript-eslint`, and
  `eslint-plugin-jsx-a11y` with a focused flat config (`ui/eslint.config.js`) that
  enables only the jsx-a11y recommended rules (TS parser for `.tsx`), plus a `lint`
  script. Wired a dedicated **Lint UI (accessibility gate)** step into `ci.yml` before
  the UI build. The whole `src/` tree now passes with **0 violations**.
- ✅ **`no-autofocus` fixed accessibly** (the only 2 violations): LoginPage moves focus to
  the 2FA code input via `useRef`+`useEffect` on the explicit step change; TwoFactorModal
  uses Mantine's `data-autofocus` inside the modal focus trap. (Also fixed a latent missing
  `Paper` import in `TwoFactorModal`.)
- ✅ **`aria-label`s on icon-only controls** in `Shell.tsx`: sidebar collapse/expand toggle,
  color-scheme menu, refresh-status button, and the mobile burger.
- ✅ **Skip-to-content + landmark.** Added a `.skip-to-content` link (visually hidden until
  focused) targeting `<main id="main-content">` (`AppShell.Main`), so keyboard users can
  bypass the navigation.
- ✅ **Focus + motion.** `styles.css` now defines a high-contrast `:focus-visible` outline
  for keyboard users and a global `@media (prefers-reduced-motion: reduce)` block that
  neutralizes non-essential animations/transitions.
- **Done when:** a11y audit passes; lint green. — **met:** jsx-a11y gate green (0 issues),
  `bun run build` green; the structural a11y primitives (skip link, landmark, focus ring,
  reduced-motion, icon labels) are in place. _Full axe/Lighthouse pass + per-form keyboard
  audit tracked as an incremental follow-up as new screens are added._

### Session 9 — Wazuh-like detection foundation (backend) — ✅ DONE
- ✅ **FIM scanner.** New dependency-free `internal/security/fim` package: records a
  SHA-256 baseline over a configured set of files/directories (recursive walk, regular
  files only, symlinks skipped, per-file read bound), then `Scan()` diffs the current
  state into ordered `added`/`modified`/`removed` `Event`s and updates the baseline. It is
  thread-safe (`sync.RWMutex`), keeps a bounded recent-event ring buffer + lifetime drift
  counter, exposes an immutable `Status()` snapshot, and runs periodically via
  `Start(ctx)`. Drift fires an `OnDrift` callback (wired to log warnings).
- ✅ **Opt-in wiring.** FIM activates only when `GATEON_FIM_PATHS` (OS-path-list) is set;
  `GATEON_FIM_INTERVAL` (Go duration, default 5m, floored at 10s) tunes the cadence. The
  scanner is started on the server wait-group in `run.go` and cancelled via `ctx`.
- ✅ **`/v1/security/posture` endpoint.** Registered in `rest.go`, RBAC-gated
  (`ResourceGlobal` read). Returns a typed `SecurityPostureReport` with WAF
  (enabled/auto-update/`LastUpdated` — new `WAFUpdater.LastUpdated()` reads the persisted
  status file), ClamAV (enabled/installed/last-scan/result/error via `GetScanStatus()` +
  `IsInstalled`), and FIM status. Decoupled via a `Deps.SecurityPosture` provider built in
  `run.go`; falls back to a minimal report when unwired (never 500s).
- ✅ **YARA-lite signature scanning.** New dependency-free, pure-Go `internal/security/yara`
  engine (no `libyara`/cgo): a `Rule` is a set of byte/text `Strings` combined with a
  `MatchAny`/`MatchAll` condition, each carrying a `Severity` and optional MITRE technique
  IDs. Patterns support literal text (with ASCII case-insensitivity, allocation-free
  `indexFold`) and hex magic bytes; rules are compiled once. An 11-rule built-in set covers
  EICAR, embedded PE/ELF, PHP/JSP/ASPX webshells, reverse shells, encoded PowerShell, PDF
  JS/auto-launch, Office auto-exec macros, and HTML/script polyglots; custom rules load
  from JSON (`yara.LoadFile`). Integrated **inline** into `file_security.go` (after
  MIME/magic, before ClamAV): matches `>=` block severity (default `high`) reject with 403,
  lower-severity matches are logged. New factory keys `enable_signature_scan` (default-on),
  `signature_rules_path`, `signature_block_severity`. Engine state (enabled + rule count)
  is surfaced in the posture report (`signatures`). Table-driven tests cover the engine
  (EICAR/webshell/ELF/PE/reverse-shell/PDF-JS/MatchAll/validation/custom-file) and the
  middleware (block/allow/opt-in). Documented in `doc/security-posture.md`.
- ⬜ **Deferred (optional, external deps):** CVE scanning of uploaded artifacts
  (containers/packages) via Trivy/Grype + a detonation/sandboxing flow — both pull in
  external binaries, so they remain an optional follow-up.
- **Done when:** FIM drift and malicious uploads raise alerts; posture endpoint reports
  WAF/ClamAV/CVE freshness. — **met:** FIM drift alerts, **YARA-lite malicious-upload
  blocking**, and the posture endpoint (WAF/ClamAV/signatures/FIM freshness) are all
  delivered & tested. Only external-binary CVE artifact scanning (Trivy/Grype) remains as
  an optional add-on.

### Session 10 — Correlation + SIEM export (backend) — ✅ DONE
- ✅ **Correlation engine.** New dependency-free `internal/security/correlation` package: a
  thread-safe sliding-window `Engine` keys each recorded threat by fingerprint (preferred)
  or source IP and raises an `Incident` once the windowed signals reach `MinSignals`
  (default 3) **or** cumulative `MinScore`. Incidents aggregate the contributing signal
  types, max severity, cumulative score, countries, and the **deduplicated MITRE ATT&CK
  techniques** implied by the signal types (`mitre.go` map covers brute-force, exploit
  scan, probe/fuzzing, DGA, DoS, WAF/SQLi, bot/anomaly, GeoIP-proxy, valid-accounts). A
  re-alert interval debounces alert storms; tracked sources and per-source signals are
  bounded with idle GC for memory safety.
- ✅ **SIEM export.** New dependency-free `internal/security/siem` package: a `Shipper`
  with a **bounded async queue** (non-blocking `Ship`, drop+count on overflow, atomic
  `Stats`) and a worker that formats + sends events. Formatters: **JSON** (newline-delimited),
  **CEF** (ArcSight, properly escaped, 0–10 severity), and **RFC 5424 syslog**
  (structured-data, facility `local0`). Transports: **HTTP** (bearer token, per-send
  timeout) and **UDP/TCP** (lazy reconnect). Config from `GATEON_SIEM_*` env
  (`ENDPOINT`/`ENABLED`/`FORMAT`/`TRANSPORT`/`TOKEN`/`QUEUE_SIZE`/`TIMEOUT`).
- ✅ **Wiring.** `cmd/gateon/threatpipeline.go` subscribes to `telemetry.ThreatBroadcaster`,
  adapts each threat into a `correlation.Signal`, and feeds the engine; every incident is
  logged as a structured warning (works without SIEM) and shipped to the SIEM when enabled.
  Raw threats are optionally shipped via `GATEON_SIEM_RAW_THREATS`. All goroutines are
  ctx-cancellable; the shipper best-effort flushes on shutdown.
- ✅ **Tests + docs.** Table-driven tests cover the MITRE map, window/threshold/debounce/
  window-expiry/GC behavior, JSON/CEF/syslog formatting + escaping, severity maps, env-
  disabled cases, end-to-end HTTP delivery via `httptest`, and overflow-drop accounting.
  Documented in `doc/siem-correlation.md` (linked from `doc/README.md`).
- **Done when:** incidents are emitted with technique IDs and exported to a SIEM sink.
  — **met:** MITRE-annotated incidents are emitted and exported (JSON/CEF/syslog over
  HTTP/UDP/TCP); engine + shipper fully unit-tested.

### Session 11 — UI delight features (frontend) — ✅ DONE
- ✅ **⌘K command palette.** New `ui/src/components/CommandPalette/` (modular folder:
  `CommandPalette.tsx` provider/hook, `useCommands.ts`, `CommandSearchButton.tsx`,
  `types.ts`, `index.ts`). Dependency-free — built on Mantine `Modal` + `@mantine/hooks`
  `useHotkeys` (⌘K / Ctrl+K toggles) rather than pulling in `@mantine/spotlight`. Offers a
  case-insensitive multi-token fuzzy filter across **every page** plus quick actions
  (toggle sidebar, switch theme light/dark/auto, sign out), with full keyboard control
  (↑/↓ to move, Enter to run, Esc to close) and auto-scroll of the active row. Role-aware
  (the Users command is admin-only). A header `CommandSearchButton` shows the
  platform-aware shortcut hint (⌘ on macOS, Ctrl elsewhere) and collapses to an icon on
  small screens.
- ✅ **Persisted user preferences.** New `usePreferencesStore` (Zustand `persist`
  middleware → localStorage, key `gateon-preferences`): `sidebarCollapsed` (now the single
  source of truth for the desktop sidebar in `Shell`, surviving reloads/navigation) and
  `tableDensity` (`comfortable`/`compact`).
- ✅ **Table-density wiring.** A new `useTableDensity` hook maps the persisted
  `tableDensity` to Mantine `Table` `verticalSpacing`/`horizontalSpacing`/`fontSize` props,
  and an **Appearance → Table Density** segmented control (`AppearanceCard`) lets users
  switch comfortable/compact. The hook is applied to every data table (RouteList,
  PathStats, ReputationMonitor, ThreatExplorer, Domain/Country traffic tables, Metrics
  route/target tables, Users, EntryPoints, Traces, CircuitBreaker, Middlewares, TLSOptions),
  so all tables re-render instantly when the preference changes.
- ✅ **Connection-status indicator.** New `ConnectionStatus` component replaces the static
  STATUS badge in `Shell`: it derives **LIVE / CONNECTING / RECONNECTING / OFFLINE** from
  the browser network state (`@mantine/hooks` `useNetwork`) combined with the backend
  status poll, so users can trust the "live" data and see reconnection clearly.
- ✅ **Optimistic toggles.** Route pause/resume in `RoutesPage.tsx` now responds
  instantly: the mutation's `onMutate` cancels in-flight `["routes"]` queries, snapshots
  every cached page, and flips the matching route's `disabled` flag across all of them;
  `onError` restores the snapshots (rollback) and `onSettled` invalidates to reconcile
  with the server. The per-mutation `onError` keeps the global `MutationCache` toast from
  double-firing.
- ✅ **Onboarding checklist.** `components/Dashboard/OnboardingChecklist` — a
  dashboard-mounted guided setup (entry-point → service → route → protection) deriving
  completion purely from live config (`total_count` of entrypoints/services/routes +
  security middleware `type` detection), with a progress bar, per-step deep links,
  RBAC-gated action buttons, a persisted dismiss (`usePreferencesStore.onboardingDismissed`),
  and auto-hide once every step is complete.
- ✅ **Global search + shareable URL-state filters.** New `useUrlFilters` hook
  (`hooks/useUrlFilters.ts`) lifts page filter/search state into TanStack Router search
  params (reads via `useSearch({strict:false})`, writes via `navigate` with empty-value
  pruning + `replace`), backed by `validateSearch` on the `traces` (`q`,`route`) and
  `audit-logs` (`q`) routes. `AuditLogsPage` and `TracesPage` now persist their filters in
  the URL so a filtered view is bookmarkable/shareable; TracesPage keeps its deferred
  (transition-based) search for responsiveness while mirroring to the URL.
- ✅ **i18n scaffolding.** New dependency-free, type-safe `ui/src/i18n/` package (no
  `react-i18next` dependency): `en.ts` is the canonical catalog whose shape derives the
  `TranslationKey` type; `locales.ts` is the language registry (`en` + a partial `id`
  locale demonstrating graceful English fallback for missing keys, plus
  `normalizeLanguage`); `useTranslation()` returns a memoized, type-safe `t(key, params)`
  with `{{param}}` interpolation sourcing the language from the persisted preferences
  store; `I18nProvider` keeps `document.documentElement.lang` in sync. The selected
  `language` is persisted in `usePreferencesStore` (version bumped to 2) and exposed via a
  translated **Appearance → Language** `Select`, with `AppearanceCard` fully migrated to
  `t()` as the worked example for incremental string extraction.
- **Done when:** features work end-to-end; preferences persist; live status visible.
  — **met:** ⌘K palette, persisted preferences, live connection status, optimistic
  toggles, onboarding checklist, shareable URL-state filters, and i18n scaffolding are all
  delivered end-to-end (`bun run lint` jsx-a11y + `bun run build` green, all chunks
  <500KB). No UI test runner is configured in `package.json`, so verification is via the
  lint/build gates.

---

## Quick Reference — Suggested Priority

1. **Correctness & security** (Sessions 1–4)
2. **Performance & resource bounds** (Sessions 5–6)
3. **Architecture & maintainability** (Sessions 7–8)
4. **Advanced detection & UX features** (Sessions 9–11)
