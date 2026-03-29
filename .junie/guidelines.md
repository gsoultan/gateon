### Junie Guidelines - Gateon Project

#### Core Principles
- **KISS & DRY**: Favor simple, readable solutions over cleverness; consolidate duplicated logic.
- **Organization**:
    - **Domain-Driven**: Group packages, files, and Protobuf definitions by business/feature domain, not by technical type.
    - **Modular Proto**: Separate `.proto` files by domain (one per feature); avoid monolithic proto files; use imports to share messages.
    - **Proto Best Practices**:
        - **Organization**: Versioned packages (e.g. `package gateon.v1;`), directory structure matches package.
        - **Naming**: `PascalCase` for Messages and Services; `snake_case` for fields; `SCREAMING_SNAKE_CASE` for Enum values (prefixed with Enum name).
        - **Backward Compatibility**: Never reuse field tags; use `reserved` for deleted tags/names.
        - **Types**: Use `google.protobuf.Timestamp` and `google.protobuf.Duration` for time and duration.
        - **Documentation**: Use Go-style comments on all exported messages, fields, and services.
    - **Single Responsibility**: One main interface or struct per file; extract complex logic into small, well-named functions.
    - **SQL & Queries**: Put SQL, GraphQL, or other query strings as constants/vars in a dedicated file (e.g. `queries.go`, `queries.sql`) within the domain.
    - **Workflow**: Small, logical, production-ready commits. No partial or experimental features.
- **Lean Design**: Avoid unnecessary abstractions/layers; remove dead code. Keep files under 500 lines.
- **Clean Code**:
    - **Early Returns**: Use guard clauses to handle errors/edge cases first (avoid deep nesting).
    - **Low Complexity**: Keep functions small and focused; refactor complex branches into named helpers.
    - **Explicit Naming**: Use intention-revealing names and named constants (no magic values).
      **OOP & Patterns**: Prefer composition to inheritance. Use small interfaces (1-3 methods) defined in consumer packages.
  - **Composition over God Structs**: Embed specialized smaller structs into a main struct to maintain a unified API while delegating logic to manageable units.
  - **Consumer-Centric Interfaces**: Define interfaces that serve the consumer's needs rather than the implementation, enhancing modularity and testability.
  - **Patterns & Implementation**:
    - **Repository**: `RouteStore`, `ServiceStore`, etc. (internal/config/interfaces.go).
    - **Factory**: Middleware creation (`middleware/factory.go`), Load Balancers (`pkg/proxy/lb_factory.go`).
    - **Strategy**: LB policies, Entrypoint runners (`httpRunner`, `tcpRunner`).
    - **Decorator/Chain**: Middleware wrapping handlers, `StatusResponseWriter`.
    - **Observer**: `ProxyInvalidator` for cache invalidation on config change.
    - **Visitor**: `ConfigVisitor` for validation/export without coupling.
    - **Options**: `NewServer(opts...Option)` for stepwise configuration.

- **Go & Backend**: Use SOLID principles and programming by interface. Prefer composition over inheritance. Implement standard patterns (Repository, Factory, Strategy, Options, Decorator, Adapter, Proxy, Observer).
- **Go 1.26**: Use all modern Go idioms (iterators, slices/maps helpers, new(val), omitzero, etc.) as specified in system instructions.
- **Robustness**: Explicitly handle all errors; wrap with context (`%w`). Stop timers/tickers and close resources with `defer`. Prevent goroutine leaks using `context` and `sync.WaitGroup`.
- **Performance**:
    - **Zero Allocation**: Avoid `any` in hot paths; pre-allocate slices/maps (`make` with capacity).
    - **Reuse**: Use `sync.Pool` for heavy structs/buffers; `strings.Builder` for concatenation in loops.
    - **Optimization**: Use `go test -bench`, `go build -gcflags="-m"` (escape analysis), and `pprof`.
- **Testing & Docs**: Run `gofmt`/`goimports`. Write table-driven unit tests using `testing` package. Use `t.Context()` for context and `b.Loop()` in benchmarks. Use standard Go doc comments for all exported symbols.
- **Naming**:
    - **Go**: `snake_case` files, `lowercase` packages, `PascalCase` exported symbols, `camelCase` unexported, `er` suffix for interfaces.
    - **General**: Use intention-revealing names and named constants (no magic values).
- **Security**: Use parameterized SQL; sanitize external inputs; use least-privilege credentials and TLS.

#### Production-Ready Roadmap (Active Development)
- **Advanced Middleware Engine**: Production-ready suite including WASM, WAF (OWASP CRS), Distributed Rate Limiting, and Comprehensive Auth (JWT/JWKS/PASETO/ForwardAuth).
- **Automated TLS Lifecycle (ACME)**: Automatic certificate provisioning and renewal using `autocert` with dynamic route domain discovery and persistent cache (SQLite/Redis).
- **Security & Privacy Shield**: Native integration for Cloudflare Turnstile, MaxMind GeoIP, and HMAC webhook verification.
- **Traffic & Performance Suite**: Distributed caching, Brotli/Gzip compression, and advanced resilience (Retry, Circuit Breaker).
- **Secrets Management Integration**: Resolve sensitive configuration values via `$vault:`, `$env:`, or other providers at runtime to avoid plaintext storage.
- **Dynamic Service Discovery**: Auto-detect backend targets via DNS-SRV, Consul, or Etcd to enable zero-configuration scaling.
- **Kubernetes Ingress & Gateway API Controller**: Native K8s integration to manage Gateon via standard `Ingress` and `Gateway` resources.
- **"Command Center" Observability (Phase 2 UI)**: Real-time global health metrics, circuit breaker dashboards, and enhanced log filtering for actionable insights.

#### UI & Frontend
- **Optimization (Critical)**:
    - **Lazy Loading**: Default to `React.lazy`/`Suspense` for routes and heavy components.
    - **Waterfalls**: Parallelize independent operations (`Promise.all()`); defer `await` to point of use.
    - **Bundle Size**: Use dynamic imports and Vite manual chunks; monitor `bun run build` and size warnings.
    - **Re-render**: Use derived state during render (no `useEffect` sync); defer state reads to event handlers; extract non-primitive defaults to constants outside components.
- **React Patterns**:
    - **State**: Use local state first; `Zustand` for global; `react-query` for server state/caching.
    - **Hooks**: Maintain strict dependency arrays; use `useTransition` for non-urgent updates.
    - **Components**: Small, pure function components; accept minimal, explicit props.
    - **Forms & Routing**: TanStack Form for complex forms; TanStack Router for routing (co-locate logic).
- **Standards**:
    - **DX**: TypeScript (strict, type-only imports), Mantine + Tailwind styling, semantic HTML (a11y).
    - **Naming**: PascalCase for components/types/interfaces, `use` prefix for hooks, `on`/`handle` for event handlers.
    - **Organization**: Colocate domain logic (components, hooks, types) in feature folders; one component/hook per file.
    - **Resilience**: Wrap critical trees in Error Boundaries; test behavior with MSW and `@testing-library/react`.
    - **Security**: Sanitize untrusted HTML; escape user input; keep secrets server-side.
- **Common Pitfalls**: Never mutate state/props directly; avoid `useEffect` for synchronous derivations; virtualize long lists; use stable `key` props (not indices).
