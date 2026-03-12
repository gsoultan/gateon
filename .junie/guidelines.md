### Junie Guidelines - Gateon Project

#### Core Principles
- **KISS & DRY**: Favor simple, readable solutions over cleverness; consolidate duplicated logic.
- **Consistency**: Follow existing patterns, naming conventions, and project structure.
- **Workflow**: Small, logical, production-ready commits. No partial or experimental features.
- **Lean Design**: Avoid unnecessary abstractions/layers; remove dead code. Keep files under 500 lines.
- **Clean Code**:
    - **Early Returns**: Use guard clauses to handle errors/edge cases first (avoid deep nesting).
    - **Low Complexity**: Keep functions small and focused; refactor complex branches into named helpers.
    - **Explicit Naming**: Use intention-revealing names and named constants (no magic values).
      **OOP & Patterns**: Prefer composition to inheritance. Use small interfaces (1-3 methods).
  - **Composition over God Structs**: Embed specialized smaller structs into a main struct to maintain a unified API while delegating logic to manageable units.
  - **Consumer-Centric Interfaces**: Define interfaces that serve the consumer's needs rather than the implementation, enhancing modularity and testability.
  - Implement standard patterns (Strategy, Factory, Observer, Singleton, Builder, Decorator, Adapter, Proxy, Facade, Chain of Responsibility, Mediator, State, Command, Interpreter, Iterator, Memento, Visitor, Null Object, Template Method).

#### Go & Backend (Go 1.26)
- **Modern Idioms**: Use `new(val)`, `for i := range n`, `strings.SplitSeq`, iterators (`maps.Keys/Values`, `slices.Collect/Sorted`), `slices` package helpers, `errors.Is/AsType/Join`, `wg.Go(fn)`, and `omitzero` JSON tags.
- **Design**: Follow SOLID; prefer composition over inheritance; return interfaces where appropriate; define small interfaces (1-3 methods) close to consumers. Use unexported fields with getters/setters.
- **Robustness**: Explicitly handle all errors; wrap with context (`%w`). Stop timers/tickers and close resources with `defer`. Prevent goroutine leaks using `context` and `sync.WaitGroup`.
- **Performance**:
    - **Zero Allocation**: Avoid `any` in hot paths; pre-allocate slices/maps (`make` with capacity).
    - **Reuse**: Use `sync.Pool` for heavy structs/buffers; `strings.Builder` for concatenation in loops.
    - **Optimization**: Use `go test -bench`, `go build -gcflags="-m"` (escape analysis), and `pprof`.
- **Testing & Docs**: Run `gofmt`/`goimports`. Write table-driven unit tests using `testing` package. Use `t.Context()` for context and `b.Loop()` in benchmarks. Use standard Go doc comments for all exported symbols.
- **Security**: Use parameterized SQL; sanitize external inputs; use least-privilege credentials and TLS.

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
    - **Resilience**: Wrap critical trees in Error Boundaries; test behavior with MSW and `@testing-library/react`.
    - **Security**: Sanitize untrusted HTML; escape user input; keep secrets server-side.
- **Common Pitfalls**: Never mutate state/props directly; avoid `useEffect` for synchronous derivations; virtualize long lists; use stable `key` props (not indices).
