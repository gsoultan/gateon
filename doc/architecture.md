# Gateon Architecture & Dependency Diagram

This document complements the [ADRs](./adr/README.md) with a visual overview of
Gateon's layered architecture, the request path, and the **target** grouping of the
`internal/middleware` package (see [ADR-0002](./adr/0002-middleware-package-refactor.md)).

## Layered execution flow

Per [ADR-0001](./adr/0001-layered-architecture.md), a request flows top-to-bottom and
dependencies point downward only (no layer depends on a layer above it).

```mermaid
flowchart TD
    T["Transports<br/><small>internal/server (HTTP / gRPC / SSE / WS / L4)</small>"]
    M["Middlewares<br/><small>internal/middleware</small>"]
    E["Endpoints<br/><small>request/response seam</small>"]
    S["Services / Facade<br/><small>internal/domain/&lt;domain&gt;</small>"]
    U["Usecases<br/><small>atomic business ops</small>"]
    R["Repositories / Stores<br/><small>internal/config, internal/telemetry</small>"]

    T --> M --> E --> S --> U --> R

    R -. interfaces .-> S
```

## Configuration store interfaces

Per [ADR-0003](./adr/0003-config-store-interfaces.md), domain services depend on
per-domain `Store` interfaces, not on concrete backends.

```mermaid
flowchart LR
    subgraph domain["internal/domain"]
        RS["route.Service"]
        SS["service.Service"]
        MS["middleware.Service"]
    end

    subgraph ifaces["internal/config (interfaces)"]
        RStore["RouteStore"]
        SStore["ServiceStore"]
        MStore["MiddlewareStore"]
    end

    subgraph impl["concrete backends"]
        FReg["File registries<br/>(routes.json, …) — default"]
        DB["DB / etcd backends<br/>(planned)"]
    end

    RS --> RStore
    SS --> SStore
    MS --> MStore

    FReg -. implements .-> RStore
    FReg -. implements .-> SStore
    FReg -. implements .-> MStore
    DB -. implements .-> RStore
    DB -. implements .-> SStore
    DB -. implements .-> MStore
```

## Target `internal/middleware` package layout

The package is being split in safe stages (ADR-0002). The **target** dependency graph
is acyclic: subpackages depend only on the `kind` leaf, and the root `middleware`
package depends on the subpackages (registry/dispatch), never the reverse.

```mermaid
flowchart TD
    Kind["middleware/kind<br/><small>Middleware type, Chain, Recovery,<br/>context keys, status_writer, errors</small>"]

    Auth["middleware/auth<br/><small>auth, forwardauth, hmac, oauth2,<br/>oidc, paseto, apikey, revocation, tls_binding</small>"]
    Sec["middleware/security<br/><small>waf, graphql_firewall, schema/openapi,<br/>file_security, bot, deception, honeypot,<br/>pow, turnstile, tls_fingerprint, geoip, ipfilter, policy</small>"]
    Traf["middleware/traffic<br/><small>ratelimit, connlimit, maxbody, inflight,<br/>retry, cache, buffering, compress</small>"]
    Trans["middleware/transform<br/><small>headers, rewrite, transform, cors,<br/>prefix, grpcweb, wasm, xfcc</small>"]

    Root["middleware (root)<br/><small>factory.go / registry — dispatch only</small>"]

    Auth --> Kind
    Sec --> Kind
    Traf --> Kind
    Trans --> Kind

    Root --> Auth
    Root --> Sec
    Root --> Traf
    Root --> Trans
    Root --> Kind
```

### Why the staged approach

A flat-to-nested move fails to compile because the current `Middleware` type lives in
`package middleware` while `factory.go` (also in `package middleware`) would import any
new subpackage — an `import cycle`. Stage 0 extracts the cycle-free core into the
`kind` leaf package (with temporary type aliases for backward compatibility), after
which each cohesive group can be moved and verified (`go build ./... && go test -race
./...`) one shippable step at a time.

## Related documents

- [ADR-0001 — Layered architecture](./adr/0001-layered-architecture.md)
- [ADR-0002 — Middleware package refactor](./adr/0002-middleware-package-refactor.md)
- [ADR-0003 — Config store interfaces](./adr/0003-config-store-interfaces.md)
- [recommendations.md](./recommendations.md) — execution roadmap (Session 7).
