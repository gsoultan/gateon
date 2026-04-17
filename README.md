# Gateon

Production-ready, modular HTTP, gRPC, and gRPC-Web reverse proxy and load balancer. This repository provides a high-performance Go backend and a modern TypeScript UI.

## Features
- API Gateway written in Go
  - Modern HTTP reverse proxy with path/host routing
  - Built-in load balancer (**Round Robin** and **Least Connections**) with active health checks per route
  - **Circuit Breaker**: Automatic failure detection and target isolation (Closed, Open, Half-Open states)
  - **WebSocket and SSE Support**: Full-duplex proxying and real-time streaming for modern applications (see [doc/websockets-sse.md](doc/websockets-sse.md))
  - **Cloud-native Observability**:
    - **Prometheus Metrics** (requests total, latency duration) via `/metrics` endpoint.
    - **Structured JSON Access Logging** for all traffic.
    - **Live Dashboard Logs**: Real-time log streaming via WebSockets.
    - OpenTelemetry integration for distributed tracing.
  - gRPC server on the same port as HTTP
  - gRPC routing; add the **grpcweb** middleware to grpc routes for browser (gRPC-Web) support
  - Minimal REST endpoints for UI parity
  - Health and readiness endpoints
  - **Dynamic Routing with Hot-Reload**: Host, Path, PathPrefix, PathRegex, Methods, Headers matchers (Traefik-compatible rules). Routes can be **paused** (disabled) without deletion.
  - **Configuration**: Supports JSON and YAML for route definitions.
  - **HTTP Management**: Advanced proxy configuration (custom headers, timeouts) and real-time metrics (request count, error rate, latency, active connections) per route.
  - **AuthN/Z**: JWT (HMAC/JWKS) and API Key validation per route
  - **Weighted Load Balancing**: Canary deployments and traffic splitting support.
  - **Distributed Rate Limiting**: Redis-backed rate limiting for multitenant workloads.
  - **Multitenant Rate Limiting**: Per-IP and Per-Tenant (context-aware)
  - **SSL/TLS Certificate Management**: Built-in support for uploading and managing custom certificates per domain directly from the UI.
- **TCP/UDP L4 Proxy**: TCP and UDP entrypoints forward traffic to backends via Route → Service (configure a Route with type tcp/udp and a Service with backend_type tcp/udp).
- **Config Import/Export**: Backup and restore via `/v1/config/export` and `/v1/config/import`. Validate before import with `POST /v1/config/validate`.
- React UI (Vite + TypeScript + Mantine + Tailwind)
  - Status dashboard and route management
- **Clean modular structure with protobuf generation**
- **Traefik-compatible HTTP Middlewares**:
  - `AddPrefix`, `StripPrefix`, `StripPrefixRegex`
  - `ReplacePath`, `ReplacePathRegex`, `Rewrite`
  - `Compress` (Gzip)
  - `Errors` (Custom error pages)
  - `Retry`
  - `Headers` (Add/Set/Del for Request and Response)
  - `IPFilter` (allow/deny by IP or CIDR; supports `trust_cloudflare_headers`)
  - `WAF` (Coraza WAF with OWASP CRS)
  - `Turnstile` (Cloudflare Turnstile bot verification)
  - `GeoIP` (allow/deny by country using MaxMind GeoLite2)
  - `HMAC` (webhook signature verification)
  - `Cache` (in-memory or Redis response cache for GET)
  - `gRPC-Web` (required for grpc routes called from browsers; converts gRPC-Web to gRPC)

## Repository Structure
```
cmd/gateon/      # Application entry point (HTTP + gRPC + gRPC-Web)
doc/             # Setup guides and documentation (e.g. doc/email-backend-setup.md)
internal/        # Server logic and shared packages (server, logger, config, router, etc.)
  - server/      # API Gateway implementation
  - router/      # Routers connect incoming requests to the services that handle them.
proto/           # Protobuf definitions (generated Go under proto/gateon/v1/)
ui/              # React UI (Vite + TS + Mantine + Tailwind); built to internal/ui/dist for embed
  docs/          # Documentation content (displayed in UI Docs page)
```

## Releases and Services

Release binaries (Linux, macOS, Windows) are built by [GoReleaser](https://goreleaser.com/) on tag push.

**Install as a service** (no separate scripts):

```bash
# Linux
sudo gateon install

# Windows (run as Administrator)
gateon install
```

Uninstall: `gateon uninstall`. See [doc/services.md](doc/services.md) for package-based install and WinSW fallback.

## Architecture Notes

- **Dedicated Management Entrypoint**: Gateon runs a separate, secure management server for the dashboard and internal API. This prevents accidental lockout when managing proxy entrypoints. See [doc/management-entrypoint.md](doc/management-entrypoint.md).
- **Dependency inversion**: The server depends on store interfaces (`RouteStore`, `ServiceStore`, etc.), not concrete registries. TLS manager and middleware factory receive interfaces via constructors.
- **Proxy caching**: HTTP proxy instances are cached per route and invalidated on route changes. See `internal/server/proxy_cache.go`.
- **Context propagation**: Domain services and config stores use `context.Context` as the first parameter for cancellation and tracing.
- **Handler style**: REST handlers follow early returns, minimal nesting, and extracted helpers (e.g. `writeJSONError`, `decodeGlobalConfig`, `validateConfigExport`). See `.cursor/rules/backend-guidelines.mdc`.

## Getting Started (Backend)
Requirements:
- Go 1.25+

Install dependencies:
```
go mod tidy
```

Build service (with UI):
```
go generate ./...
go build -o gateon ./cmd/gateon
```

Or build UI through the gateway binary (requires Go installed):
```
go run ./cmd/gateon --build-ui
go build -o gateon ./cmd/gateon
```

Run service:
```
ENV=development VERSION=dev PORT=8080 go run ./cmd/gateon
```

Test endpoints:
```
# Health
curl -s http://localhost:8080/healthz

# Status
curl -s http://localhost:8080/v1/status | jq
```

## gRPC and gRPC-Web

- **Standard gRPC**: Routes with type `grpc` proxy gRPC traffic to backends. Add the route and service; no middleware needed.
- **gRPC-Web (browser)**: Browsers cannot use raw gRPC. Add the **grpcweb** middleware to grpc routes that will be called from web apps (e.g. via `@improbable-eng/grpc-web` or `grpc-web`). The middleware converts gRPC-Web requests to standard gRPC before proxying. Without it, gRPC-Web requests to a grpc route return `415 Unsupported Media Type`.
- **Internal API**: Gateon's dashboard uses gRPC-Web to talk to its own API; that path is handled separately and does not use route middlewares.

[buf](https://buf.build) is used to generate Go code from the Protocol Buffer definitions in `proto/gateon/v1/`. Proto files are split by domain (route, service, auth, etc.); `api.proto` defines the `ApiService`.

### Installation and Generation

1) Install the toolchain:
```bash
# buf CLI — https://buf.build/docs/installation
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
```

2) Regenerate Go bindings (output goes to `proto/gateon/v1/`):
```bash
buf generate
# or via Make:
make proto
```

3) Services are fully implemented and registered in `internal/server` and wired from `cmd/gateon`.

## Environment Variables
- `PORT`: API Gateway port (default 8080)
- `OTEL_EXPORTER_OTLP_ENDPOINT`: Endpoint for OTLP traces (e.g., http://localhost:4318). If empty, tracing is disabled.
- `GATEON_JWT_SECRET`: Shared secret for HMAC-based JWT validation.
- `GATEON_API_KEYS`: Comma-separated list of `key:tenant_id` pairs for static API key management (e.g., `key1:tenantA,key2:tenantB`).
- `GATEON_ENTRYPOINT_RATE_LIMIT_QPS`: Per-IP requests per second for entrypoints. Use `0` to disable (recommended for high throughput, e.g. 100k req/s).
- `GATEON_ENTRYPOINT_RATE_LIMIT_BURST`: Burst size when rate limiting is enabled (default 2× QPS).
- `GATEON_ACCESS_LOG_SAMPLE_RATE`: Access log sampling. `1` = log all; `N` = log 1 in N requests; `0` = no access log. Use `1000`+ for high-throughput to reduce I/O.
- `GATEON_TRUST_CLOUDFLARE_HEADERS`: Set to `true`, `1`, or `yes` when Gateon is behind Cloudflare; IPFilter and ratelimit will use `CF-Connecting-IP` for client IP.
- `GATEON_TURNSTILE_SECRET`: Cloudflare Turnstile secret key (fallback when middleware config omits it).
- `GATEON_GEOIP_DB_PATH`: Path to GeoLite2-Country.mmdb for GeoIP middleware (fallback when config omits db_path).
- `GATEON_HMAC_SECRET`: HMAC secret for webhook signature verification (fallback when middleware config omits it).
- `GATEON_ENCRYPTION_KEY`: Optional. When set (min 16 chars), `database_url`, `paseto_secret`, and database password are encrypted in global.json.
- `GATEON_MANAGEMENT_BIND`: IP address for the dedicated management server (default `127.0.0.1`). Use `0.0.0.0` for remote access (e.g. via Cloudflare Tunnel on another machine).
- `GATEON_MANAGEMENT_ALLOWED_IPS`: Comma-separated list of allowed IPs for management access (default `127.0.0.1,::1`). Use `0.0.0.0/0` with caution for initial setup via tunnel.

> **Note on Cloudflare Tunnels**: If you experience a `502 Bad Gateway` when accessing Gateon via a Cloudflare Tunnel, ensure `GATEON_TRUST_CLOUDFLARE_HEADERS=true` is set and `GATEON_MANAGEMENT_ALLOWED_IPS` includes your tunnel's IP (or use `0.0.0.0/0` to troubleshoot). See [doc/management-entrypoint.md](doc/management-entrypoint.md) for details.

## UI (React + Vite + Mantine + Tailwind)
The UI is automatically built and embedded into the Go binary during the build process. When Gateon is running, the dashboard is accessible on the same port as the gateway (default: `http://localhost:8080`).

### Development
Requirements:
- [Bun](https://bun.sh)

Install and run:
```
cd ui
bun install
bun run dev
```

### Manual Build
If you need to manually build the UI:
```
cd ui
bun run build
```
The build artifacts in `ui/dist` are synced to `internal/ui/dist` for embedding (run `go run ./scripts/sync_assets.go` from repo root, or use `go run ./cmd/gateon --build-ui` to build and sync before starting).

Configure the API base URL for the UI via environment (only needed for `bun run dev`):
- Create `.env` in `ui/` with: `VITE_API_URL=http://localhost:8080`

## Comparison with Other Gateways

Gateon is designed as a **modern, lightweight reverse proxy and load balancer**, comparable to Traefik, Nginx, or Apache APISIX, but with a focus on ease of use and native gRPC/grpc-web support.

| Feature | Gateon | Traefik | NGINX | Apache APISIX |
| :--- | :--- | :--- | :--- | :--- |
| **Language** | Go | Go | C | Lua (on OpenResty) |
| **gRPC/gRPC-Web** | **Native** (First-class) | Native | Via Module/Config | Native |
| **Hot Reload** | Native (Dynamic Routes) | Native | Requires Reload | Native (via etcd) |
| **Observability** | **Prometheus + JSON Logs** | Prometheus + Logs | Basic / Commercial | Prometheus + Plugins |
| **Load Balancing** | **RR + LeastConn + WRR** | RR + Wrr + ... | RR + LC + IP Hash | RR + LC + ... |
| **Config Style** | Code-first / JSON / YAML | Dynamic / Labels | Static Files | Dashboard / API |
| **Dashboard** | Included (React + Live Logs) | Included | Commercial (Plus) | Included |
| **Extensibility** | Go Middlewares | Go Middlewares/WASM | C Modules / Lua | Lua Plugins |

### When to choose Gateon?
- **gRPC-First Workloads**: If your services are primarily gRPC and you need seamless grpc-web proxying without complex envoy configurations.
- **Go-Centric Teams**: If you want to extend your gateway using the same language and patterns as your backend services.
- **Need for a Simple Management UI**: When you need a built-in dashboard to monitor and manage your gateway traffic.

## Roadmap

### Implemented
- [WAF (Web Application Firewall)](doc/waf.md) – OWASP CRS protection.
- [WASM Middleware](doc/wasm.md) – Extensible WASM-based traffic manipulation.
- [Redis-backed Rate Limiting](doc/rate-limiting.md) – Distributed rate limiting with Redis (see Features).
- **Comprehensive Auth** – JWT, JWKS, PASETO, Forward Auth, and API Keys.
- **Security Integrations** – Cloudflare Turnstile, MaxMind GeoIP, HMAC Signatures.
- **Traffic Management** – Caching (Redis/Local/Cluster), Compression (Gzip/Brotli), Resilience (Retry, Circuit Breaker).
- **High Availability (HA)** – Active-Passive failover (VRRP-like) with VIP management.
- **Anomaly Detection** – AI-powered traffic pattern analysis via Prometheus.
- **eBPF Offloading** – Kernel-level XDP rate limiting and TC filtering.
- **Canary Deployment Wizard** – Automated gradual traffic shifting for services.
- **FIPS 140-2 Compliance** – BoringCrypto support for regulated environments.
- **Kubernetes Gateway API Controller** – Native support for `Gateway` and `HTTPRoute` resources.
- **Mutual TLS (mTLS)** – End-to-end security with client certificates for backend targets.
- **Config Sync & Discovery** – Multi-cluster synchronization (Redis) and mDNS/Eureka/Zookeeper support.
- **External Secrets Management** – Resolution of `$vault:`, `$env:`, and `$aws-sm:` variables at runtime.
- **Observability & AI** – Topology map, AI-powered log assistant, and `gateon top` CLI TUI.
- **AI Optimization** – Best practices for guidelines, scenarios, and plans for AI agents ([docs/ai-optimization.md](docs/ai-optimization.md)).
- **Backend Transport Rollout Guide** – Operations guide for protocol-aware targets, health-check modes, PROXY protocol, dynamic backend mTLS, migration, canary, and rollback ([docs/backend-transport-rollout.md](docs/backend-transport-rollout.md)).
- **Automatic TLS (Let's Encrypt)** – Backend support via ACME/autocert in `internal/tls`; configurable via TLS config (Email + Domains).
- **Metrics export (Prometheus/OpenTelemetry)** – Prometheus `/metrics` and OpenTelemetry tracing (see Features).
- **Dashboard (Live logs)** – Live log streaming via WebSockets.

### Next (Enterprise & Scalability)
- **Active-Active HA**: Gossip-based state synchronization for distributed clusters.
- **Service Mesh Integration**: Istio/Linkerd sidecar support.
- **Advanced WAF Rule Builder**: Visual UI for creating custom Coraza rules.
- **Global Load Balancing (GSLB)**: DNS-based traffic steering across geographical regions.