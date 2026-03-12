# Gateon

Production-ready, modular HTTP, gRPC, and gRPC-Web reverse proxy and load balancer. This repository provides a high-performance Go backend and a modern TypeScript UI.

## Features
- API Gateway written in Go
  - Modern HTTP reverse proxy with path/host routing
  - Built-in load balancer (**Round Robin** and **Least Connections**) with active health checks per route
  - **Circuit Breaker**: Automatic failure detection and target isolation (Closed, Open, Half-Open states)
  - **WebSocket Support**: Full-duplex proxying for modern real-time applications
  - **Cloud-native Observability**:
    - **Prometheus Metrics** (requests total, latency duration) via `/metrics` endpoint.
    - **Structured JSON Access Logging** for all traffic.
    - **Live Dashboard Logs**: Real-time log streaming via WebSockets.
    - OpenTelemetry integration for distributed tracing.
  - gRPC server on the same port as HTTP
  - gRPC routing and grpc-web proxying on the same listener
  - Minimal REST endpoints for UI parity
  - Health and readiness endpoints
  - **Dynamic Routing with Hot-Reload** (Host and Path based)
  - **Configuration**: Supports JSON and YAML for route definitions.
  - **HTTP Management**: Advanced proxy configuration (custom headers, timeouts) and real-time metrics (request count, error rate, latency, active connections) per route.
  - **AuthN/Z**: JWT (HMAC/JWKS) and API Key validation per route
  - **Weighted Load Balancing**: Canary deployments and traffic splitting support.
  - **Distributed Rate Limiting**: Redis-backed rate limiting for multitenant workloads.
  - **Multitenant Rate Limiting**: Per-IP and Per-Tenant (context-aware)
  - **SSL/TLS Certificate Management**: Built-in support for uploading and managing custom certificates per domain directly from the UI.
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

## Repository Structure
```
cmd/gateon/      # Application entry point (HTTP + gRPC + gRPC-Web)
internal/        # Server logic and shared packages (server, logger, config, router, etc.)
  - server/      # API Gateway implementation
  - router/      # Routers connect incoming requests to the services that handle them.
proto/           # Protobuf definitions (generated Go under proto/gateon/v1/)
ui/              # React UI (Vite + TS + Mantine + Tailwind); built to internal/ui/dist for embed
```

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
The API gateway is wired with a gRPC server and grpc-web wrapper. While Gateon acts as a transparent proxy for your services' gRPC traffic (similar to Traefik), `protoc` is required for developing and maintaining Gateon itself because:

1.  **Management API**: Gateon's own control plane (routing, status, metrics) is defined using Protocol Buffers (`proto/gateon.proto`).
2.  **Internal Communication**: The backend uses generated Go code to handle these management requests efficiently.
3.  **Extensibility**: If you want to extend Gateon with custom gRPC services or modify the management API, you will need to re-generate the Go bindings.

### Installation and Generation

1) Install protobuf toolchain (example):
```bash
# protoc with Go plugins
# (Use your preferred package manager to install protoc)
# Go plugins:
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
```

2) Generate Go code (output goes to `proto/gateon/v1/` per `go_package`):
```bash
protoc \
  --go_out=. --go_opt=module=github.com/gateon/gateon \
  --go-grpc_out=. --go-grpc_opt=module=github.com/gateon/gateon \
  proto/gateon.proto
```
Generated files live only in `proto/gateon/v1/`; do not commit root-level `*.pb.go` in `proto/`.

3) Services are fully implemented and registered in `internal/server` and wired from `cmd/gateon`.

## Environment Variables
- `PORT`: API Gateway port (default 8080)
- `OTEL_EXPORTER_OTLP_ENDPOINT`: Endpoint for OTLP traces (e.g., http://localhost:4318). If empty, tracing is disabled.
- `GATEON_JWT_SECRET`: Shared secret for HMAC-based JWT validation.
- `GATEON_API_KEYS`: Comma-separated list of `key:tenant_id` pairs for static API key management (e.g., `key1:tenantA,key2:tenantB`).

## UI (React + Vite + Mantine + Tailwind)
The UI is automatically built and embedded into the Go binary during the build process. When Gateon is running, the dashboard is accessible on the same port as the gateway (default: `http://localhost:8080`).

### Development
Requirements:
- Node.js 18+ (or Bun)

Install and run:
```
cd ui
npm install
npm run dev
```

### Manual Build
If you need to manually build the UI:
```
cd ui
npm run build
```
The build artifacts in `ui/dist` are synced to `internal/ui/dist` for embedding (run `go run ./scripts/sync_assets.go` from repo root, or use `go run ./cmd/gateon --build-ui` to build and sync before starting).

Configure the API base URL for the UI via environment (only needed for `npm run dev`):
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
- **Redis-backed Rate Limiting** – Distributed rate limiting with Redis (see Features).
- **Automatic TLS (Let's Encrypt)** – Backend support via ACME/autocert in `internal/tls`; configurable via TLS config (Email + Domains).
- **Metrics export (Prometheus/OpenTelemetry)** – Prometheus `/metrics` and OpenTelemetry tracing (see Features).
- **Dashboard (Live logs)** – Live log streaming via WebSockets; further enhancements below.

### Next (see [.junie/Strategic UI_UX Plan for Enterprise-Grade Gateon.md](.junie/Strategic%20UI_UX%20Plan%20for%20Enterprise-Grade%20Gateon.md))
- Sidebar navigation and Shell layout (Dashboard, Routes, Certificates, Logs, Settings).
- Global health bar and service overview cards.
- Enterprise route management: search/filter, paginated table, wizard-based route creation, config preview.
- Observability: sparklines per route, log filtering, Circuit Breaker dashboard.
- Dark/light mode, lazy loading, RBAC placeholder.