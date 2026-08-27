# Gateon

A modern, high-performance, and security-focused API Gateway, Reverse Proxy, and Service Mesh entry point. 

Gateon is designed for cloud-native environments, offering native gRPC/gRPC-Web support, kernel-level packet filtering via eBPF (see the caveats below), and a sophisticated security suite including a semantic, multi-tier WAF and AI-powered anomaly detection.

## 🚀 Core Features

### 🌐 High-Performance Traffic Management
- **Multiprotocol Proxy**: Native support for **HTTP/1.1, HTTP/2, gRPC, and gRPC-Web** on a single port.
- **Real-time Streaming**: Full-duplex **WebSocket and SSE** proxying (see [doc/websockets-sse.md](doc/websockets-sse.md)).
- **Layer 4 Proxy**: TCP and UDP entrypoints for low-level traffic forwarding.
- **Dynamic Routing**: Traefik-compatible rules (Host, Path, Regex, Headers, Methods) with **Hot-Reload**.
- **Advanced Load Balancing**: Round Robin, Least Connections, and Weighted Round Robin (WRR) for canary deployments.
- **Resilience**: Built-in **Circuit Breakers** (Closed/Open/Half-Open) and automatic retries.

### 🛡️ Enterprise-Grade Security & Shielding
- **Advanced WAF**: Built-in **[gwaf](https://github.com/gsoultan/gwaf)**, an embeddable Go WAF that parses request *intent* rather than matching signatures — semantic detectors for SQLi, XSS, shell, path, template, NoSQL and PHP injection, plus prompt injection. OWASP CRS rules import through its SecLang adapter. Blocks by default with no tuning phase, and every decision carries a rule ID and the matched byte span.
- **Data Loss Prevention**: Response- and request-phase inspection for card numbers (issuer range + Luhn, not a regex guess), cloud and SaaS credentials, private keys, database URIs with embedded passwords, and stack traces or database errors leaking from the origin. Choose **block, redact or audit** per route, so a programme can start by watching and tighten later. Outbound and inbound are separate rule sets on purpose — a card number in a response is a leak, the same number in a request is a customer paying for something. See [ADR 0008](doc/adr/0008-response-inspection-must-control-its-own-encoding.md).
- **Kernel Offloading**: eBPF rate limiting, IP shunning and packet filtering, at the earliest hook the NIC actually supports.
  **Native XDP runs in the driver before the packet ever becomes an `skb`** — but most virtualized NICs cannot offer it.
  The AWS ENA driver, for one, refuses a native attach above a page-sized MTU (the EC2 VPC default is 9001) and unless
  the driver is using at most half its queues. Where native XDP is unavailable, Gateon attaches at the **TC (clsact)
  ingress** hook instead, which runs after `skb` allocation and so drops no earlier than a firewall rule, but carries
  none of generic XDP's per-packet cost. **Generic/SKB XDP is refused by default** (`ebpf.allow_generic_xdp`): it drops
  no earlier than TC while charging every packet the full program cost plus a possible re-allocation and copy, which
  makes it slower than running no eBPF at all. See
  [ADR 0007](doc/adr/0007-xdp-attach-mode-and-the-tc-ingress-hook.md).
- **Bot Management**: JS Challenges, Browser Integrity checks, and Cloudflare Turnstile integration.
- **Identity & Access**: Comprehensive AuthN/Z via **JWT (HMAC/JWKS), PASETO, API Keys**, and Forward Auth.
- **Traffic Deception**: Honeypots and deception layers to trap and identify malicious actors.
- **Advanced TLS**: Automatic TLS (Let's Encrypt), **mTLS** for backends, and **JA3/JA4 Fingerprinting**.

### 📊 Cloud-Native Observability & AI
- **AI Anomaly Detection**: Proactive threat detection using traffic pattern analysis and Prometheus metrics.
- **Deep Visibility**: Prometheus metrics, OpenTelemetry tracing, and structured JSON access logs.
- **Live Diagnostics**: Real-time log streaming and a built-in **Topology Map** of your services.
- **Management TUI**: A terminal-based dashboard (`gateon top`) for real-time monitoring.

### ⚙️ Automation & Scalability
- **Kubernetes Native**: Full support for the **Kubernetes Gateway API** (`Gateway`, `HTTPRoute`).
- **High Availability**: Active-Passive failover (VRRP) and multi-cluster configuration sync via Redis.
- **Secrets Management**: Securely resolve secrets from **HashiCorp Vault, AWS Secrets Manager**, and environment variables at runtime.
- **WASM Extensibility**: Custom traffic manipulation using WebAssembly-based middlewares.

## Repository Structure

Gateon follows a domain-based organization within the `internal/` directory, adhering to a layered architecture: **Transports → Middlewares → Endpoints → Services → Usecases → Repositories**.

```text
cmd/gateon/      # Application entry point (HTTP + gRPC + gRPC-Web)
doc/             # Setup guides and documentation
internal/        # Domain-driven internal packages
  - ebpf/        # Kernel-level traffic offloading
  - ha/          # High Availability (VRRP)
  - k8s/         # Kubernetes Gateway API Controller
  - middleware/  # Security and traffic manipulation layers
  - security/    # WAF (gwaf) engine, reputation, mitigation, SIEM, FIM
proto/           # Protobuf definitions (managed via Buf)
ui/              # React UI (Vite 8 + TS + Mantine 9 + Tailwind)
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

## Getting Started

### Prerequisites
- **Go 1.26+** (Typically at `/opt/homebrew/bin/go` on macOS)
- **Bun** (for UI builds)
- **Buf** (for gRPC generation)
- **rtk** (CLI proxy for token optimization - optional)

### Development Setup

1. **Install dependencies**:
   ```bash
   rtk go mod tidy
   ```

2. **Generate gRPC code**:
   ```bash
   make proto
   ```

3. **Build & Run (with UI)**:
   ```bash
   # Build UI and Sync assets
   rtk go run ./cmd/gateon --build-ui
   
   # Build the binary
   rtk go build -o gateon ./cmd/gateon
   
   # Run in development mode
   ENV=development VERSION=dev PORT=8080 ./gateon
   ```

4. **Verify Health**:
   ```bash
   curl -s http://localhost:8080/healthz
   ```

## 🧠 AI-Ready Development

Gateon is built with AI-assisted development in mind. We provide several tools to optimize your workflow when working with LLMs and agents:

- **Graphify**: Architecture exploration and GraphRAG-based codebase navigation.
- **Serena**: Persistent memory for cross-session context and architectural decisions.
- **rtk**: A CLI proxy that optimizes token usage for shell commands (go, git, test, etc.).
- **Junie Guidelines**: Formalized standards for Clean Code and OOP in Go.

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
- `GATEON_WAF_DLP_ACTION`: What to do when a data-leak rule fires — `block` (default), `redact` (remove the finding, forward the rest) or `audit` (record it, forward untouched). Applies to data-leak rules only; an injection is still refused. Any unrecognised value means `block`. Overridden per route by the `dlp_action` middleware key, and globally by `waf.dlp_action` in the config file.
- `GATEON_TRACE_DIR`: Directory for the Pebble request-trace store. Defaults to `telemetry_pebble` next to a file-backed SQLite database, or relative to the working directory for Postgres/MySQL. Set this to place traces on a dedicated volume without changing the database URL.

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
| **eBPF Offloading** | **XDP (native, where the NIC allows) + TC** | No | No (via module) | Via Plugin |
| **AI Diagnostics** | **Native (Anomaly)** | No | No | No |
| **Observability** | **Prometheus + OpenTelemetry** | Prometheus + Logs | Basic / Commercial | Prometheus + Plugins |
| **Load Balancing** | **RR + LeastConn + WRR** | RR + Wrr + ... | RR + LC + IP Hash | RR + LC + ... |
| **Config Style** | Code-first / JSON / YAML | Dynamic / Labels | Static Files | Dashboard / API |
| **Dashboard** | Included (React + Live Logs) | Included | Commercial (Plus) | Included |
| **Extensibility** | Go / WASM | Go / WASM | C / Lua | Lua |

### When to choose Gateon?
- **gRPC-First Workloads**: If your services are primarily gRPC and you need seamless grpc-web proxying without complex envoy configurations.
- **Go-Centric Teams**: If you want to extend your gateway using the same language and patterns as your backend services.
- **Need for a Simple Management UI**: When you need a built-in dashboard to monitor and manage your gateway traffic.

## Roadmap

Gateon is rapidly evolving. Below are our recent milestones and future plans.

### Recently Added
- **eBPF Offloading**: Kernel-level XDP/TC traffic filtering.
- **AI Anomaly Detection**: Pattern-based threat identification.
- **Kubernetes Gateway API**: Native K8s resource support.
- **Advanced WAF**: replaced Coraza with **gwaf** (see [ADR 0004](doc/adr/0004-waf-engine-replacement.md)) — CGO-free, allocation-free on benign traffic, and measured against Coraza + CRS 4.25 on real CVE traffic rather than claimed.
- **Data Loss Prevention that actually runs** (see [ADR 0008](doc/adr/0008-response-inspection-must-control-its-own-encoding.md)): response inspection now negotiates a content encoding it can read, because a gzipped response had been reducing every data-leak rule to a no-op. 29 outbound and 19 inbound detectors, block/redact/audit, and a coverage metric so a body nobody could read is never reported as clean.
- **External Secrets**: Vault and AWS Secrets Manager integration.
- **High Availability**: VRRP-based active-passive failover.

### Next (Enterprise & Scalability)
- **Active-Active HA**: Gossip-based state synchronization for distributed clusters.
- **Service Mesh Integration**: Istio/Linkerd sidecar support.
- **Advanced WAF Rule Builder**: Visual UI for creating custom rules.
- **Global Load Balancing (GSLB)**: DNS-based traffic steering across geographical regions.
- **Native WASM SDK**: Simplified development for custom Go/Rust middlewares.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the setup steps, the checks to run
before opening a pull request, and the review bar. Security issues go through
[`SECURITY.md`](SECURITY.md), never a public issue.

## License

Gateon is released under the **[MIT License](LICENSE)**. Every source file
carries the SPDX marker:

```
SPDX-License-Identifier: MIT
```

Contributions are accepted under the same license; there is no CLA. Gateon's
third-party dependencies keep their own licenses — a CycloneDX SBOM is attached
to every release archive.

Copyright (c) 2026 Gembit Soultan Shirazi.