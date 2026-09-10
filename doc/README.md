# Gateon Documentation

Setup guides and configuration references.

## Available Guides

| Document | Description |
|----------|-------------|
| [management-entrypoint.md](./management-entrypoint.md) | Dedicated secure management server configuration (dashboard and internal API) |
| [services.md](./services.md) | Running Gateon as a system service (Linux and Windows) |
| [email-backend-setup.md](./email-backend-setup.md) | Configure Gateon to proxy email servers (SMTP, IMAP, POP3) with SPF and DKIM support via PROXY protocol |
| [proxy-protocol.md](./proxy-protocol.md) | Full guide to PROXY protocol concepts, v1/v2 differences, configuration, security, and troubleshooting |
| [websockets-sse.md](./websockets-sse.md) | Native support for WebSockets and Server-Sent Events (SSE) |
| [waf-rollout.md](./waf-rollout.md) | Turning the WAF on without breaking your application: audit-only first, what to measure, when to enforce, how to roll back |
| [deployment-sizing.md](./deployment-sizing.md) | What the 2 core / 2 GB target was measured to mean, how to re-measure it, and the runtime budget knobs |
| [storage-retention.md](./storage-retention.md) | Persistent stores, retention/disk-reclamation behavior, and tunable cache-size/disk-usage settings |
| [backup-restore.md](./backup-restore.md) | What to back up and in what order, why `GATEON_ENCRYPTION_KEY` is the item no file-based backup contains, and how to prove a restore works |
| [security-posture.md](./security-posture.md) | File Integrity Monitoring (FIM) configuration and the `GET /v1/security/posture` endpoint (WAF/ClamAV/FIM freshness) |
| [waf-origins.md](./waf-origins.md) | Declaring `waf.origins` so off-origin redirect and SSRF detection stay active — and why a path-routed gateway derives none |
| [siem-correlation.md](./siem-correlation.md) | Threat correlation engine (MITRE ATT&CK-annotated incidents) and SIEM export (JSON/CEF/syslog over HTTP/UDP/TCP) via `GATEON_SIEM_*` |
| [architecture.md](./architecture.md) | Layered architecture overview, request-path and dependency diagrams (Mermaid), and the target `internal/middleware` package layout |
| [adr/README.md](./adr/README.md) | Architecture Decision Records (ADRs): layered architecture, middleware package refactor, config store interfaces |
| [recommendations.md](./recommendations.md) | Consolidated backend/UI improvement recommendations and a session-based, production-ready execution roadmap |
