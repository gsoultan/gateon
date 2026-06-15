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
| [storage-retention.md](./storage-retention.md) | Persistent stores, retention/disk-reclamation behavior, and tunable cache-size/disk-usage settings |
| [security-posture.md](./security-posture.md) | File Integrity Monitoring (FIM) configuration and the `GET /v1/security/posture` endpoint (WAF/ClamAV/FIM freshness) |
| [siem-correlation.md](./siem-correlation.md) | Threat correlation engine (MITRE ATT&CK-annotated incidents) and SIEM export (JSON/CEF/syslog over HTTP/UDP/TCP) via `GATEON_SIEM_*` |
| [architecture.md](./architecture.md) | Layered architecture overview, request-path and dependency diagrams (Mermaid), and the target `internal/middleware` package layout |
| [adr/README.md](./adr/README.md) | Architecture Decision Records (ADRs): layered architecture, middleware package refactor, config store interfaces |
| [recommendations.md](./recommendations.md) | Consolidated backend/UI improvement recommendations and a session-based, production-ready execution roadmap |
