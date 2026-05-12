# Security

## Setup Flow and Secrets

- **Run setup in a controlled environment.** The `/v1/setup` endpoint initializes auth and creates the admin user. By default, management endpoints (`/v1/*`, `/metrics`, and dashboard UI) are ONLY accessible via the dedicated **management entrypoint** (default port `9090` on `127.0.0.1`).
- **Restrict public access.** Management access is blocked on standard entrypoints (port 80/443) unless explicitly allowed:
    - Set `allow_public_management: true` in `GlobalConfig` or `GATEON_ALLOW_PUBLIC_MANAGEMENT=true` to allow all public traffic (risky).
    - Add specific domains to `allowed_hosts` in `ManagementConfig` to allow access only via those hostnames (e.g., `admin.example.com`).
- **Default Paseto secret.** A default random secret is generated during the first run if not provided. This secret is used only to detect "setup required". Never use it as an actual key in production; always run setup and set a strong, unique Paseto secret.
- **Secret strength.** Use a Paseto secret of at least 32 cryptographically random bytes. Avoid weak or predictable values.
- **`GATEON_ENCRYPTION_KEY`.** When set (min 16 chars), `database_url`, `paseto_secret`, and database password are encrypted in `global.json`. Use this for production deployments.

## Dependency Updates

Gateon uses security-sensitive dependencies including Coraza WAF, OWASP CRS, and authentication libraries. **Update them regularly** to address CVEs and zero-day fixes.

### Security-Critical Dependencies

| Package | Purpose | Update Command |
|---------|---------|----------------|
| `github.com/corazawaf/coraza/v3` | Web Application Firewall | `go get -u github.com/corazawaf/coraza/v3` |
| `github.com/corazawaf/coraza-coreruleset` | OWASP Core Rule Set | `go get -u github.com/corazawaf/coraza-coreruleset` |
| `github.com/golang-jwt/jwt/v5` | JWT handling | `go get -u github.com/golang-jwt/jwt/v5` |
| `github.com/o1egl/paseto/v2` | Paseto auth | `go get -u github.com/o1egl/paseto/v2` |
| `golang.org/x/crypto` | Crypto primitives | `go get -u golang.org/x/crypto` |
| `golang.org/x/net` | HTTP/2, HTTP/3 | `go get -u golang.org/x/net` |

### Recommended Update Flow

1. **Weekly or after CVE disclosure:**
   ```bash
   go get -u ./...
   go mod tidy
   go build ./...
   go test ./...
   ```

2. **Check for known vulnerabilities:**
   ```bash
   go install golang.org/x/vuln/cmd/govulncheck@latest
   govulncheck ./...
   ```

3. **Pin to fixed versions** after verifying compatibility.

## IPS/IDS and Production Readiness

Gateon includes a high-performance IPS/IDS system based on Coraza WAF and OWASP CRS. To ensure production readiness:

- **Enable Prevention Mode.** Set `audit_only: false` in WAF configuration to block detected threats.
- **Configure Body Limits.** Use `request_body_limit` and `response_body_limit` to prevent DoS attacks via large payloads.
- **Enable Audit Logs.** Set `audit_log_path` to a dedicated log file for detailed forensic analysis of security matches.
- **XDP/eBPF Shunning.** For high-traffic environments, ensure `EbpfConfig` is enabled. WAF will automatically shun IPs that trigger critical security rules at the kernel level (XDP), significantly reducing CPU overhead during attacks.
- **Bot Management.** Enable JS challenges and browser integrity checks for public-facing routes to mitigate automated scraping and credential stuffing.
- **Monitoring.** Monitor `gateon_middleware_waf_matches_total` and `gateon_middleware_bot_management_total` metrics for real-time visibility into security events.
