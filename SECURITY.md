# Security

## Setup Flow and Secrets

- **Run setup in a controlled environment.** The `/v1/setup` endpoint initializes auth and creates the admin user. Restrict access to this endpoint (e.g. firewall, VPN) until setup is complete.
- **Default Paseto secret.** The default secret (`YELLOW SUBMARINE, BLACK WIZARDRY`) is used only to detect "setup required". Never use it as an actual key in production; always run setup and set a strong, unique Paseto secret.
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
