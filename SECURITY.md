# Security

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
