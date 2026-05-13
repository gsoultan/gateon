package security

import (
	"net/http"

	"github.com/gsoultan/gateon/internal/audit"
)

// HoneytokenMiddleware returns a middleware that detects access to "trap" resources.
// Any access to these resources is a deterministic signal of a malicious actor.
func HoneytokenMiddleware(tokens map[string]string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if reason, ok := tokens[r.URL.Path]; ok {
				// Log the attempt as a high-severity security event
				audit.Log(r.Context(), "system", "honeytoken_triggered", r.URL.Path, "Reason: "+reason, r.RemoteAddr)

				// Return a fake error to the attacker
				http.Error(w, "Not Found", http.StatusNotFound)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// DefaultHoneytokens provides a set of common traps.
func DefaultHoneytokens() map[string]string {
	return map[string]string{
		"/.env":             "Environment file access attempt",
		"/.git/config":      "Git configuration access attempt",
		"/wp-config.php":    "WordPress configuration access attempt",
		"/admin/config.php": "Admin configuration access attempt",
		"/backup.sql":       "Database backup access attempt",
		"/etc/passwd":       "System file access attempt",
		"/.aws/credentials": "AWS credentials access attempt",
		"/server-status":    "Apache server status access attempt",
		"/phpinfo.php":      "PHP info access attempt",
		"/actuator/env":     "Spring Boot actuator access attempt",
	}
}
