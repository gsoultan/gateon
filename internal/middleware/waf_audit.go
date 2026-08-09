// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package middleware

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gwaf"
)

// The WAF audit log used to be written by Coraza, configured through
// SecAuditLog directives. gwaf writes nothing anywhere — it hands back a
// decision and the embedder owns the logging — so gateon writes it.
//
// That is a better arrangement than it sounds. The old audit log recorded what
// Coraza thought had happened in Coraza's format; this one records gateon's own
// decision structure and is JSON per line, so it can be shipped without a
// parser.

// auditRecord is one line of the WAF audit log.
type auditRecord struct {
	Time        time.Time `json:"time"`
	Route       string    `json:"route"`
	Blocked     bool      `json:"blocked"`
	Status      int       `json:"status,omitempty"`
	RuleID      string    `json:"rule_id,omitempty"`
	Message     string    `json:"message,omitempty"`
	Severity    string    `json:"severity,omitempty"`
	Confidence  string    `json:"confidence,omitempty"`
	Score       int       `json:"score"`
	Reason      string    `json:"reason,omitempty"`
	Target      string    `json:"target,omitempty"`
	Key         string    `json:"key,omitempty"`
	Decoding    string    `json:"decoding,omitempty"`
	Method      string    `json:"method,omitempty"`
	URI         string    `json:"uri,omitempty"`
	ClientIP    string    `json:"client_ip,omitempty"`
	MatchedRule []string  `json:"matched_rules,omitempty"`

	// The fields below come from Decision.Explain() and exist so an operator can
	// answer "why was this blocked, and what do I do about it?" from the record
	// alone, without replaying the request.
	//
	// gwaf ships no UI on purpose, but its corollary is binding: every datum a
	// UI would need has to be reachable as a library API. gateon is the UI, so
	// this is the half of that contract gateon owes — the data was already
	// available through Explain() and simply was not being written down.

	// MatchedBytes is the exact span of the value that matched, truncated. It is
	// the difference between "SQLi in ARGS:q" and showing the operator the eight
	// bytes that did it.
	MatchedBytes string `json:"matched_bytes,omitempty"`

	// MatchedAt is the byte offset and length of that span within the value.
	MatchedAt *auditSpan `json:"matched_at,omitempty"`

	// TransformChain is the transforms applied before the match. A block that
	// only makes sense after url_decode+lowercase is not obvious from the raw
	// request, and this is what explains it.
	TransformChain []string `json:"transform_chain,omitempty"`

	// Exception is the narrowest suppression that would stop this exact finding
	// without weakening the rule anywhere else. It is what turns a false
	// positive into a one-click fix instead of a rule somebody disables wholesale.
	Exception *auditException `json:"suggested_exception,omitempty"`
}

// auditSpan locates the match inside the value.
type auditSpan struct {
	Offset int `json:"offset"`
	Length int `json:"length"`
}

// auditException is the narrowest exception that suppresses one finding,
// rendered as data the API and dashboard can act on directly.
type auditException struct {
	RuleID uint32 `json:"rule_id"`
	Path   string `json:"path,omitempty"`
	Target string `json:"target,omitempty"`
	Key    string `json:"key,omitempty"`
}

// maxMatchedBytes bounds what the audit record copies out of a request.
//
// The matched span is attacker-controlled, and an audit log is read by humans
// and shipped to a SIEM. Writing an unbounded slice of a hostile request into
// both is how a log becomes an injection vector of its own.
const maxMatchedBytes = 256

// auditLog appends WAF decisions to a file.
//
// Writes are serialised through a mutex rather than a channel: the volume is
// bounded by the number of requests that actually match a rule, which on
// ordinary traffic is a rounding error, and a channel would add a goroutine and
// a queue whose overflow behaviour would then have to be designed.
type auditLog struct {
	mu           sync.Mutex
	file         *os.File
	relevantOnly bool
}

// The audit log records no header or argument *values*, only rule identity,
// the collection and key that matched, and the request line.
//
// That is stronger than the redaction it replaces. Coraza's audit log wrote
// full transaction data and relied on a SecLang rule (1900300) listing headers
// to redact — a rule an operator could delete, and a list that only covered the
// header names somebody had thought of. Recording no values at all cannot be
// switched off and has nothing to keep in step.

// newAuditLog opens the audit log a config asks for, or returns nil when the
// config asks for none.
func newAuditLog(cfg WAFConfig) (*auditLog, error) {
	path := resolveAuditLogPath(cfg)
	if path == "" {
		return nil, nil
	}
	if err := ensureAuditLogFile(path); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return nil, fmt.Errorf("open audit log %q: %w", path, err)
	}
	return &auditLog{file: f, relevantOnly: cfg.AuditLogRelevantOnly}, nil
}

// record writes one decision.
func (a *auditLog) record(d gwaf.Decision, matches []gwaf.Match, o wafObservation) {
	if a == nil || a.file == nil {
		return
	}
	if a.relevantOnly && !d.Blocked() && len(matches) == 0 {
		return
	}

	rec := auditRecord{
		Time:     time.Now().UTC(),
		Route:    o.routeID,
		Blocked:  d.Blocked(),
		Status:   d.Status(),
		Message:  d.Message(),
		Score:    d.Score(),
		Reason:   fmt.Sprint(d.Reason()),
		Key:      d.Key(),
		Decoding: d.Interpretation(),
		Method:   o.request.Method,
		URI:      o.request.RequestURI,
	}
	if d.RuleID() != 0 {
		rec.RuleID = d.RuleID().String()
		rec.Severity = d.Severity().String()
		rec.Confidence = d.Confidence().String()
		rec.Target = d.Target().String()
	}
	for _, m := range matches {
		rec.MatchedRule = append(rec.MatchedRule, m.RuleID.String())
	}
	// Explain() is only meaningful once something matched; an allowed request
	// has nothing to explain and would cost a copy for an empty record.
	if d.RuleID() != 0 {
		explain(&rec, d.Explain())
	}

	line, err := json.Marshal(rec)
	if err != nil {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.file.Write(append(line, '\n')); err != nil {
		logger.L.LogWarn("could not write the WAF audit log", "error", err)
	}
}

// Close releases the file.
func (a *auditLog) Close() error {
	if a == nil || a.file == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.file.Close()
}

// resolveAuditLogPath returns the file a config's audit log belongs in.
func resolveAuditLogPath(cfg WAFConfig) string {
	if p := strings.TrimSpace(cfg.AuditLogPath); p != "" {
		return p
	}
	name := sanitizeAuditName(cfg.RouteID)
	if name == "" {
		name = "waf"
	}
	return filepath.Join(config.DataDir(), "audit", "waf", name+"_audit.log")
}

// sanitizeAuditName makes a route identifier safe to use as a file name.
//
// The route ID reaches this from configuration, so a name containing a path
// separator would otherwise choose where the log is written.
func sanitizeAuditName(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return strings.Trim(b.String(), "._")
}

// ensureAuditLogFile creates the log and its directory.
func ensureAuditLogFile(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create audit log dir %q: %w", dir, err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return fmt.Errorf("create audit log file %q: %w", path, err)
	}
	return f.Close()
}

// explain copies the parts of a gwaf Explanation an operator acts on into the
// audit record.
//
// The matched bytes are truncated and the exception is flattened to plain data,
// so the record stays a record: something a SIEM can index and an API can return
// without holding a reference to a transaction that has already been recycled.
func explain(rec *auditRecord, e gwaf.Explanation) {
	if b := e.MatchedBytes(); len(b) > 0 {
		if len(b) > maxMatchedBytes {
			b = b[:maxMatchedBytes]
		}
		// Copied rather than aliased: the explanation points into the
		// transaction's arena, which is pooled and reused by the next request.
		rec.MatchedBytes = string(b)
	}
	if span, ok := e.MatchedSpan(); ok {
		rec.MatchedAt = &auditSpan{Offset: int(span.Off), Length: int(span.Len)}
	}
	if chain := e.TransformChain(); len(chain) > 0 {
		rec.TransformChain = append(rec.TransformChain, chain...)
	}
	if x, ok := e.NarrowestException(); ok {
		rec.Exception = &auditException{
			RuleID: uint32(x.RuleID),
			Path:   x.Path,
			Target: x.Target.String(),
			Key:    x.Key,
		}
	}
}
