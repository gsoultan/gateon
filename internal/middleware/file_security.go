package middleware

import (
	"bytes"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/dutchcoders/go-clamd"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/security/yara"
	"github.com/h2non/filetype"
)

const (
	defaultScanTimeout        = 30 * time.Second
	defaultMaxConcurrentScans = 4
	defaultMaxScanBytes       = 64 << 20 // 64 MiB
	fileTypeHeaderSize        = 261      // bytes required by github.com/h2non/filetype
)

// FileSecurityConfig configures the upload-inspection middleware.
type FileSecurityConfig struct {
	EnableClamAV     bool
	ClamAVAddr       string // e.g. "tcp://localhost:3310" or "unix:///var/run/clamav/clamd.ctl"
	BlockedMimeTypes []string
	AllowedMimeTypes []string
	MaxFileSize      int64
	// ScanTimeout bounds a single ClamAV stream scan. Defaults to 30s.
	ScanTimeout time.Duration
	// FailOpen controls behaviour when the scanner is unavailable or times out.
	// false (default) = fail-closed (reject the request); true = fail-open (forward).
	FailOpen bool
	// MaxConcurrentScans bounds how many requests may buffer+scan simultaneously,
	// providing backpressure and bounding memory/clamd connections. Defaults to 4.
	MaxConcurrentScans int
	// MaxScanBytes caps the buffered request body size. Requests larger than this
	// are rejected with 413. Defaults to 64 MiB.
	MaxScanBytes int64
	// EnableSignatureScan turns on the dependency-free YARA-lite signature engine
	// that inspects upload content for malware/webshell/exploit indicators.
	EnableSignatureScan bool
	// SignatureRulesPath optionally points to a JSON file of custom rules that
	// extend the built-in ruleset. Empty uses only the built-in rules.
	SignatureRulesPath string
	// SignatureBlockSeverity is the minimum match severity that blocks an upload.
	// Lower-severity matches are logged but allowed. Defaults to "high".
	SignatureBlockSeverity yara.Severity
}

func (c FileSecurityConfig) withDefaults() FileSecurityConfig {
	if c.ScanTimeout <= 0 {
		c.ScanTimeout = defaultScanTimeout
	}
	if c.MaxConcurrentScans <= 0 {
		c.MaxConcurrentScans = defaultMaxConcurrentScans
	}
	if c.MaxScanBytes <= 0 {
		c.MaxScanBytes = defaultMaxScanBytes
	}
	return c
}

// scanResult communicates the outcome of inspecting a multipart body.
type scanResult struct {
	blocked    bool
	status     int
	message    string
	scannerErr error // infrastructure failure (clamd unavailable / timeout)
}

// FileSecurity returns a middleware that inspects multipart uploads for malicious
// content. It buffers the request body so that, after a clean scan, the original
// (intact) body is forwarded to the upstream handler.
func FileSecurity(cfg FileSecurityConfig) Middleware {
	cfg = cfg.withDefaults()
	sem := make(chan struct{}, cfg.MaxConcurrentScans)
	engine := cfg.buildSignatureEngine()
	blockSev := cfg.blockSeverity()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !isUploadMethod(r.Method) || !isMultipart(r.Header.Get("Content-Type")) {
				next.ServeHTTP(w, r)
				return
			}

			boundary, err := multipartBoundary(r.Header.Get("Content-Type"))
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}

			// Acquire a scan slot for backpressure; bounds memory and clamd connections.
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-r.Context().Done():
				return
			}

			body, tooLarge, err := bufferBody(r.Body, cfg.MaxScanBytes)
			if tooLarge {
				http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			if err != nil {
				// The body could not be fully read; there is nothing safe to forward.
				logger.L.LogError("failed to read request body", "error", err, "client_ip", r.RemoteAddr)
				http.Error(w, "Security scan unavailable", http.StatusServiceUnavailable)
				return
			}

			// Reconstruct the body so any downstream path receives the intact upload.
			restoreBody(r, body)

			res := scanMultipart(r, body, boundary, cfg, engine, blockSev)
			if res.scannerErr != nil {
				if !cfg.FailOpen {
					logger.L.LogError("ClamAV scan failed (fail-closed)", "error", res.scannerErr, "client_ip", r.RemoteAddr)
					http.Error(w, "Security scan unavailable", http.StatusServiceUnavailable)
					return
				}
				logger.L.LogWarn("ClamAV scan failed (fail-open), forwarding upload", "error", res.scannerErr, "client_ip", r.RemoteAddr)
			} else if res.blocked {
				http.Error(w, res.message, res.status)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func isUploadMethod(method string) bool {
	return method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch
}

func isMultipart(contentType string) bool {
	return strings.HasPrefix(contentType, "multipart/form-data")
}

func multipartBoundary(contentType string) (string, error) {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return "", err
	}
	boundary := params["boundary"]
	if boundary == "" {
		return "", fmt.Errorf("missing multipart boundary")
	}
	return boundary, nil
}

// bufferBody reads up to maxBytes from the body. It reports tooLarge=true when the
// body exceeds maxBytes so the caller can reject it without buffering unbounded data.
func bufferBody(body io.Reader, maxBytes int64) (buf []byte, tooLarge bool, err error) {
	buf, err = io.ReadAll(io.LimitReader(body, maxBytes+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(buf)) > maxBytes {
		return nil, true, nil
	}
	return buf, false, nil
}

// scanMultipart inspects every file part of the buffered body.
func scanMultipart(r *http.Request, body []byte, boundary string, cfg FileSecurityConfig, engine *yara.Engine, blockSev yara.Severity) scanResult {
	mr := multipart.NewReader(bytes.NewReader(body), boundary)
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		if p.FileName() == "" {
			continue
		}
		if res := inspectPart(r, p, cfg, engine, blockSev); res.blocked || res.scannerErr != nil {
			return res
		}
	}
	return scanResult{}
}

// inspectPart validates a single file part: size, MIME/magic, and ClamAV.
// The part is fully read from the already-buffered (bounded) request body.
func inspectPart(r *http.Request, p *multipart.Part, cfg FileSecurityConfig, engine *yara.Engine, blockSev yara.Severity) scanResult {
	content, err := io.ReadAll(p)
	if err != nil {
		logger.L.LogError("Failed to read upload part", "error", err)
		return scanResult{}
	}

	if cfg.MaxFileSize > 0 && int64(len(content)) > cfg.MaxFileSize {
		logger.L.LogWarn("File upload blocked: file too large",
			"filename", p.FileName(), "size", len(content), "max", cfg.MaxFileSize, "client_ip", r.RemoteAddr)
		return scanResult{blocked: true, status: http.StatusRequestEntityTooLarge, message: "File too large"}
	}

	head := content
	if len(head) > fileTypeHeaderSize {
		head = head[:fileTypeHeaderSize]
	}
	if res := validateMime(r, p, head, cfg); res.blocked {
		return res
	}

	// Close the MIME head-window bypass: MIME/magic detection only inspects the
	// first fileTypeHeaderSize bytes, so an attacker can prepend a benign header
	// (e.g. PNG magic) and append a payload. Scan the FULL content for
	// unambiguous executable magic and block when the file is wrapped as a
	// benign inline type. This is independent of (and complements) the signature
	// engine below, so it holds even when signature scanning is disabled.
	if res := scanEmbeddedExecutable(r, p, head, content); res.blocked {
		return res
	}

	if engine != nil {
		if res := scanSignatures(r, p, content, engine, blockSev); res.blocked {
			return res
		}
	}

	if cfg.EnableClamAV && cfg.ClamAVAddr != "" {
		return scanPartWithClamAV(r, p, content, cfg)
	}
	return scanResult{}
}

// buildSignatureEngine constructs the YARA-lite engine for the middleware,
// loading custom rules when configured and falling back to the built-in ruleset
// on any load error. Returns nil when signature scanning is disabled.
func (c FileSecurityConfig) buildSignatureEngine() *yara.Engine {
	if !c.EnableSignatureScan {
		return nil
	}
	if c.SignatureRulesPath == "" {
		return yara.Default()
	}
	engine, err := yara.LoadFile(c.SignatureRulesPath)
	if err != nil {
		logger.L.LogError("failed to load custom signature rules, using built-in ruleset",
			"error", err, "path", c.SignatureRulesPath)
		return yara.Default()
	}
	return engine
}

// blockSeverity returns the configured minimum blocking severity, defaulting to
// High so only strong indicators reject an upload.
func (c FileSecurityConfig) blockSeverity() yara.Severity {
	if c.SignatureBlockSeverity == "" {
		return yara.SeverityHigh
	}
	return c.SignatureBlockSeverity
}

// scanSignatures runs the YARA-lite engine over a part's content. Matches at or
// above blockSev reject the upload; lower-severity matches are logged only.
func scanSignatures(r *http.Request, p *multipart.Part, content []byte, engine *yara.Engine, blockSev yara.Severity) scanResult {
	matches := engine.Scan(content)
	if len(matches) == 0 {
		return scanResult{}
	}
	top := yara.HighestSeverity(matches)
	names := matchRuleNames(matches)
	if top.AtLeast(blockSev) {
		logger.L.LogWarn("File upload blocked: malicious signature match",
			"filename", p.FileName(), "rules", strings.Join(names, ","),
			"severity", string(top), "client_ip", r.RemoteAddr)
		return scanResult{blocked: true, status: http.StatusForbidden,
			message: fmt.Sprintf("Malicious content detected: %s", strings.Join(names, ", "))}
	}
	logger.L.LogWarn("Suspicious signature match in upload (allowed)",
		"filename", p.FileName(), "rules", strings.Join(names, ","),
		"severity", string(top), "client_ip", r.RemoteAddr)
	return scanResult{}
}

// matchRuleNames extracts the rule names from a set of matches for logging.
func matchRuleNames(matches []yara.Match) []string {
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, m.Rule)
	}
	return names
}

// validateMime enforces MIME allow/deny lists and extension/magic mismatch rules.
func validateMime(r *http.Request, p *multipart.Part, head []byte, cfg FileSecurityConfig) scanResult {
	if len(head) == 0 {
		return scanResult{}
	}
	kind, _ := filetype.Match(head)
	mimeType := kind.MIME.Value
	if mimeType == "" {
		mimeType = http.DetectContentType(head)
	}

	if isBlockedMime(mimeType, cfg) {
		logger.L.LogWarn("File upload blocked: suspicious MIME type",
			"filename", p.FileName(), "mime", mimeType, "client_ip", r.RemoteAddr)
		return scanResult{blocked: true, status: http.StatusForbidden, message: "File type not allowed"}
	}

	ext := strings.ToLower(filepath.Ext(p.FileName()))
	if ext != "" && kind.Extension != "" && ext != "."+kind.Extension && isHighRiskMismatch(ext, kind.Extension) {
		logger.L.LogWarn("File upload blocked: extension/magic mismatch",
			"filename", p.FileName(), "ext", ext, "magic_ext", kind.Extension, "client_ip", r.RemoteAddr)
		return scanResult{blocked: true, status: http.StatusForbidden, message: "File extension mismatch"}
	}
	return scanResult{}
}

// benignWrapperMIMEs are content types that render/preview inline and must not
// legitimately contain an embedded executable image. A hit here strongly
// indicates a polyglot/padding bypass.
var benignWrapperMIMEs = map[string]bool{
	"image/jpeg": true, "image/png": true, "image/gif": true, "image/webp": true,
	"image/bmp": true, "image/tiff": true, "application/pdf": true, "text/plain": true,
}

// scanEmbeddedExecutable looks for unambiguous executable magic anywhere in the
// full content and blocks when the file was uploaded under a benign inline MIME
// type. This catches the "benign 261-byte header + appended payload" bypass that
// head-only MIME detection cannot see. Magic signatures are chosen to be highly
// specific (≥4 bytes) so legitimate images/PDFs effectively never match.
func scanEmbeddedExecutable(r *http.Request, p *multipart.Part, head, content []byte) scanResult {
	if len(head) == 0 {
		return scanResult{}
	}
	kind, _ := filetype.Match(head)
	mimeType := kind.MIME.Value
	if mimeType == "" {
		mimeType = http.DetectContentType(head)
	}
	// Only treat embedded executables as a block-worthy bypass when the file
	// claims to be a benign inline type; ZIP/octet-stream uploads legitimately
	// carry such bytes and are handled by the MIME allowlist + signature engine.
	base := mimeType
	if idx := strings.IndexByte(base, ';'); idx != -1 {
		base = strings.TrimSpace(base[:idx])
	}
	if !benignWrapperMIMEs[base] {
		return scanResult{}
	}
	type sig struct {
		name  string
		magic []byte
	}
	for _, s := range []sig{
		{"ELF", []byte("\x7fELF")},
		{"Mach-O", []byte("\xcf\xfa\xed\xfe")},
		{"Mach-O", []byte("\xfe\xed\xfa\xcf")},
		{"Mach-O", []byte("\xca\xfe\xba\xbe")},
		{"PE", []byte("PE\x00\x00")},
	} {
		if bytes.Contains(content, s.magic) {
			logger.L.LogWarn("File upload blocked: embedded executable in benign wrapper",
				"filename", p.FileName(), "mime", mimeType, "embedded", s.name, "client_ip", r.RemoteAddr)
			return scanResult{blocked: true, status: http.StatusForbidden, message: "Embedded executable content detected"}
		}
	}
	return scanResult{}
}

// scanPartWithClamAV streams the full part content to clamd.
func scanPartWithClamAV(r *http.Request, p *multipart.Part, content []byte, cfg FileSecurityConfig) scanResult {
	res, err := scanStream(r, cfg, bytes.NewReader(content))
	if err != nil {
		logger.L.LogError("ClamAV scan failed", "error", err, "filename", p.FileName())
		return scanResult{scannerErr: err}
	}
	if res != nil && res.Status == clamd.RES_FOUND {
		logger.L.LogWarn("Malware detected in upload",
			"filename", p.FileName(), "virus", res.Description, "client_ip", r.RemoteAddr)
		return scanResult{blocked: true, status: http.StatusForbidden,
			message: fmt.Sprintf("Malware detected: %s", res.Description)}
	}
	return scanResult{}
}

// scanStream performs a single bounded ClamAV stream scan.
func scanStream(r *http.Request, cfg FileSecurityConfig, stream io.Reader) (*clamd.ScanResult, error) {
	c := clamd.NewClamd(cfg.ClamAVAddr)
	abort := make(chan bool, 1)
	response, err := c.ScanStream(stream, abort)
	if err != nil {
		return nil, fmt.Errorf("clamd connection failed: %w", err)
	}

	var found *clamd.ScanResult
	done := make(chan struct{})
	go func() {
		defer close(done)
		for res := range response {
			if res.Status == clamd.RES_FOUND {
				found = res
				signalAbort(abort)
				return
			}
		}
	}()

	select {
	case <-done:
		return found, nil
	case <-time.After(cfg.ScanTimeout):
		signalAbort(abort)
		return nil, fmt.Errorf("scan timed out after %s", cfg.ScanTimeout)
	case <-r.Context().Done():
		signalAbort(abort)
		return nil, r.Context().Err()
	}
}

func signalAbort(abort chan bool) {
	select {
	case abort <- true:
	default:
	}
}

// restoreBody replaces the (consumed) request body with the buffered copy so the
// upstream handler receives the intact upload, and keeps Content-Length consistent.
func restoreBody(r *http.Request, body []byte) {
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
}

func isBlockedMime(mimeType string, cfg FileSecurityConfig) bool {
	if len(cfg.AllowedMimeTypes) > 0 {
		for _, a := range cfg.AllowedMimeTypes {
			if mimeType == a {
				return false
			}
		}
		return true
	}
	for _, b := range cfg.BlockedMimeTypes {
		if mimeType == b {
			return true
		}
	}
	return false
}

func isHighRiskMismatch(ext, magicExt string) bool {
	highRiskExts := map[string]bool{
		".exe": true, ".dll": true, ".so": true, ".sh": true, ".php": true, ".py": true, ".elf": true,
	}
	if highRiskExts["."+magicExt] {
		imageExts := map[string]bool{".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".pdf": true}
		if imageExts[ext] {
			return true
		}
	}
	return false
}
