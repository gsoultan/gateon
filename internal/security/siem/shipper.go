package siem

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Environment variables controlling the SIEM exporter (all optional; the
// exporter is disabled unless GATEON_SIEM_ENDPOINT is set or _ENABLED is true).
const (
	envEnabled   = "GATEON_SIEM_ENABLED"
	envFormat    = "GATEON_SIEM_FORMAT"    // json | cef | syslog (default json)
	envTransport = "GATEON_SIEM_TRANSPORT" // http | udp | tcp (default http)
	envEndpoint  = "GATEON_SIEM_ENDPOINT"  // URL (http) or host:port (udp/tcp)
	envToken     = "GATEON_SIEM_TOKEN"     // optional bearer token (http)
	envQueueSize = "GATEON_SIEM_QUEUE_SIZE"
	envTimeout   = "GATEON_SIEM_TIMEOUT" // per-send timeout, e.g. "5s"
)

// Default tuning values.
const (
	defaultQueueSize = 2048
	defaultTimeout   = 5 * time.Second
	minQueueSize     = 16
	jsonContentType  = "application/json"
	textContentType  = "text/plain; charset=utf-8"
)

// ErrDisabled indicates SIEM export is not configured.
var ErrDisabled = errors.New("siem: export disabled")

// Config configures a Shipper.
type Config struct {
	Enabled   bool
	Format    Format
	Transport string // "http", "udp", or "tcp"
	Endpoint  string
	Token     string
	QueueSize int
	Timeout   time.Duration
	// Version is reported in CEF/syslog headers (e.g. the Gateon build version).
	Version string
}

// Stats is a snapshot of shipper counters, safe to expose in posture reports.
type Stats struct {
	Enqueued int64 `json:"enqueued"`
	Shipped  int64 `json:"shipped"`
	Dropped  int64 `json:"dropped"`
	Errors   int64 `json:"errors"`
}

// Shipper asynchronously exports events to a SIEM sink over a bounded queue.
// Ship never blocks the caller; on queue overflow events are dropped and
// counted rather than back-pressuring the request hot path.
type Shipper struct {
	formatter formatter
	transport transport
	queue     chan Event

	enqueued atomic.Int64
	shipped  atomic.Int64
	dropped  atomic.Int64
	errs     atomic.Int64
}

// ConfigFromEnv builds a Config from environment variables. It returns
// ErrDisabled when export is not configured.
func ConfigFromEnv(version string) (Config, error) {
	endpoint := strings.TrimSpace(os.Getenv(envEndpoint))
	if endpoint == "" {
		return Config{}, ErrDisabled
	}
	// Export is enabled when an endpoint is configured, unless explicitly
	// disabled via GATEON_SIEM_ENABLED=false.
	if raw := strings.TrimSpace(os.Getenv(envEnabled)); raw != "" && !boolEnv(envEnabled) {
		return Config{}, ErrDisabled
	}

	cfg := Config{
		Enabled:   true,
		Format:    parseFormat(os.Getenv(envFormat)),
		Transport: parseTransport(os.Getenv(envTransport)),
		Endpoint:  endpoint,
		Token:     strings.TrimSpace(os.Getenv(envToken)),
		QueueSize: intEnv(envQueueSize, defaultQueueSize),
		Timeout:   durationEnv(envTimeout, defaultTimeout),
		Version:   version,
	}
	return cfg, nil
}

// New builds a Shipper from cfg. It returns ErrDisabled when cfg.Enabled is
// false and an error when the endpoint/transport is invalid.
func New(cfg Config) (*Shipper, error) {
	if !cfg.Enabled {
		return nil, ErrDisabled
	}
	if strings.TrimSpace(cfg.Endpoint) == "" {
		return nil, errors.New("siem: endpoint is required")
	}

	queueSize := cfg.QueueSize
	if queueSize < minQueueSize {
		queueSize = defaultQueueSize
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	fmtr := newFormatter(cfg.Format, cfg.Version)
	tr, err := buildTransport(cfg, fmtr, timeout)
	if err != nil {
		return nil, err
	}

	return &Shipper{
		formatter: fmtr,
		transport: tr,
		queue:     make(chan Event, queueSize),
	}, nil
}

// buildTransport selects the transport implementation from cfg.
func buildTransport(cfg Config, fmtr formatter, timeout time.Duration) (transport, error) {
	switch cfg.Transport {
	case "udp", "tcp":
		return newNetTransport(cfg.Transport, cfg.Endpoint, timeout), nil
	case "http", "":
		ct := jsonContentType
		if _, ok := fmtr.(jsonFormatter); !ok {
			ct = textContentType
		}
		return newHTTPTransport(cfg.Endpoint, cfg.Token, ct, timeout), nil
	default:
		return nil, errors.New("siem: unsupported transport " + cfg.Transport)
	}
}

// Ship enqueues an event for asynchronous export. It never blocks; if the queue
// is full the event is dropped and counted.
func (s *Shipper) Ship(e Event) {
	if s == nil {
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	select {
	case s.queue <- e:
		s.enqueued.Add(1)
	default:
		s.dropped.Add(1)
	}
}

// Run drains the queue and exports events until ctx is cancelled, then flushes
// remaining queued events on a best-effort basis and closes the transport. It
// blocks and is intended to run in its own goroutine.
func (s *Shipper) Run(ctx context.Context) {
	defer func() { _ = s.transport.Close() }()
	for {
		select {
		case <-ctx.Done():
			s.drain()
			return
		case e := <-s.queue:
			s.export(ctx, e)
		}
	}
}

// drain flushes any still-queued events using a short bounded context.
func (s *Shipper) drain() {
	flushCtx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()
	for {
		select {
		case e := <-s.queue:
			s.export(flushCtx, e)
		default:
			return
		}
	}
}

// export formats and sends a single event, updating counters.
func (s *Shipper) export(ctx context.Context, e Event) {
	payload := s.formatter.format(e)
	if len(payload) == 0 {
		s.errs.Add(1)
		return
	}
	if err := s.transport.send(ctx, payload); err != nil {
		s.errs.Add(1)
		return
	}
	s.shipped.Add(1)
}

// Stats returns a snapshot of the shipper counters.
func (s *Shipper) Stats() Stats {
	if s == nil {
		return Stats{}
	}
	return Stats{
		Enqueued: s.enqueued.Load(),
		Shipped:  s.shipped.Load(),
		Dropped:  s.dropped.Load(),
		Errors:   s.errs.Load(),
	}
}

func parseFormat(v string) Format {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case string(FormatCEF):
		return FormatCEF
	case string(FormatSyslog):
		return FormatSyslog
	default:
		return FormatJSON
	}
}

func parseTransport(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "udp":
		return "udp"
	case "tcp":
		return "tcp"
	default:
		return "http"
	}
}

func boolEnv(key string) bool {
	v, err := strconv.ParseBool(strings.TrimSpace(os.Getenv(key)))
	if err != nil {
		return false
	}
	return v
}

func intEnv(key string, def int) int {
	v, err := strconv.Atoi(strings.TrimSpace(os.Getenv(key)))
	if err != nil || v <= 0 {
		return def
	}
	return v
}

func durationEnv(key string, def time.Duration) time.Duration {
	v, err := time.ParseDuration(strings.TrimSpace(os.Getenv(key)))
	if err != nil || v <= 0 {
		return def
	}
	return v
}
