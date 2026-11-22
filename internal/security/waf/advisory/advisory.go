// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package advisory sends a bounded sample of the requests a WAF let through
// to a worker on another host, for a second opinion the request path cannot
// afford, and takes back what the worker says about them (ADR 0104).
//
// The worker advises. It is asked after the request was answered, it never
// holds a request up, and nothing it says refuses one: a verdict becomes an
// entry in the Security Hub, and in reputation mode evidence against the
// source, which the gateway's own reputation rules act on like any other.
//
// What leaves the gateway is what the tuning sample holds (ADR 0097): method,
// path, query parameters and headers, with every credential removed. No
// body, no time, and no client address: a verdict comes back for a sample's
// number, and only the gateway knows whose request that was.
//
// Everything is bounded. The queue has a fixed size and a full one drops the
// sample and counts it; one goroutine sends, one batch at a time, with a
// deadline; a worker that is down costs the samples and nothing else.
package advisory

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
)

// Mode is what a verdict does once it is back.
type Mode string

const (
	// Record lists a verdict in the Security Hub and holds it against
	// nobody. It is the default: a worker is believed only once what it
	// says has been read.
	Record Mode = "record"
	// Reputation also counts a verdict as evidence against the source, as a
	// detection the gateway made itself would be.
	Reputation Mode = "reputation"
)

// The environment the process-wide queue is configured from. There is one
// worker per gateway, so none of this is route configuration.
const (
	URLEnv   = "GATEON_WAF_ADVISORY_URL"
	TokenEnv = "GATEON_WAF_ADVISORY_TOKEN"
	ModeEnv  = "GATEON_WAF_ADVISORY_MODE"
	QueueEnv = "GATEON_WAF_ADVISORY_QUEUE"
)

// The fixed bounds of the exchange with the worker.
const (
	// maxQueue caps what QueueEnv may ask for. A sample is at most about
	// 6 KiB, so this is 24 MiB of requests waiting on another host.
	maxQueue = 4096

	defaultBatch   = 32
	defaultWait    = 2 * time.Second
	defaultTimeout = 10 * time.Second
	defaultBackoff = time.Second
	maxBackoff     = time.Minute

	// maxResponseBytes is the most of a worker's answer that is read. A
	// batch is at most defaultBatch verdicts of a few hundred bytes each.
	maxResponseBytes = 256 << 10
)

// Config is one worker and how it is spoken to.
type Config struct {
	// URL is where batches are posted. Empty turns the whole feature off.
	URL string
	// Token is sent as a bearer credential so the worker can tell this
	// gateway from anyone else who can reach it.
	Token string
	Mode  Mode
	// Capacity is how many samples may wait to be sent.
	Capacity int

	// The rest default when zero and are set only by tests.
	BatchSize int
	BatchWait time.Duration
	Timeout   time.Duration
	Backoff   time.Duration
}

// Queue is the gateway's side of the exchange. It is safe for concurrent
// use, and its request-path methods take no lock.
type Queue struct {
	cfg      Config
	endpoint string
	ch       chan *Sample
	client   *http.Client
	sink     atomic.Pointer[func(Finding)]

	seq, tick                               atomic.Uint64
	offered, dropped, sent, failed, flagged atomic.Uint64
	unmatched                               atomic.Uint64
	lastContact                             atomic.Int64
	lastError                               atomic.Pointer[string]
}

// Off is a queue with no worker. It accepts nothing and sends nothing.
func Off() *Queue { return &Queue{} }

// New returns a queue for cfg, or an error when cfg names a worker that must
// not be used.
func New(cfg Config) (*Queue, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return Off(), nil
	}
	endpoint, err := checkURL(cfg.URL)
	if err != nil {
		return nil, err
	}
	switch cfg.Mode {
	case "":
		cfg.Mode = Record
	case Record, Reputation:
	default:
		return nil, errors.New("advisory mode must be \"record\" or \"reputation\"")
	}
	cfg = withDefaults(cfg)
	return &Queue{
		cfg:      cfg,
		endpoint: endpoint,
		ch:       make(chan *Sample, cfg.Capacity),
		client:   newClient(cfg.Timeout),
	}, nil
}

func withDefaults(cfg Config) Config {
	if cfg.Capacity < 1 {
		cfg.Capacity = 1
	}
	cfg.Capacity = min(cfg.Capacity, maxQueue)
	if cfg.BatchSize < 1 {
		cfg.BatchSize = defaultBatch
	}
	if cfg.BatchWait <= 0 {
		cfg.BatchWait = defaultWait
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.Backoff <= 0 {
		cfg.Backoff = defaultBackoff
	}
	return cfg
}

// checkURL reports the scheme and host of a usable worker address.
//
// A sample carries no credential, but it is still what clients sent, and the
// token rides with it. So the worker is reached over TLS, or over plain HTTP
// on this host only. An address that carries a password, a query or a
// fragment is refused: it would be written to the log with every error.
func checkURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", errors.New("advisory worker address is not a URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("advisory worker address must not carry a credential, a query or a fragment")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopbackHost(u.Hostname()) {
			return "", errors.New("advisory worker address must be https unless the worker is on this host")
		}
	default:
		return "", errors.New("advisory worker address must be https")
	}
	return u.Scheme + "://" + u.Host, nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// newClient is the one client batches are sent with. Every limit is set here
// and none is inherited. A redirect is not followed: it would carry the
// token and the samples to wherever the answer pointed.
func newClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:                  http.ProxyFromEnvironment,
			DialContext:            (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout:    5 * time.Second,
			ResponseHeaderTimeout:  timeout,
			IdleConnTimeout:        90 * time.Second,
			MaxIdleConns:           2,
			MaxIdleConnsPerHost:    2,
			MaxConnsPerHost:        2,
			MaxResponseHeaderBytes: 16 << 10,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// Enabled reports whether there is a worker to ask.
func (q *Queue) Enabled() bool { return q.ch != nil }

// Mode is what a verdict does.
func (q *Queue) Mode() Mode { return q.cfg.Mode }

// Room reports whether a sample offered now would be kept. The request path
// asks before it builds one, so a flood of requests worth a second opinion
// costs a comparison each once the queue is full, not an allocation.
func (q *Queue) Room() bool { return q.ch != nil && len(q.ch) < cap(q.ch) }

// Due reports whether this request is the one in every rate to offer though
// nothing matched it. A rate below 1 offers none.
func (q *Queue) Due(rate int) bool {
	if rate < 1 || q.ch == nil {
		return false
	}
	return q.tick.Add(1)%uint64(rate) == 0
}

// Offer queues s and reports whether it was kept. It never blocks: a full
// queue drops s and counts it.
func (q *Queue) Offer(s *Sample) bool {
	if q.ch == nil || s == nil {
		return false
	}
	q.offered.Add(1)
	s.ID = strconv.FormatUint(q.seq.Add(1), 10)
	select {
	case q.ch <- s:
		return true
	default:
		q.dropped.Add(1)
		return false
	}
}

// SetSink names what is told of each verdict. One sink, the last set.
func (q *Queue) SetSink(sink func(Finding)) { q.sink.Store(&sink) }

// Run sends what is queued until ctx is done. It is the queue's only
// goroutine; whoever calls it owns its lifetime.
func (q *Queue) Run(ctx context.Context) {
	if q.ch == nil {
		return
	}
	failures := 0
	for {
		batch := q.gather(ctx)
		if batch == nil {
			return
		}
		if err := q.send(ctx, batch); err != nil {
			if ctx.Err() != nil {
				return
			}
			q.failed.Add(uint64(len(batch)))
			msg := err.Error()
			q.lastError.Store(&msg)
			if failures == 0 {
				logger.L.LogWarn("WAF advisory worker could not be asked; samples are dropped until it answers",
					"worker", q.endpoint, "error", msg)
			}
			failures++
			if !pause(ctx, backoffAfter(q.cfg.Backoff, failures)) {
				return
			}
			continue
		}
		if failures > 0 {
			logger.L.LogInfo("WAF advisory worker is answering again", "worker", q.endpoint)
		}
		failures = 0
	}
}

// gather waits for a sample, then for a full batch or BatchWait, whichever
// comes first. It returns nil once ctx is done.
func (q *Queue) gather(ctx context.Context) []*Sample {
	var first *Sample
	select {
	case <-ctx.Done():
		return nil
	case first = <-q.ch:
	}
	batch := make([]*Sample, 1, q.cfg.BatchSize)
	batch[0] = first
	if len(batch) == q.cfg.BatchSize {
		return batch
	}
	timer := time.NewTimer(q.cfg.BatchWait)
	defer timer.Stop()
	for len(batch) < q.cfg.BatchSize {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			return batch
		case s := <-q.ch:
			batch = append(batch, s)
		}
	}
	return batch
}

// backoffAfter doubles from base with each failure in a row, up to a minute.
func backoffAfter(base time.Duration, failures int) time.Duration {
	d := base
	for i := 1; i < failures && d < maxBackoff; i++ {
		d *= 2
	}
	return min(d, maxBackoff)
}

// pause waits d and reports false when ctx ended first.
func pause(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// FromEnv reads the process's worker from the environment.
func FromEnv() Config {
	capacity, _ := strconv.Atoi(strings.TrimSpace(os.Getenv(QueueEnv)))
	if capacity < 1 {
		capacity = config.CurrentTierDefaults().WAFAdvisoryQueue
	}
	return Config{
		URL:      strings.TrimSpace(os.Getenv(URLEnv)),
		Token:    strings.TrimSpace(os.Getenv(TokenEnv)),
		Mode:     Mode(strings.ToLower(strings.TrimSpace(os.Getenv(ModeEnv)))),
		Capacity: capacity,
	}
}

// Shared is the process's one queue. A worker address that must not be used
// is said once, loudly, and leaves the feature off: the alternative is a
// gateway that will not start because of a setting nothing depends on.
var Shared = sync.OnceValue(func() *Queue {
	q, err := New(FromEnv())
	if err != nil {
		logger.L.LogError("WAF advisory worker is not used", "error", err, "setting", URLEnv)
		return Off()
	}
	if q.Enabled() {
		logger.L.LogInfo("WAF asks an advisory worker about a sample of forwarded requests",
			"worker", q.endpoint, "mode", string(q.cfg.Mode), "queue", q.cfg.Capacity)
	}
	return q
})
