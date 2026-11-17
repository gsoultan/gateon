// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package syslogsink sends a copy of every audit entry off the host, as
// RFC 5424 syslog over TCP, TLS or UDP, as it is written (ADR 0097).
//
// The audit log is signed and chained, and it lives in the gateway's own
// database with its signing key in the gateway's own environment. Someone who
// takes the host has both, and can rewrite the log so that it still verifies.
// A copy that left the host as each entry was written is the one record they
// cannot reach. Each forwarded entry carries its signature and the previous
// entry's, so the copy can be checked against the chain on its own.
//
// It is configured from the host's environment only. A dashboard session --
// a stolen one included -- can neither switch it off nor point it somewhere
// else.
package syslogsink

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/gsoultan/gateon/internal/audit"
	"github.com/gsoultan/gateon/internal/logger"
)

// The variables that configure forwarding.
const (
	// EnvAddr is where entries go: tls://host:port, tcp://host:port or
	// udp://host:port. Unset, nothing is forwarded.
	EnvAddr = "GATEON_AUDIT_SYSLOG_ADDR"
	// EnvCAFile is a PEM file of CA certificates a tls:// receiver is verified
	// against instead of the system roots.
	EnvCAFile = "GATEON_AUDIT_SYSLOG_CA"
)

// Bounds. A receiver that is down or slow must cost the gateway a fixed
// amount of memory, never the request path's time.
const (
	// priorityQueue holds entries an account wrote: sign-ins, user and
	// configuration changes. It is drained first, so a flood of system
	// entries cannot push an administrator's out.
	priorityQueue = 1024
	// bulkQueue holds the entries the gateway writes for itself, one per
	// security threat, which an attacker can drive at any rate.
	bulkQueue = 2048
	// maxDetails is the most of an entry's details a forwarded copy carries.
	// A cut entry says so, and no longer verifies on its own.
	maxDetails = 8 << 10
	// maxHostname bounds the HOSTNAME field (RFC 5424 §6.2.4).
	maxHostname  = 255
	dialTimeout  = 5 * time.Second
	writeTimeout = 5 * time.Second
	minBackoff   = 500 * time.Millisecond
	maxBackoff   = 30 * time.Second
)

// facilityLogAudit is syslog facility 13, "log audit".
const facilityLogAudit = 13

const (
	severityNotice = 5 // an account's entry
	severityInfo   = 6 // a system entry
)

var (
	forwardedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "gateon_audit_forward_sent_total",
		Help: "Audit entries sent to the off-host syslog receiver.",
	})
	droppedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gateon_audit_forward_dropped_total",
		Help: "Audit entries not forwarded because their queue was full, by queue (account or system).",
	}, []string{"queue"})
	connectedGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "gateon_audit_forward_connected",
		Help: "1 while the off-host syslog receiver is connected, 0 while it is not.",
	})
)

// Config says where to forward. Network is "tcp", "tls" or "udp".
type Config struct {
	Network  string
	Address  string
	TLS      *tls.Config
	Hostname string
}

// ConfigFromEnv reads EnvAddr and EnvCAFile. ok is false when EnvAddr is
// unset. A value that is set and cannot be used is an error, never a silent
// "not forwarding".
func ConfigFromEnv() (cfg Config, ok bool, err error) {
	raw := strings.TrimSpace(os.Getenv(EnvAddr))
	if raw == "" {
		return Config{}, false, nil
	}
	cfg, err = parseAddr(raw)
	if err != nil {
		return Config{}, true, err
	}
	if cfg.Network == "tls" {
		if cfg.TLS, err = tlsConfig(cfg.Address, os.Getenv(EnvCAFile)); err != nil {
			return Config{}, true, err
		}
	}
	cfg.Hostname = hostname()
	return cfg, true, nil
}

func parseAddr(raw string) (Config, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return Config{}, fmt.Errorf("%s=%q is not scheme://host:port", EnvAddr, raw)
	}
	switch u.Scheme {
	case "tcp", "tls", "udp":
	default:
		return Config{}, fmt.Errorf("%s=%q: the scheme must be tls, tcp or udp", EnvAddr, raw)
	}
	if _, port, err := net.SplitHostPort(u.Host); err != nil || port == "" {
		return Config{}, fmt.Errorf("%s=%q names no port", EnvAddr, raw)
	}
	return Config{Network: u.Scheme, Address: u.Host}, nil
}

func tlsConfig(address, caFile string) (*tls.Config, error) {
	host, _, _ := net.SplitHostPort(address)
	c := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
	if caFile == "" {
		return c, nil
	}
	pem, err := os.ReadFile(caFile) // #nosec G304 -- a path the host's environment names, not a request.
	if err != nil {
		return nil, fmt.Errorf("%s: %w", EnvCAFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s=%q holds no PEM certificate", EnvCAFile, caFile)
	}
	c.RootCAs = pool
	return c, nil
}

// hostname is the HOSTNAME field: GATEON_NODE_NAME, else the host's name,
// as printable ASCII without spaces.
func hostname() string {
	h := os.Getenv("GATEON_NODE_NAME")
	if h == "" {
		h, _ = os.Hostname()
	}
	b := make([]byte, 0, min(len(h), maxHostname))
	for i := 0; i < len(h) && len(b) < maxHostname; i++ {
		if h[i] > ' ' && h[i] < 0x7f {
			b = append(b, h[i])
		}
	}
	if len(b) == 0 {
		return "-"
	}
	return string(b)
}

// Forwarder queues entries and sends them on its own goroutine.
type Forwarder struct {
	cfg     Config
	account chan queued
	system  chan queued
	dial    func(ctx context.Context) (net.Conn, error)
	done    chan struct{}
	drops   atomic.Uint64
}

// New returns a forwarder for cfg; Run sends what Sink queues.
func New(cfg Config) *Forwarder {
	f := &Forwarder{
		cfg:     cfg,
		account: make(chan queued, priorityQueue),
		system:  make(chan queued, bulkQueue),
		done:    make(chan struct{}),
	}
	f.dial = f.dialReceiver
	return f
}

// Start reads the environment and, when forwarding is configured, registers
// a forwarder as an audit sink and runs it until ctx ends. It returns the
// error of a configuration that cannot be used.
func Start(ctx context.Context) (*Forwarder, error) {
	cfg, ok, err := ConfigFromEnv()
	if err != nil || !ok {
		return nil, err
	}
	f := New(cfg)
	remove := audit.AddSink(f.Sink)
	go func() {
		defer remove()
		f.Run(ctx)
	}()
	logger.L.LogInfo("audit entries are forwarded off the host", "network", cfg.Network, "address", cfg.Address)
	return f, nil
}

// Done is closed when Run returns.
func (f *Forwarder) Done() <-chan struct{} { return f.done }

// queued is an entry waiting to be sent, and whether its details were cut.
type queued struct {
	e         audit.AuditEntry
	truncated bool
}

// Sink queues e without blocking. A full queue drops the entry and counts it.
func (f *Forwarder) Sink(e audit.AuditEntry) {
	q, name := f.account, "account"
	if e.UserID == "system" {
		q, name = f.system, "system"
	}
	item := queued{e: e}
	if len(e.Details) > maxDetails {
		// A copy, so the queue does not keep the whole original alive.
		item.e.Details, item.truncated = strings.Clone(e.Details[:maxDetails]), true
	}
	select {
	case q <- item:
	default:
		droppedTotal.WithLabelValues(name).Inc()
		if n := f.drops.Add(1); n == 1 || n%1000 == 0 {
			logger.L.LogWarn("audit forwarding is behind; entries dropped", "queue", name, "dropped_total", n)
		}
	}
}

// Run sends queued entries until ctx ends, reconnecting with backoff. An
// entry a failed write did not deliver is sent again on the next connection,
// so the receiver can see one twice and never sees a gap it is not told of.
func (f *Forwarder) Run(ctx context.Context) {
	defer close(f.done)
	defer connectedGauge.Set(0)
	var conn net.Conn
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()
	backoff := minBackoff
	for {
		e, ok := f.next(ctx)
		if !ok {
			return
		}
		for {
			if conn == nil {
				c, err := f.dial(ctx)
				if err != nil {
					logger.L.LogWarn("audit forwarding cannot reach its receiver", "address", f.cfg.Address, "error", err)
					if !sleep(ctx, backoff) {
						return
					}
					backoff = min(backoff*2, maxBackoff)
					continue
				}
				conn, backoff = c, minBackoff
				connectedGauge.Set(1)
			}
			if err := f.write(conn, e); err != nil {
				_ = conn.Close()
				conn = nil
				connectedGauge.Set(0)
				continue
			}
			forwardedTotal.Inc()
			break
		}
	}
}

// next is the next entry to send, an account's before the system's.
func (f *Forwarder) next(ctx context.Context) (queued, bool) {
	select {
	case e := <-f.account:
		return e, true
	default:
	}
	select {
	case e := <-f.account:
		return e, true
	case e := <-f.system:
		return e, true
	case <-ctx.Done():
		return queued{}, false
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func (f *Forwarder) dialReceiver(ctx context.Context) (net.Conn, error) {
	d := net.Dialer{Timeout: dialTimeout}
	switch f.cfg.Network {
	case "tls":
		td := tls.Dialer{NetDialer: &d, Config: f.cfg.TLS}
		return td.DialContext(ctx, "tcp", f.cfg.Address)
	case "udp":
		return d.DialContext(ctx, "udp", f.cfg.Address)
	default:
		return d.DialContext(ctx, "tcp", f.cfg.Address)
	}
}

func (f *Forwarder) write(conn net.Conn, q queued) error {
	msg, err := format(f.cfg.Hostname, q.e, q.truncated)
	if err != nil {
		return err
	}
	if f.cfg.Network != "udp" {
		// Octet counting (RFC 5425 §4.3, RFC 6587 §3.4.1): a message may
		// then carry a newline, which a details field can.
		msg = append([]byte(strconv.Itoa(len(msg))+" "), msg...)
	}
	if err := conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return err
	}
	_, err = conn.Write(msg)
	return err
}

// record is the forwarded form of an entry: every field the chain signs, so
// a receiver holding the signature key can verify the copy.
type record struct {
	audit.AuditEntry
	DetailsTruncated bool `json:"detailsTruncated,omitzero"`
}

// Format renders e as one RFC 5424 message whose MSG is the entry as JSON.
func Format(host string, e audit.AuditEntry) ([]byte, error) {
	return format(host, e, false)
}

func format(host string, e audit.AuditEntry, truncated bool) ([]byte, error) {
	body, err := json.Marshal(record{AuditEntry: e, DetailsTruncated: truncated})
	if err != nil {
		return nil, errors.Join(errors.New("audit forwarding: encode entry"), err)
	}
	sev := severityNotice
	if e.UserID == "system" {
		sev = severityInfo
	}
	ts := e.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	head := fmt.Sprintf("<%d>1 %s %s gateon - audit - ", facilityLogAudit*8+sev,
		ts.UTC().Format(time.RFC3339Nano), host)
	return append([]byte(head), body...), nil
}
