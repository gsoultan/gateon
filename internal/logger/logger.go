// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package logger

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Logger defines the minimal logging interface for dependency injection.
type Logger interface {
	LogDebug(msg string, args ...any)
	LogInfo(msg string, args ...any)
	LogWarn(msg string, args ...any)
	LogError(msg string, args ...any)
}

// L is the global logger instance.
var L = newShim(slog.Default())

var eventPool = sync.Pool{
	New: func() any {
		return &Event{
			args: make([]any, 0, 16),
		}
	},
}

func getEvent(l *slog.Logger, level slog.Level) *Event {
	e := eventPool.Get().(*Event)
	e.l = l
	e.level = level
	e.isFatal = false
	e.args = e.args[:0]
	return e
}

// Default returns the global logger.
func Default() Logger {
	if L == nil {
		return newShim(slog.Default())
	}
	return L
}

// SlogShim adapts slog to the Logger interface.
//
// The inner logger is held in an atomic.Pointer rather than a plain field, and
// the package-level L is never reassigned. cmd/gateon configures logging twice
// on every boot -- once before reading the config file and once after -- and by
// the second call the pprof goroutine is already logging. Swapping the L
// pointer there was an unsynchronised write against every reader in the
// process; swapping the value inside a fixed shim is not.
type SlogShim struct {
	p atomic.Pointer[slog.Logger]
}

// get returns the current logger, falling back to slog's default so a shim used
// before Init never panics on a nil dereference.
func (s *SlogShim) get() *slog.Logger {
	if s == nil {
		return slog.Default()
	}
	if l := s.p.Load(); l != nil {
		return l
	}
	return slog.Default()
}

// set installs a new logger. Callers keep whatever *SlogShim they already hold.
func (s *SlogShim) set(l *slog.Logger) { s.p.Store(l) }

// newShim builds a shim around l.
func newShim(l *slog.Logger) *SlogShim {
	s := &SlogShim{}
	s.set(l)
	return s
}

func (s *SlogShim) Write(p []byte) (n int, err error) {
	if s == nil {
		slog.Info(string(p))
		return len(p), nil
	}
	s.get().Info(string(p))
	return len(p), nil
}

// Zerolog-compatible methods
func (s *SlogShim) Info() *Event {
	l := slog.Default()
	if s != nil {
		l = s.get()
	}
	return getEvent(l, slog.LevelInfo)
}
func (s *SlogShim) Error() *Event {
	l := slog.Default()
	if s != nil {
		l = s.get()
	}
	return getEvent(l, slog.LevelError)
}
func (s *SlogShim) Debug() *Event {
	l := slog.Default()
	if s != nil {
		l = s.get()
	}
	return getEvent(l, slog.LevelDebug)
}
func (s *SlogShim) Warn() *Event {
	l := slog.Default()
	if s != nil {
		l = s.get()
	}
	return getEvent(l, slog.LevelWarn)
}
func (s *SlogShim) Fatal() *Event {
	l := slog.Default()
	if s != nil {
		l = s.get()
	}
	e := getEvent(l, slog.LevelError)
	e.isFatal = true
	return e
}

type Event struct {
	l       *slog.Logger
	level   slog.Level
	args    []any
	isFatal bool
}

func (e *Event) Str(k, v string) *Event               { e.args = append(e.args, k, v); return e }
func (e *Event) Int(k string, v int) *Event           { e.args = append(e.args, k, v); return e }
func (e *Event) Int32(k string, v int32) *Event       { e.args = append(e.args, k, v); return e }
func (e *Event) Int64(k string, v int64) *Event       { e.args = append(e.args, k, v); return e }
func (e *Event) Float64(k string, v float64) *Event   { e.args = append(e.args, k, v); return e }
func (e *Event) Bool(k string, v bool) *Event         { e.args = append(e.args, k, v); return e }
func (e *Event) Err(err error) *Event                 { e.args = append(e.args, "error", err); return e }
func (e *Event) Interface(k string, v any) *Event     { e.args = append(e.args, k, v); return e }
func (e *Event) Strs(k string, v []string) *Event     { e.args = append(e.args, k, v); return e }
func (e *Event) Dur(k string, v time.Duration) *Event { e.args = append(e.args, k, v); return e }

func (e *Event) Msg(msg string) {
	if e == nil || e.l == nil {
		return
	}
	e.l.Log(context.Background(), e.level, msg, e.args...)
	isFatal := e.isFatal
	eventPool.Put(e)
	if isFatal {
		os.Exit(1)
	}
}

func (e *Event) Msgf(format string, v ...any) {
	if e == nil || e.l == nil {
		return
	}
	e.l.Log(context.Background(), e.level, fmt.Sprintf(format, v...), e.args...)
	isFatal := e.isFatal
	eventPool.Put(e)
	if isFatal {
		os.Exit(1)
	}
}

// Now for the Logger interface (DI)
func (s *SlogShim) LogInfo(msg string, args ...any) {
	if s == nil {
		slog.Info(msg, args...)
		return
	}
	s.get().Info(msg, args...)
}
func (s *SlogShim) LogError(msg string, args ...any) {
	if s == nil {
		slog.Error(msg, args...)
		return
	}
	s.get().Error(msg, args...)
}
func (s *SlogShim) LogWarn(msg string, args ...any) {
	if s == nil {
		slog.Warn(msg, args...)
		return
	}
	s.get().Warn(msg, args...)
}
func (s *SlogShim) LogDebug(msg string, args ...any) {
	if s == nil {
		slog.Debug(msg, args...)
		return
	}
	s.get().Debug(msg, args...)
}

// LogAttrs logs msg at level with typed attributes. Unlike the Log* methods it
// boxes nothing: each argument to those is converted to an interface, which
// allocates for every string, and a line written per request -- the access log
// -- paid that once per field.
func (s *SlogShim) LogAttrs(ctx context.Context, level slog.Level, msg string, attrs ...slog.Attr) {
	s.get().LogAttrs(ctx, level, msg, attrs...)
}

func (s *SlogShim) IsEnabled(level slog.Level) bool {
	if s == nil {
		return false
	}
	return s.get().Enabled(context.Background(), level)
}

type LogBroadcast struct {
	mu          sync.Mutex
	subscribers map[chan string]struct{}
	history     []string
	maxHistory  int
}

var Broadcaster = &LogBroadcast{
	subscribers: make(map[chan string]struct{}),
	history:     make([]string, 0, 100),
	maxHistory:  100,
}

func (lb *LogBroadcast) Subscribe() (chan string, []string) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	ch := make(chan string, 1000)
	lb.subscribers[ch] = struct{}{}
	hist := make([]string, len(lb.history))
	copy(hist, lb.history)
	return ch, hist
}

func (lb *LogBroadcast) Unsubscribe(ch chan string) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	if _, ok := lb.subscribers[ch]; ok {
		delete(lb.subscribers, ch)
		close(ch)
	}
}

func (lb *LogBroadcast) Write(p []byte) (n int, err error) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	msg := string(p)
	lb.history = append(lb.history, msg)
	if len(lb.history) > lb.maxHistory {
		lb.history = lb.history[1:]
	}
	for ch := range lb.subscribers {
		select {
		case ch <- msg:
		default:
		}
	}
	return len(p), nil
}

type FilteredHandshakeWriter struct {
	Out     io.Writer
	OnError func(remoteAddr, err string)
}

func (w *FilteredHandshakeWriter) Write(p []byte) (n int, err error) {
	if bytes.Contains(p, []byte("http: TLS handshake error")) {
		msg := string(p)
		if bytes.Contains(p, []byte("EOF")) {
			if w.OnError != nil {
				w.OnError("", msg)
			}
			return len(p), nil
		}
		if w.OnError != nil {
			w.OnError("", msg)
		}
	}
	return w.Out.Write(p)
}

func NewFilteredHandshakeLogger(out io.Writer, onError func(string, string)) *log.Logger {
	return log.New(&FilteredHandshakeWriter{Out: out, OnError: onError}, "", 0)
}

func Init(prod bool) error {
	level := slog.LevelInfo
	if !prod {
		level = slog.LevelDebug
	}
	return initInternal(level, prod)
}

// resolveJSONOutput decides the log encoding.
//
// The handler used to be chosen by ENV=production alone, so log.format was in
// the schema and rendered in the dashboard while an operator who asked for JSON
// got text — and a log pipeline parsing JSON got nothing it could read.
//
// An explicit format wins because it is the most specific thing the operator
// said. Failing that, development means text, and otherwise the previous
// ENV-derived behaviour stands, so an install that sets neither sees no change.
func resolveJSONOutput(format string, development, prod bool) bool {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "json":
		return true
	case "text":
		return false
	}
	if development {
		return false
	}
	return prod
}

// InitWithConfig configures level only, leaving the encoding to ENV.
//
// Deprecated: prefer InitWithOptions, which also honours log.format and
// log.development. Kept for callers that have no config to pass.
func InitWithConfig(confLevel string, prod bool) error {
	return InitWithOptions(confLevel, "", false, prod)
}

// InitWithOptions configures the logger from the log settings.
func InitWithOptions(confLevel, format string, development, prod bool) error {
	level := slog.LevelInfo
	switch strings.ToLower(confLevel) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	return initInternal(level, resolveJSONOutput(format, development, prod))
}

// initInternal builds the handler. useJSON, rather than a "prod" flag, because
// the encoding is now a decision the caller has already made.
func initInternal(level slog.Level, useJSON bool) error {
	next := slog.New(NewHandler(io.MultiWriter(os.Stdout, Broadcaster), level, useJSON))
	// In place: rebinding L would race every goroutine already logging.
	L.set(next)
	slog.SetDefault(next)
	return nil
}

// NewHandler is the handler Init installs, writing to w: JSON or text at
// level, with the time as RFC 3339. Exported so a benchmark can price a log
// line as production writes it rather than as slog's defaults would.
func NewHandler(w io.Writer, level slog.Level, useJSON bool) slog.Handler {
	opts := &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			switch {
			case a.Key == slog.TimeKey:
				// Kind first: Value.Time panics on anything else, and a
				// caller's own attribute may be named "time".
				if a.Value.Kind() == slog.KindTime && !a.Value.Time().IsZero() {
					a.Value = slog.StringValue(a.Value.Time().Format(time.RFC3339))
				}
			case a.Key == slog.LevelKey && len(groups) == 0:
				// With a ReplaceAttr installed, slog hands the level over as
				// an Any, and the JSON handler then encodes it through
				// encoding/json and reflection on every line. Its text is
				// what that produced, and for the four levels a constant.
				if l, ok := a.Value.Any().(slog.Level); ok {
					a.Value = slog.StringValue(l.String())
				}
			}
			return a
		},
	}
	if useJSON {
		return slog.NewJSONHandler(w, opts)
	}
	return slog.NewTextHandler(w, opts)
}

func Sync() {}

func IsProd() bool {
	return os.Getenv("ENV") == "production"
}

func Fatal(msg string, args ...any) {
	// get() falls back to slog's default, so this needs no nil dance.
	L.get().Error(msg, args...)
	os.Exit(1)
}
