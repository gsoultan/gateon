package logger

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"sync"
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
var L *SlogShim = &SlogShim{l: slog.Default()}

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
		return &SlogShim{l: slog.Default()}
	}
	return L
}

type SlogShim struct {
	l *slog.Logger
}

func (s *SlogShim) Write(p []byte) (n int, err error) {
	if s == nil || s.l == nil {
		slog.Info(string(p))
		return len(p), nil
	}
	s.l.Info(string(p))
	return len(p), nil
}

// Zerolog-compatible methods
func (s *SlogShim) Info() *Event {
	l := slog.Default()
	if s != nil && s.l != nil {
		l = s.l
	}
	return getEvent(l, slog.LevelInfo)
}
func (s *SlogShim) Error() *Event {
	l := slog.Default()
	if s != nil && s.l != nil {
		l = s.l
	}
	return getEvent(l, slog.LevelError)
}
func (s *SlogShim) Debug() *Event {
	l := slog.Default()
	if s != nil && s.l != nil {
		l = s.l
	}
	return getEvent(l, slog.LevelDebug)
}
func (s *SlogShim) Warn() *Event {
	l := slog.Default()
	if s != nil && s.l != nil {
		l = s.l
	}
	return getEvent(l, slog.LevelWarn)
}
func (s *SlogShim) Fatal() *Event {
	l := slog.Default()
	if s != nil && s.l != nil {
		l = s.l
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
	if s == nil || s.l == nil {
		slog.Info(msg, args...)
		return
	}
	s.l.Info(msg, args...)
}
func (s *SlogShim) LogError(msg string, args ...any) {
	if s == nil || s.l == nil {
		slog.Error(msg, args...)
		return
	}
	s.l.Error(msg, args...)
}
func (s *SlogShim) LogWarn(msg string, args ...any) {
	if s == nil || s.l == nil {
		slog.Warn(msg, args...)
		return
	}
	s.l.Warn(msg, args...)
}
func (s *SlogShim) LogDebug(msg string, args ...any) {
	if s == nil || s.l == nil {
		slog.Debug(msg, args...)
		return
	}
	s.l.Debug(msg, args...)
}

func (s *SlogShim) IsEnabled(level slog.Level) bool {
	if s == nil || s.l == nil {
		return false
	}
	return s.l.Enabled(context.Background(), level)
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
	ch := make(chan string, 100)
	lb.subscribers[ch] = struct{}{}
	hist := make([]string, len(lb.history))
	copy(hist, lb.history)
	return ch, hist
}

func (lb *LogBroadcast) Unsubscribe(ch chan string) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	delete(lb.subscribers, ch)
	close(ch)
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
	opts := &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey && !a.Value.Time().IsZero() {
				a.Value = slog.StringValue(a.Value.Time().Format(time.RFC3339))
			}
			return a
		},
	}
	var handler slog.Handler
	if prod {
		handler = slog.NewJSONHandler(io.MultiWriter(os.Stdout, Broadcaster), opts)
	} else {
		handler = slog.NewTextHandler(io.MultiWriter(os.Stdout, Broadcaster), opts)
	}
	L = &SlogShim{l: slog.New(handler)}
	slog.SetDefault(L.l)
	return nil
}

func Sync() {}

func IsProd() bool {
	return os.Getenv("ENV") == "production"
}

func Fatal(msg string, args ...any) {
	if L != nil && L.l != nil {
		L.l.Error(msg, args...)
	} else {
		slog.Error(msg, args...)
	}
	os.Exit(1)
}
