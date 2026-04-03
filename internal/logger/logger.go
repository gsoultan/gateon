package logger

import (
	"bytes"
	"io"
	"log"
	"os"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// Logger defines the minimal logging interface for dependency injection (Dependency Inversion).
// Implementations can be swapped for testing or alternative backends.
type Logger interface {
	Info() *zerolog.Event
	Error() *zerolog.Event
	Debug() *zerolog.Event
	Fatal() *zerolog.Event
}

// zerologAdapter adapts *zerolog.Logger to Logger (zerolog uses pointer receivers).
type zerologAdapter struct{ *zerolog.Logger }

// L is the global logger instance.
var L zerolog.Logger

// Default returns the global logger as Logger interface (for injection).
func Default() Logger {
	return &zerologAdapter{&L}
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
	// Return a copy of the history
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

	// Add to history (newest first for UI, but let's keep it chronologically in buffer)
	// UI does `[event.data, ...prev]` so newest is at start.
	// Let's store newest at end of buffer.
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

// FilteredHandshakeWriter wraps an io.Writer and filters out TLS handshake EOF errors.
// These are common from probes or clients that disconnect abruptly during handshake.
type FilteredHandshakeWriter struct {
	Out io.Writer
}

func (w *FilteredHandshakeWriter) Write(p []byte) (n int, err error) {
	if bytes.Contains(p, []byte("http: TLS handshake error")) && bytes.Contains(p, []byte("EOF")) {
		return len(p), nil
	}
	return w.Out.Write(p)
}

// NewFilteredHandshakeLogger returns a log.Logger that filters out TLS handshake EOF errors.
func NewFilteredHandshakeLogger(out io.Writer) *log.Logger {
	return log.New(&FilteredHandshakeWriter{Out: out}, "", 0)
}

func Init(prod bool) error {
	zerolog.TimeFieldFormat = time.RFC3339

	var output io.Writer
	if prod {
		output = os.Stdout
	} else {
		output = zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}
	}

	// Use multi-writer to send logs to stdout and our broadcaster
	multi := zerolog.MultiLevelWriter(output, Broadcaster)

	level := zerolog.InfoLevel
	if !prod {
		level = zerolog.DebugLevel
	}

	L = zerolog.New(multi).With().Timestamp().Logger().Level(level)
	return nil
}

func Sync() {
	// zerolog doesn't have a Sync method like zap, but we keep it for compatibility
}

func IsProd() bool {
	return os.Getenv("ENV") == "production"
}
