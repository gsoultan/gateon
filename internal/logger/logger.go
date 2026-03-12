package logger

import (
	"io"
	"os"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// L is the global logger instance
var L zerolog.Logger

type LogBroadcast struct {
	mu          sync.Mutex
	subscribers map[chan string]struct{}
}

var Broadcaster = &LogBroadcast{
	subscribers: make(map[chan string]struct{}),
}

func (lb *LogBroadcast) Subscribe() chan string {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	ch := make(chan string, 100)
	lb.subscribers[ch] = struct{}{}
	return ch
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
	for ch := range lb.subscribers {
		select {
		case ch <- msg:
		default:
		}
	}
	return len(p), nil
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
