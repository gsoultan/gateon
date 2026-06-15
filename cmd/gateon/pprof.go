package main

import (
	"context"
	"net/http"
	"net/http/pprof"
	"os"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
)

// pprofEnvAddr is the environment variable that opts into the runtime profiling
// server. It is intentionally OFF by default: exposing pprof publicly leaks
// internal state and is a denial-of-service vector, so operators must
// explicitly bind it (preferably to a loopback address, e.g. "127.0.0.1:6060").
const pprofEnvAddr = "GATEON_PPROF_ADDR"

// startPprofServer launches the net/http/pprof endpoints on a dedicated mux when
// GATEON_PPROF_ADDR is set. The server is shut down when ctx is cancelled.
//
// Security: pprof is served on its own listener (never the public proxy/API
// listeners) so it can be bound to localhost only and kept off production
// ingress paths.
func startPprofServer(ctx context.Context) {
	addr := os.Getenv(pprofEnvAddr)
	if addr == "" {
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		logger.L.LogWarn("pprof profiling server enabled — do not expose publicly", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.L.LogError("pprof server failed", "error", err)
		}
	}()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
}
