// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
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

// pprofEnvAllowRemote, set to "true", lets GATEON_PPROF_ADDR name an address
// other than loopback -- for a container whose profile is fetched through a
// port-forward or a sidecar. Without it a non-loopback address is refused.
const pprofEnvAllowRemote = "GATEON_PPROF_ALLOW_REMOTE"

// errPprofNotLoopback is why a profiling address was refused.
var errPprofNotLoopback = errors.New("pprof address is not loopback")

// checkPprofAddr reports whether addr may serve the profiling endpoints. They
// have no authentication: /debug/pprof/cmdline returns the process arguments
// and /debug/pprof/profile holds a CPU busy for as long as the caller asks, so
// ":6060" -- every interface -- handed both to anyone who could reach the port
// (2026-11-20 audit, L7). Loopback is accepted, and anything else only when the
// operator says so a second time.
func checkPprofAddr(addr string, allowRemote bool) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%s=%q: %w", pprofEnvAddr, addr, err)
	}
	if allowRemote || host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("%s=%q: %w; bind 127.0.0.1 or set %s=true", pprofEnvAddr, addr, errPprofNotLoopback, pprofEnvAllowRemote)
}

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
	if err := checkPprofAddr(addr, os.Getenv(pprofEnvAllowRemote) == "true"); err != nil {
		logger.L.LogError("pprof profiling server not started", "error", err)
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

	// This goroutine is the shutdown linkage, not a leak of one: it exists to
	// wait on ctx and stop the server.
	//
	// #nosec G118 -- the context.Background() below is the parent of the
	// shutdown *deadline*, which deliberately must not be ctx. ctx has just been
	// cancelled at that point, so deriving the deadline from it would give
	// Shutdown an already-expired context and turn a graceful drain into an
	// immediate close.
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
}
