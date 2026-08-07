// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

// Command backend is a tiny echo server for the dev environment. It stands in
// for a real upstream so `scripts/dev.sh` has something to proxy to: it reports
// which backend answered, the method and path it saw, and the headers gateon
// forwarded, which is enough to watch routing, header middleware, and stripprefix
// take effect.
//
//	go run ./dev/backend -name whoami -addr 127.0.0.1:9001
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
)

func main() {
	name := flag.String("name", envOr("GATEON_DEV_BACKEND_NAME", "backend"), "backend identifier reported in responses")
	addr := flag.String("addr", envOr("GATEON_DEV_BACKEND_ADDR", "127.0.0.1:9001"), "host:port to listen on")
	flag.Parse()

	mux := http.NewServeMux()

	// A dedicated health endpoint so gateon's health checks have a cheap target.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		headers := make(map[string]string, len(r.Header))
		names := make([]string, 0, len(r.Header))
		for k := range r.Header {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			headers[k] = r.Header.Get(k)
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Backend", *name)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"backend":  *name,
			"method":   r.Method,
			"path":     r.URL.Path,
			"query":    r.URL.RawQuery,
			"remote":   r.RemoteAddr,
			"host":     r.Host,
			"headers":  headers,
			"received": true,
		})
		log.Printf("[%s] %s %s", *name, r.Method, r.URL.RequestURI())
	})

	log.Printf("dev backend %q listening on http://%s", *name, *addr)
	srv := &http.Server{Addr: *addr, Handler: mux}
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "backend %q: %v\n", *name, err)
		os.Exit(1)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
