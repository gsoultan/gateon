// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	f, _ := os.OpenFile("/tmp/gateon_mock_backend.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND|os.O_SYNC, 0666)
	log.SetOutput(f)
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("Mock backend starting...")

	http.HandleFunc("/pgadmin4/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-pgadmin-version", "8.9")
		_, _ = w.Write([]byte("<html><body>pgAdmin 4</body></html>"))
	})

	http.HandleFunc("/synology/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "id=SYNO; Path=/")
		_, _ = w.Write([]byte("<html><body>Synology DSM</body></html>"))
	})

	http.HandleFunc("/grpc", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "grpc-status")
		w.WriteHeader(http.StatusOK)
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("DEBUG: Method=%s Path=%q Upgrade=%q Conn=%q\n", r.Method, r.URL.Path, r.Header.Get("Upgrade"), r.Header.Get("Connection"))

		// ?delay=<ms> holds the response open, so a test can keep a request
		// genuinely in-flight across a gateway shutdown and check it still
		// completes (graceful drain) rather than being reset.
		if d := r.URL.Query().Get("delay"); d != "" {
			if ms, err := strconv.Atoi(d); err == nil && ms > 0 {
				time.Sleep(time.Duration(ms) * time.Millisecond)
			}
		}

		isUpgrade := strings.EqualFold(r.Header.Get("Upgrade"), "websocket")

		if r.URL.Path == "/ws" && isUpgrade {
			log.Println("DEBUG: Handling WebSocket upgrade")
			hj, ok := w.(http.Hijacker)
			if !ok {
				log.Println("DEBUG: Hijacking not supported")
				http.Error(w, "hijacking not supported", http.StatusInternalServerError)
				return
			}

			conn, bufrw, err := hj.Hijack()
			if err != nil {
				log.Printf("DEBUG: Hijack failed: %v\n", err)
				http.Error(w, "hijack failed", http.StatusInternalServerError)
				return
			}
			defer conn.Close()

			_, _ = bufrw.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
			_, _ = bufrw.WriteString("Upgrade: websocket\r\n")
			_, _ = bufrw.WriteString("Connection: Upgrade\r\n")
			_, _ = bufrw.WriteString("\r\n")
			bufrw.Flush()

			log.Println("DEBUG: WebSocket connection established")
			for {
				line, err := bufrw.ReadString('\n')
				if err != nil {
					log.Printf("DEBUG: WebSocket read error: %v\n", err)
					break
				}
				_, _ = bufrw.WriteString("ECHO: " + line)
				bufrw.Flush()
			}
			return
		}

		log.Println("DEBUG: Handling as normal HTTP")

		headers := make(map[string]string)
		for k, v := range r.Header {
			headers[k] = v[0]
		}

		resp := map[string]interface{}{
			"message": "Hello from mock backend",
			"path":    r.URL.Path,
			"method":  r.Method,
			"headers": headers,
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8082"
	}
	fmt.Printf("Mock backend listening on :%s\n", port)
	// #nosec G114 -- dev mock backend; not the shipped server.
	_ = http.ListenAndServe(":"+port, nil)
}
