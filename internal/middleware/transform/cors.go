// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package transform

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gsoultan/gateon/internal/alerting"
	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/rs/cors"
	"go.opentelemetry.io/otel/trace"
)

// CORSConfig defines the configuration for the CORS middleware.
type CORSConfig struct {
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	ExposedHeaders   []string
	AllowCredentials bool
	MaxAge           int
	Debug            bool
	// DenyAllOrigins grants no origin cross-origin access. rs/cors reads an
	// empty AllowedOrigins as "every origin", so an empty list cannot say
	// "none" on its own.
	DenyAllOrigins bool
}

// corsOptions maps a CORSConfig onto the rs/cors options struct. Extracted so
// that EvaluateCORS judges a request with exactly the options the served
// middleware is built from: a second mapping is how the Diagnostics validator
// drifted away from what the proxy enforces in the first place.
func corsOptions(cfg CORSConfig) cors.Options {
	o := cors.Options{
		AllowedOrigins:   cfg.AllowedOrigins,
		AllowedMethods:   cfg.AllowedMethods,
		AllowedHeaders:   cfg.AllowedHeaders,
		ExposedHeaders:   cfg.ExposedHeaders,
		AllowCredentials: cfg.AllowCredentials,
		MaxAge:           cfg.MaxAge,
		Debug:            cfg.Debug,
	}
	if cfg.DenyAllOrigins {
		// AllowOriginFunc takes precedence over AllowedOrigins in rs/cors.
		o.AllowOriginFunc = func(string) bool { return false }
	}
	return o
}

// CORS returns a middleware that handles Cross-Origin Resource Sharing (CORS).
func CORS(cfg CORSConfig) kind.Middleware {
	opts := corsOptions(cfg)
	// Built once. cors.New normalises the origin, method and header lists,
	// and doing that on every request allocated route-derivable state on the
	// hot path. A recording span still gets its own instance, because its
	// logger is bound to the span.
	base := cors.New(opts)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Context().Value(kind.CORSHandledContextKey) != nil {
				next.ServeHTTP(w, r)
				return
			}

			c := base
			if span := trace.SpanFromContext(r.Context()); span.IsRecording() {
				traced := opts
				traced.Debug = true
				traced.Logger = &spanLogger{span: span, rs: request.GetRequestState(r)}
				c = cors.New(traced)
			}

			// Detect invalid CORS request. The library's own matcher decides,
			// so a wildcard pattern such as https://*.example.com is judged
			// here the same way it is on the response; the exact-match helper
			// this used reported every request from such an origin as a
			// violation while the response allowed it.
			if origin := r.Header.Get("Origin"); origin != "" && !c.OriginAllowed(r) {
				reportCORSViolation(r, origin, cfg)
			}

			// Mark as handled for downstream middlewares
			wrappedNext := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r = r.WithContext(context.WithValue(r.Context(), kind.CORSHandledContextKey, true))
				next.ServeHTTP(w, r)
			})

			c.Handler(wrappedNext).ServeHTTP(w, r)
		})
	}
}

// DefaultCORS is the CORS policy of a route that attaches neither a cors nor a
// grpcweb middleware: the backend's own, and a permissive, credential-free
// default wherever the answer that comes back carries none.
//
// It decides when the response is committed, from the finished headers,
// because only then is it known whether the backend answered for itself. The
// entrypoint used to decide first, for every route, before one was chosen: it
// answered every preflight itself, so neither a route's cors middleware nor a
// backend's own CORS ever saw one, and it set Access-Control-Allow-Origin
// before proxying, so a backend's own header went out as a second value, which
// browsers refuse. See ADR-0015.
//
// Credentials are never allowed here. Reflecting an arbitrary Origin together
// with Access-Control-Allow-Credentials: true lets any page on the internet
// issue credentialed requests to the backend and read the replies. A route
// that needs credentials names its origins in a cors middleware; a backend that
// answers with its own headers is left alone.
func DefaultCORS() kind.Middleware {
	policy := cors.New(cors.Options{
		AllowOriginFunc: func(string) bool { return true },
		AllowedMethods:  defaultCORSMethods(),
		AllowedHeaders:  []string{"*"},
		ExposedHeaders: []string{
			"Grpc-Status", "Grpc-Message", "Grpc-Encoding",
			"Grpc-Accept-Encoding", "X-Grpc-Web", "X-Accept-Content-Transfer-Encoding",
			"X-Accept-Response-Streaming", kind.HeaderAuthorization, "Content-Type",
		},
		AllowCredentials: false,
		MaxAge:           86400,
	})

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Origin") == "" {
				// Not a CORS request, but the answer to one would differ, so a
				// cache between here and the browser must not hand this
				// response to one.
				addVaryOrigin(w.Header())
				next.ServeHTTP(w, r)
				return
			}
			dw := &defaultCORSWriter{ResponseWriter: w, r: r, policy: policy, preflight: kind.IsCorsPreflight(r)}
			next.ServeHTTP(dw, r)
			// A handler that returns without writing gets an implicit 200 from
			// the server, below this writer; commit it here instead.
			if !dw.committed && !dw.hijacked {
				dw.WriteHeader(http.StatusOK)
			}
		})
	}
}

// varyOrigin is shared, like rs/cors's own: its capacity is its length, so an
// append by anything downstream copies it rather than writing into it.
var varyOrigin = []string{"Origin"}

func addVaryOrigin(h http.Header) {
	if vary, ok := h["Vary"]; ok {
		h["Vary"] = append(vary, "Origin")
		return
	}
	h["Vary"] = varyOrigin
}

// preflightBodyHeaders describe a body, and an answered preflight has none.
var preflightBodyHeaders = [...]string{"Content-Length", "Content-Type", "Content-Encoding", "Transfer-Encoding"}

// defaultCORSWriter applies DefaultCORS when the response is committed.
//
// An answer that already carries Access-Control-Allow-Origin is downstream's
// own -- the backend's policy -- and goes out untouched. Otherwise an actual
// response gets the default policy's headers, and a preflight is answered by
// the default policy instead: an answer with no CORS headers is no answer to
// the browser's question, whatever its status, and before this the gateway
// answered every preflight without asking the backend at all.
type defaultCORSWriter struct {
	http.ResponseWriter
	r         *http.Request
	policy    *cors.Cors
	preflight bool
	committed bool
	hijacked  bool
	// answered is set once a preflight has been answered here; what
	// downstream writes after that is discarded.
	answered bool
}

func (w *defaultCORSWriter) commit() {
	if w.committed {
		return
	}
	w.committed = true
	h := w.Header()
	if h.Get("Access-Control-Allow-Origin") != "" {
		return
	}
	if w.preflight {
		for _, k := range preflightBodyHeaders {
			h.Del(k)
		}
		w.answered = true
	}
	w.policy.HandlerFunc(headerSink{h}, w.r)
}

func (w *defaultCORSWriter) WriteHeader(code int) {
	// An informational response is not the response; its headers go out on
	// their own and the final ones are still being assembled.
	if code >= http.StatusOK {
		w.commit()
		if w.answered {
			code = http.StatusNoContent
		}
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *defaultCORSWriter) Write(b []byte) (int, error) {
	if !w.committed {
		w.WriteHeader(http.StatusOK)
	}
	if w.answered {
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}

// Flush commits first, since flushing is what puts the headers on the wire.
func (w *defaultCORSWriter) Flush() {
	if !w.committed {
		w.WriteHeader(http.StatusOK)
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the underlying writer for the
// controls this wrapper does not forward itself, such as write deadlines.
func (w *defaultCORSWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Hijack forwards to the underlying writer. Browsers send Origin on every
// WebSocket handshake, so every browser WebSocket on a route without a cors
// middleware passes through this writer, and the proxy needs the connection.
func (w *defaultCORSWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := w.ResponseWriter.(http.Hijacker); ok {
		conn, rw, err := hj.Hijack()
		w.hijacked = err == nil
		return conn, rw, err
	}
	return nil, nil, http.ErrNotSupported
}

// headerSink hands rs/cors a response whose headers are the real ones and
// whose status and body go nowhere, so the policy can write its headers into a
// response that is still being assembled. A single-map struct fits in an
// interface without allocating.
type headerSink struct{ h http.Header }

func (s headerSink) Header() http.Header       { return s.h }
func (headerSink) Write(b []byte) (int, error) { return len(b), nil }
func (headerSink) WriteHeader(int)             {}

// corsRouteID resolves the identifier of the route that handled the request.
// The matched route's ID is preferred because it is what the remediation API
// looks up; RouteName is only a display label and may hold the entrypoint
// fallback when the route has no name.
func corsRouteID(rs *request.RequestState) string {
	if rs == nil {
		return ""
	}
	if route, ok := rs.MatchedRoute.(interface{ GetId() string }); ok && route.GetId() != "" {
		return route.GetId()
	}
	return rs.RouteName
}

func reportCORSViolation(r *http.Request, origin string, cfg CORSConfig) {
	routeID := corsRouteID(request.GetRequestState(r))

	threat := telemetry.SecurityThreat{
		ID:             uuid.New().String(),
		Type:           "cors_violation",
		Category:       "security",
		Severity:       kind.SeverityMedium,
		SourceIP:       request.GetClientIP(r, false),
		RequestURI:     r.RequestURI,
		RouteID:        routeID,
		Details:        fmt.Sprintf("Invalid CORS request from origin: %s. Allowed origins: %v", origin, cfg.AllowedOrigins),
		Time:           time.Now(),
		UserAgent:      r.UserAgent(),
		Method:         r.Method,
		Recommendation: "Verify if this origin should be allowed in the CORS configuration for this route.",
	}

	threat = telemetry.RecordSecurityThreatWithJA4(r, threat)
	telemetry.RecordSecurityThreat(threat)
	alerting.HandleThreat(&threat)
}

// defaultCORSMethods returns the method list used by every built-in CORS
// preset. A function rather than a package-level slice: the value is handed to
// per-route configs that may append to it, and a shared backing array would let
// one route's edit surface on another.
func defaultCORSMethods() []string {
	return []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"}
}
