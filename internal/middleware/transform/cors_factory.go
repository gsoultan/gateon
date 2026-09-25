// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package transform

import (
	"net/http"
	"strings"

	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/rs/cors"
)

const (
	corsHeaderAllowOrigin    = "Access-Control-Allow-Origin"
	corsHeaderRequestHeaders = "Access-Control-Request-Headers"
)

func NewCORS(cfg map[string]string) (kind.Middleware, error) {
	policy, err := CORSConfigFromMap(cfg)
	if err != nil {
		return nil, err
	}
	return CORS(policy), nil
}

// CORSConfigFromMap derives the effective CORS policy from a raw middleware
// config map: the factory's own list parsing, then the preset overlay.
//
// Exported so the Diagnostics validator can ask for the policy the proxy will
// actually run with instead of re-reading the config map by hand. Missing the
// `preset` key was one of the ways that hand-rolled second reading disagreed
// with this one.
// It reports a malformed value rather than defaulting past it. The Diagnostics
// validator derives its answer from here too, and telling an operator what the
// proxy "would do" from a config the proxy refuses to build is the same lie as
// a dashboard showing a setting the gateway never read.
func CORSConfigFromMap(cfg map[string]string) (CORSConfig, error) {
	maxAge, err := kind.ParseIntStrict(cfg["max_age"], 0)
	if err != nil {
		return CORSConfig{}, kind.CfgError("max_age", cfg["max_age"], err)
	}

	allowCredentials, err := kind.ParseBoolStrict(cfg["allow_credentials"], false)
	if err != nil {
		return CORSConfig{}, kind.CfgError("allow_credentials", cfg["allow_credentials"], err)
	}
	base := CORSConfig{
		AllowedOrigins:   kind.ParseListStrict(cfg["allowed_origins"]),
		AllowedMethods:   kind.ParseListStrict(cfg["allowed_methods"]),
		AllowedHeaders:   kind.ParseListStrict(cfg["allowed_headers"]),
		ExposedHeaders:   kind.ParseListStrict(cfg["exposed_headers"]),
		AllowCredentials: allowCredentials,
		MaxAge:           maxAge,
	}

	return ApplyCORSPreset(cfg, base), nil
}

// CORSDecision reports what the CORS middleware built from a raw config map
// would do with a request.
type CORSDecision struct {
	// Policy is the effective configuration after presets, with the fallbacks
	// rs/cors applies for an empty list filled in. It exists so a caller can
	// show an operator what is enforced; it is never what the verdict below is
	// computed from.
	Policy CORSConfig
	// Headers are the CORS response headers the proxy would send.
	Headers map[string]string
	// Allowed is the verdict a browser reads: a response carrying no
	// Access-Control-Allow-Origin is a blocked cross-origin request, for
	// preflights and actual requests alike.
	Allowed bool
	// IsPreflight reports whether the request is a CORS preflight.
	IsPreflight bool
	// OriginAllowed, MethodAllowed and HeadersAllowed name the check that
	// stopped the request. rs/cors runs them in that order and stops at the
	// first failure, so only the first false one is a cause.
	OriginAllowed  bool
	MethodAllowed  bool
	HeadersAllowed bool
}

// EvaluateCORS answers what the CORS middleware built from cfg would do with r,
// by putting r through the very rs/cors handler the factory installs. The
// Diagnostics validator used to re-derive the policy from cfg and compare by
// hand, and disagreed with the proxy about presets, empty origin lists, origin
// case, default allowed headers and wildcard origin patterns. There is now one
// derivation and one matcher.
//
// Unlike CORS(), a rejected origin records no security threat and raises no
// alert: an operator testing an origin from the dashboard must not write to the
// threat feed.
//
// A request with no Origin is not a CORS request; the proxy answers it with no
// CORS headers at all, so Allowed is false and the phase flags are meaningless.
// Callers handle that case before asking.
func EvaluateCORS(cfg map[string]string, r *http.Request) (CORSDecision, error) {
	policy, err := CORSConfigFromMap(cfg)
	if err != nil {
		return CORSDecision{}, err
	}
	c := cors.New(corsOptions(policy))

	d := CORSDecision{
		Policy:        corsEffectivePolicy(policy),
		IsPreflight:   kind.IsCorsPreflight(r),
		OriginAllowed: c.OriginAllowed(r),
	}
	d.Headers = corsResponseHeaders(c, r)
	d.Allowed = d.Headers[corsHeaderAllowOrigin] != ""
	d.MethodAllowed, d.HeadersAllowed = d.Allowed, d.Allowed

	if !d.Allowed && d.OriginAllowed && d.IsPreflight {
		// rs/cors answers yes or no, not which check stopped it. Asking again
		// without the requested headers separates a rejected method from a
		// rejected header without re-implementing either test.
		probe := r.Clone(r.Context())
		probe.Header.Del(corsHeaderRequestHeaders)
		d.MethodAllowed = corsResponseHeaders(c, probe)[corsHeaderAllowOrigin] != ""

		// HeadersAllowed answers "were the requested headers what caused this
		// denial", not "is everything fine" -- otherwise it is just Allowed
		// again, which is what it used to be. It was assigned from Allowed and
		// never recomputed, so a request refused for its *method* reported
		// "Headers check: FAILED (X not in [...])" about headers that were
		// perfectly acceptable, and the operator went and widened the header
		// list for nothing. That is the same mis-attribution the probe above
		// exists to prevent, on the other axis.
		//
		// If the probe passes, the method is fine and the headers are to
		// blame. If it still fails, the method is to blame and the headers are
		// not implicated -- we cannot tell whether they would also have been
		// refused, and claiming they were is worse than staying quiet.
		d.HeadersAllowed = !d.MethodAllowed
	}

	return d, nil
}

// corsEffectivePolicy fills in the fallbacks rs/cors applies when a list is
// empty, so a caller reporting the policy shows what is enforced rather than
// what was typed. Display only -- no verdict is derived from it, which is why
// restating the library's defaults here cannot reintroduce the drift.
func corsEffectivePolicy(cfg CORSConfig) CORSConfig {
	if len(cfg.AllowedOrigins) == 0 {
		cfg.AllowedOrigins = []string{"*"}
	}
	if len(cfg.AllowedMethods) == 0 {
		cfg.AllowedMethods = []string{http.MethodGet, http.MethodPost, http.MethodHead}
	}
	if len(cfg.AllowedHeaders) == 0 {
		cfg.AllowedHeaders = []string{kind.HeaderAccept, "Content-Type", "X-Requested-With"}
	}
	return cfg
}

// corsResponseHeaders runs r through c and returns the headers the proxy would
// answer with.
func corsResponseHeaders(c *cors.Cors, r *http.Request) map[string]string {
	rec := corsHeaderRecorder{header: make(http.Header)}
	c.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(&rec, r)

	out := make(map[string]string, len(rec.header))
	for k, v := range rec.header {
		out[k] = strings.Join(v, ", ")
	}
	return out
}

// corsHeaderRecorder is an http.ResponseWriter that keeps the response headers
// and discards everything else. httptest.ResponseRecorder would do the same,
// but it belongs to tests and buffers a body this never writes.
type corsHeaderRecorder struct{ header http.Header }

func (rec *corsHeaderRecorder) Header() http.Header         { return rec.header }
func (rec *corsHeaderRecorder) Write(b []byte) (int, error) { return len(b), nil }
func (rec *corsHeaderRecorder) WriteHeader(int)             {}
