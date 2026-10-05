// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package request

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// RequestStateContextKey is the type used for values stored in a request's context.
type RequestStateContextKey struct{}

var RequestStatePool = sync.Pool{
	New: func() any {
		return &RequestState{}
	},
}

// RequestState holds mutable request-scoped data to avoid multiple context allocations.
type RequestState struct {
	EntryPointID     string
	RouteName        string
	IsManagement     bool
	MatchedRoute     any // avoids circular dependency with proto
	DebugInfo        *DebugInfo
	RequestID        string
	ForwardedProto   string
	StrippedHost     string
	ClientRemoteAddr string
	ClientCountry    string
	Fingerprint      any
	JA4              string
	JA4H             string
	JA4Plus          string

	// ResolvedClientIP is the trust-aware client address, memoised. Resolving it
	// walks the forwarding headers and consults the trust setting, and several
	// middlewares on one request need it.
	ResolvedClientIP string

	// ReputationID is the identity a reputation score is recorded under and
	// enforced against: the client's class (repid.Class) scoped to its network. It is
	// cached here because several middlewares on one request ask for it (the
	// reputation blocker, proof-of-work, deception, the tarpit) and building it
	// allocates. See repid.For for why it is a pair.
	ReputationID   string
	Recommendation string
	Reputation     float64
	// Breakdown timings (nanoseconds for precision)
	TEntrypoint      int64
	TRoute           int64
	TMiddlewareStart int64
	TServiceStart    int64
	TServiceEnd      int64
	TMiddlewareEnd   int64

	// Deduplication tracking to avoid redundant security checks
	ExecutedWAFs    []string // config fingerprints
	ExecutedEntropy bool     // Shannon entropy check result already recorded?
	ExecutedXSS     bool     // XSS recognition already recorded?
	ExecutedSQLI    bool     // SQLi recognition already recorded?
	// RecordedRequest is set by the first Metrics middleware to record the
	// statistics that do not depend on its route label -- path, domain,
	// country, protocol, per-IP -- so the entrypoint's and the route's do not
	// both count one request.
	RecordedRequest bool
	// AccessLogged is set by the access logger nearest the request -- the
	// route's -- so the entrypoint's, which wraps it, does not log the same
	// request again. Set whether or not sampling kept the line, so an outer
	// logger does not resample what an inner one already decided.
	AccessLogged bool
	// CredentialsWithheld is set by the data-plane entry once it has withheld
	// the management plane's credentials from this request (ADR 0051), session
	// verification included, so the proxy's second line need not verify the
	// same Authorization value again.
	CredentialsWithheld bool
	// BlockLookupsUntil is when, in Unix nanoseconds, this request stops
	// waiting for block lookups: set by the first lookup that had to ask the
	// database, one lookup deadline ahead, so the lookups a request makes --
	// an address and a fingerprint, at the entrypoint and again at the route
	// -- wait one deadline in all, not one each (ADR 0054). Zero until then.
	BlockLookupsUntil int64
	// Refused is why the gateway itself refused the request, where the refusal
	// is one the brute-force detectors must not read as a guessed credential
	// (MarkRefused). Written only by the code that refused, never from
	// anything the client sent.
	Refused Refusal
}

// Refusal is why the gateway itself refused a request, as far as the
// detectors that count refused credential attempts need to know.
type Refusal uint8

const (
	// RefusalNone: nothing the gateway knows of. A 401 or 403 with no other
	// mark came from a credential check -- a login form, Basic auth -- or
	// from a backend, and counts as a refused attempt when it could be one.
	RefusalNone Refusal = iota
	// RefusalToken: the gateway's own verification refused a token the
	// request presented -- a session, a JWT, a PASETO, an API key, an
	// introspected OAuth2 token -- as invalid, expired or insufficient. A
	// client re-presenting a token it was issued is a session that ended,
	// not someone guessing a password (ADR 0031).
	RefusalToken
	// RefusalMitigation: the gateway refused the request because its address
	// is shunned, or its client build is blocked or out of reputation on its
	// network. No credential was checked. Counted as an attempt, a shunned
	// address's own refused POSTs renewed its shun from the shun's refusals
	// the moment it lapsed (ADR 0031).
	RefusalMitigation
	// RefusalAuthentication: the gateway's authentication refused the request
	// other than for a token it verified -- HTTP Basic refusing a password or
	// a request that presented none, the forward-auth service it asked
	// refusing, the management sign-in refusing a password or a second-factor
	// code. The one refusal the gateway writes that can be a guess
	// (CredentialChecked, ADR 0059).
	RefusalAuthentication
)

// String names the refusal as a trace records it: "" for none.
func (r Refusal) String() string {
	switch r {
	case RefusalToken:
		return "token"
	case RefusalMitigation:
		return "mitigation"
	case RefusalAuthentication:
		return "authentication"
	default:
		return ""
	}
}

// MarkRefused records on r's state why the gateway refused it. The refusing
// code calls it as it writes the refusal, and nothing else may: the mark tells
// the detectors whether a 401 or 403 was a credential attempt, so inferring it
// from what a request carries -- a header's presence -- would let a password
// guess exempt itself by adding one. Without request state nothing is marked,
// and the refusal counts as it did before.
func MarkRefused(r *http.Request, why Refusal) {
	MarkRefusedContext(r.Context(), why)
}

// MarkRefusedContext is MarkRefused for code that holds the request's context
// rather than the request: a handler the management API serves over REST,
// Connect and gRPC alike.
func MarkRefusedContext(ctx context.Context, why Refusal) {
	if rs := GetRequestStateFromContext(ctx); rs != nil {
		rs.Refused = why
	}
}

// CredentialChecked reports whether a 401 or 403 this request was answered
// with can have refused a credential: the request reached its service, whose
// answer the gateway cannot read into (a backend's login form), or the
// gateway's own authentication marked it refused (RefusalAuthentication).
//
// Every other refusal the gateway writes checked no credential. A geofence, a
// WAF, a trap, bot management, deception and TLS binding all answer 403 before
// the service, and a POST each of them refused counted towards a brute-force
// shun as a refused login (ADR 0059); so did the gateway's own token and
// mitigation refusals until they were marked (ADR 0031).
func (rs *RequestState) CredentialChecked() bool {
	switch rs.Refused {
	case RefusalAuthentication:
		return true
	case RefusalNone:
		return rs.TServiceStart > 0
	default:
		return false
	}
}

// ServiceBoundary is the last middleware of a route's chain, nearest its
// service. It stamps when every route middleware has passed the request on
// (TServiceStart) and when the service returned (TServiceEnd), so a request
// without TServiceStart was answered by the gateway itself (ADR 0048, 0059).
func ServiceBoundary(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rs := GetRequestState(r)
		if rs != nil {
			rs.TServiceStart = time.Now().UnixNano()
		}
		next.ServeHTTP(w, r)
		if rs != nil {
			rs.TServiceEnd = time.Now().UnixNano()
		}
	})
}

// DebugInfo captures request/response details for diagnostic tracing.
type DebugInfo struct {
	RequestHeaders  string
	RequestBody     string
	ResponseHeaders string
	ResponseBody    string
}

// GetRequestState returns the RequestState from the context, or nil if not set.
func GetRequestState(r *http.Request) *RequestState {
	return GetRequestStateFromContext(r.Context())
}

// GetRequestStateFromContext returns the RequestState from the context, or nil if not set.
func GetRequestStateFromContext(ctx context.Context) *RequestState {
	if val, ok := ctx.Value(RequestStateContextKey{}).(*RequestState); ok {
		return val
	}
	return nil
}

// WithState returns ctx carrying rs, the writer half of
// GetRequestStateFromContext. This package owns RequestStateContextKey and
// already exports WithCountry and WithID for the other two values it owns; the
// state key had a reader and no writer, so every caller that needed to inject
// one spelled out context.WithValue against the raw key itself.
func WithState(ctx context.Context, rs *RequestState) context.Context {
	return context.WithValue(ctx, RequestStateContextKey{}, rs)
}

// Reset clears the state for reuse.
func (rs *RequestState) Reset() {
	rs.EntryPointID = ""
	rs.RouteName = ""
	rs.IsManagement = false
	rs.MatchedRoute = nil
	rs.DebugInfo = nil
	rs.RequestID = ""
	rs.ForwardedProto = ""
	rs.StrippedHost = ""
	rs.ClientRemoteAddr = ""
	rs.ClientCountry = ""
	rs.Fingerprint = nil
	rs.JA4 = ""
	rs.JA4H = ""
	rs.JA4Plus = ""
	rs.ResolvedClientIP = ""
	rs.ReputationID = ""
	rs.Recommendation = ""
	rs.Reputation = 0
	rs.TEntrypoint = 0
	rs.TRoute = 0
	rs.TMiddlewareStart = 0
	rs.TServiceStart = 0
	rs.TServiceEnd = 0
	rs.TMiddlewareEnd = 0
	rs.ExecutedWAFs = nil
	rs.ExecutedEntropy = false
	rs.ExecutedXSS = false
	rs.ExecutedSQLI = false
	rs.RecordedRequest = false
	rs.AccessLogged = false
	rs.CredentialsWithheld = false
	rs.BlockLookupsUntil = 0
	rs.Refused = RefusalNone
}
