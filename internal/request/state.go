// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package request

import (
	"context"
	"net/http"
	"sync"
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
	Recommendation   string
	Reputation       float64
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
}
