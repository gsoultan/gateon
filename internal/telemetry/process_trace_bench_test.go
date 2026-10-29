// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"net/http"
	"net/url"
	"testing"
)

// benchTraceURL and the headers below are BenchmarkGatewayChain's request: a
// browser's GET with a cookie, answered with a JSON body.
var benchTraceURL = url.URL{Scheme: "http", Host: "gateway.test", Path: "/bench/items", RawQuery: "page=2"}

var (
	benchTraceReqHeader = http.Header{
		"User-Agent":   {"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/128.0 Safari/537.36"},
		"Accept":       {"application/json"},
		"Cookie":       {"theme=dark; _ga=GA1.2.3"},
		"X-Request-Id": {"01JBENCH0000000000000000"},
	}
	benchTraceRespHeader = http.Header{"Content-Type": {"application/json"}}
)

// fillBenchTrace sets on tr what RecordRequestTrace sets for the request
// above when the recorder leaves the operation name and URI to the store.
func fillBenchTrace(tr *TraceRecord) {
	tr.ID = "01JBENCH0000000000000000"
	tr.Method, tr.Path = http.MethodGet, "/bench/items"
	tr.deriveOperation = true
	tr.uriHost, tr.url, tr.deriveURI = "http://gateway.test", benchTraceURL, true
	tr.rawReqHeader, tr.rawRespHeader, tr.headerBuf = snapshotHeaders(tr.headerBuf, benchTraceReqHeader, benchTraceRespHeader)
}

// BenchmarkProcessTrace is what the store's goroutine spends turning one
// recorded trace into what it stores: the derived operation name and URI, the
// formatted header blocks, and their redaction. The request goroutine does
// not pay it, but at the default sampling every request does cause it, on a
// single goroutine that every trace goes through.
func BenchmarkProcessTrace(b *testing.B) {
	s := &pathStatsStore{}
	b.ReportAllocs()
	for b.Loop() {
		tr := GetTraceRecord()
		fillBenchTrace(tr)
		s.processTrace(tr)
		tr.Reset()
		tracePool.Put(tr)
	}
}
