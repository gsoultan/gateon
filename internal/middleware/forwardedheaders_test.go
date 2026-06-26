package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/request"
)

func TestForwardedHeaders(t *testing.T) {
	tests := []struct {
		name         string
		proto        string
		trustForward bool
		inboundXFP   string
		want         string // expected request.Scheme observed downstream
	}{
		{name: "explicit https override", proto: "https", want: "https"},
		{name: "explicit http override", proto: "http", want: "http"},
		{name: "invalid proto ignored, no trust", proto: "ftp", want: "http"},
		{name: "trust inbound https", trustForward: true, inboundXFP: "https", want: "https"},
		{name: "trust inbound invalid falls back", trustForward: true, inboundXFP: "ftp", want: "http"},
		{name: "explicit override beats inbound", proto: "https", trustForward: true, inboundXFP: "http", want: "https"},
		{name: "no config is no-op", want: "http"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got string
			next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				got = request.Scheme(r)
			})

			mw := ForwardedHeaders(ForwardedHeadersConfig{
				Proto:              tc.proto,
				TrustForwardHeader: tc.trustForward,
			})

			r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
			// Untrusted-by-default peer so only the override path can set https.
			r.RemoteAddr = "1.2.3.4:1111"
			if tc.inboundXFP != "" {
				r.Header.Set(request.HeaderXForwardedProto, tc.inboundXFP)
			}

			mw(next).ServeHTTP(httptest.NewRecorder(), r)

			if got != tc.want {
				t.Errorf("%s: downstream scheme = %q; want %q", tc.name, got, tc.want)
			}
		})
	}
}
