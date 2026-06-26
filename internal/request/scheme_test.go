package request

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestScheme(t *testing.T) {
	mustPrefix := func(s string) netip.Prefix {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			t.Fatalf("bad cidr %q: %v", s, err)
		}
		return p
	}

	tests := []struct {
		name       string
		tls        bool
		remoteAddr string
		xfp        string
		override   string         // context override set by forwardedheaders middleware
		trusted    []netip.Prefix // nil = trust all (default posture)
		want       string
	}{
		{name: "direct TLS wins over header", tls: true, xfp: "http", want: "https"},
		{name: "trust-all honors https", remoteAddr: "1.2.3.4:1111", xfp: "https", want: "https"},
		{name: "trust-all honors http", remoteAddr: "1.2.3.4:1111", xfp: "http", want: "http"},
		{name: "no header defaults http", remoteAddr: "1.2.3.4:1111", want: "http"},
		{name: "leftmost token of chain", remoteAddr: "1.2.3.4:1111", xfp: "https, http", want: "https"},
		{name: "invalid value falls back", remoteAddr: "1.2.3.4:1111", xfp: "ftp", want: "http"},
		{name: "case insensitive", remoteAddr: "1.2.3.4:1111", xfp: "HTTPS", want: "https"},
		{name: "override beats untrusted client", remoteAddr: "1.2.3.4:1111", xfp: "http", override: "https", trusted: []netip.Prefix{mustPrefix("10.0.0.0/8")}, want: "https"},
		{name: "override beats TLS", tls: true, override: "http", want: "http"},
		{name: "invalid override is ignored", tls: true, override: "ftp", want: "https"},
		{
			name:       "untrusted client cannot spoof",
			remoteAddr: "1.2.3.4:1111",
			xfp:        "https",
			trusted:    []netip.Prefix{mustPrefix("10.0.0.0/8")},
			want:       "http",
		},
		{
			name:       "trusted proxy honored",
			remoteAddr: "10.1.2.3:1111",
			xfp:        "https",
			trusted:    []netip.Prefix{mustPrefix("10.0.0.0/8")},
			want:       "https",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			orig := trustedProxies
			trustedProxies = tc.trusted
			t.Cleanup(func() { trustedProxies = orig })

			r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
			if tc.remoteAddr != "" {
				r.RemoteAddr = tc.remoteAddr
			}
			if tc.xfp != "" {
				r.Header.Set(HeaderXForwardedProto, tc.xfp)
			}
			if tc.tls {
				r.TLS = &tls.ConnectionState{}
			}
			if tc.override != "" {
				r = r.WithContext(WithForwardedProto(r.Context(), tc.override))
			}

			if got := Scheme(r); got != tc.want {
				t.Errorf("%s: Scheme() = %q; want %q", tc.name, got, tc.want)
			}
		})
	}
}
