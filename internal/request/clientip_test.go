package request

import (
	"net/http"
	"net/netip"
	"os"
	"testing"
)

// withTrustedProxies temporarily sets the package-level trustedProxies set for
// the duration of a test and restores it afterward.
func withTrustedProxies(t *testing.T, cidrs ...string) {
	t.Helper()
	prev := trustedProxies
	t.Cleanup(func() { trustedProxies = prev })
	trustedProxies = nil
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			t.Fatalf("bad test CIDR %q: %v", c, err)
		}
		trustedProxies = append(trustedProxies, p)
	}
}

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name            string
		trusted         []string // CIDRs treated as trusted proxies for this case
		remoteAddr      string
		headers         map[string]string
		trustCloudflare bool
		want            string
	}{
		{
			name:       "remote_only",
			remoteAddr: "192.168.1.1:12345",
			want:       "192.168.1.1",
		},
		{
			// SECURITY: with no trusted proxies configured, forwarding headers
			// from an untrusted peer must be ignored (no spoofing).
			name:       "xff_ignored_when_no_trusted_proxies",
			remoteAddr: "10.0.0.1:80",
			headers:    map[string]string{HeaderXForwardedFor: "203.0.113.50"},
			want:       "10.0.0.1",
		},
		{
			name:            "cf_ignored_when_no_trusted_proxies",
			remoteAddr:      "10.0.0.1:80",
			headers:         map[string]string{HeaderCloudflareConnectingIP: "203.0.113.50"},
			trustCloudflare: true,
			want:            "10.0.0.1",
		},
		{
			name:       "xff_single_trusted_peer",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.0.0.1:80",
			headers:    map[string]string{HeaderXForwardedFor: "203.0.113.50"},
			want:       "203.0.113.50",
		},
		{
			// Only 10/8 is trusted: the rightmost (closest) untrusted hop is as
			// far back as we can trust — we must NOT believe the leftmost token.
			name:       "xff_chain_partial_trust_returns_closest_untrusted",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.0.0.1:80",
			headers:    map[string]string{HeaderXForwardedFor: "203.0.113.50, 70.41.3.18, 150.172.238.178"},
			want:       "150.172.238.178",
		},
		{
			// All intermediate hops are trusted, so we can walk back to the origin.
			name:       "xff_chain_full_trust_returns_origin",
			trusted:    []string{"10.0.0.0/8", "70.41.3.18/32", "150.172.238.178/32"},
			remoteAddr: "10.0.0.1:80",
			headers:    map[string]string{HeaderXForwardedFor: "203.0.113.50, 70.41.3.18, 150.172.238.178"},
			want:       "203.0.113.50",
		},
		{
			name:            "cf_connecting_ip_trusted_peer",
			trusted:         []string{"10.0.0.0/8"},
			remoteAddr:      "10.0.0.1:80",
			headers:         map[string]string{HeaderCloudflareConnectingIP: "203.0.113.50"},
			trustCloudflare: true,
			want:            "203.0.113.50",
		},
		{
			name:            "cf_preferred_over_xff",
			trusted:         []string{"10.0.0.0/8"},
			remoteAddr:      "10.0.0.1:80",
			headers:         map[string]string{HeaderCloudflareConnectingIP: "203.0.113.50", HeaderXForwardedFor: "70.41.3.18"},
			trustCloudflare: true,
			want:            "203.0.113.50",
		},
		{
			name:            "cf_not_used_when_flag_false",
			trusted:         []string{"10.0.0.0/8"},
			remoteAddr:      "10.0.0.1:80",
			headers:         map[string]string{HeaderCloudflareConnectingIP: "203.0.113.50", HeaderXForwardedFor: "70.41.3.18"},
			trustCloudflare: false,
			want:            "70.41.3.18",
		},
		{
			name:            "cf_trusted_builtin_ip",
			remoteAddr:      "172.64.0.1:80",
			headers:         map[string]string{HeaderCloudflareConnectingIP: "203.0.113.50"},
			trustCloudflare: true,
			want:            "203.0.113.50",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withTrustedProxies(t, tt.trusted...)
			r, _ := http.NewRequest("GET", "/", nil)
			r.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				r.Header.Set(k, v)
			}
			got := GetClientIP(r, tt.trustCloudflare)
			if got != tt.want {
				t.Errorf("GetClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseTrustCloudflare(t *testing.T) {
	os.Unsetenv(EnvTrustCloudflareHeaders)
	defer os.Unsetenv(EnvTrustCloudflareHeaders)

	if ParseTrustCloudflareStrict("true") != true {
		t.Error("ParseTrustCloudflareStrict(true) want true")
	}
	if ParseTrustCloudflareStrict("false") != false {
		t.Error("ParseTrustCloudflareStrict(false) want false")
	}
	if ParseTrustCloudflareStrict("") != false {
		t.Error("ParseTrustCloudflareStrict(empty) want false")
	}
}
