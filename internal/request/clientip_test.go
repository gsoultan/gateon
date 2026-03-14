package request

import (
	"net/http"
	"os"
	"testing"
)

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name            string
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
			name:       "xff_single",
			remoteAddr: "10.0.0.1:80",
			headers:    map[string]string{HeaderXForwardedFor: "203.0.113.50"},
			want:       "203.0.113.50",
		},
		{
			name:       "xff_chain",
			remoteAddr: "10.0.0.1:80",
			headers:    map[string]string{HeaderXForwardedFor: "203.0.113.50, 70.41.3.18, 150.172.238.178"},
			want:       "203.0.113.50",
		},
		{
			name:            "cf_connecting_ip",
			remoteAddr:      "10.0.0.1:80",
			headers:         map[string]string{HeaderCloudflareConnectingIP: "203.0.113.50"},
			trustCloudflare: true,
			want:            "203.0.113.50",
		},
		{
			name:            "cf_preferred_over_xff",
			remoteAddr:      "10.0.0.1:80",
			headers:         map[string]string{HeaderCloudflareConnectingIP: "203.0.113.50", HeaderXForwardedFor: "70.41.3.18"},
			trustCloudflare: true,
			want:            "203.0.113.50",
		},
		{
			name:            "cf_not_used_when_not_trusted",
			remoteAddr:      "10.0.0.1:80",
			headers:         map[string]string{HeaderCloudflareConnectingIP: "203.0.113.50", HeaderXForwardedFor: "70.41.3.18"},
			trustCloudflare: false,
			want:            "70.41.3.18",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
