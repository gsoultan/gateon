package httputil

import "testing"

func TestStripPort(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"Empty", "", ""},
		{"HostWithPort", "localhost:8080", "localhost"},
		{"HostNoPort", "localhost", "localhost"},
		{"IPv4WithPort", "127.0.0.1:8080", "127.0.0.1"},
		{"IPv4NoPort", "127.0.0.1", "127.0.0.1"},
		{"IPv6BracketedWithPort", "[::1]:8080", "::1"},
		{"IPv6Bracketed", "[::1]", "::1"},
		{"IPv6Bare", "::1", "::1"},
		{"IPv6FullBracketedWithPort", "[2001:db8::1]:443", "2001:db8::1"},
		{"DomainWithPort", "example.com:443", "example.com"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := StripPort(tc.input)
			if got != tc.expected {
				t.Errorf("%s: StripPort(%q) = %q; want %q", tc.name, tc.input, got, tc.expected)
			}
		})
	}
}
