// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package selfupdate

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func TestValidateSource(t *testing.T) {
	t.Parallel()
	accepted := []string{
		"",
		DefaultSource,
		"https://mirror.example.com/gateon/releases/",
		"http://127.0.0.1:8081/releases",
		"http://localhost/releases",
		"http://[::1]:9000/r",
	}
	for _, raw := range accepted {
		if err := ValidateSource(raw); err != nil {
			t.Errorf("ValidateSource(%q) = %v, want accepted", raw, err)
		}
	}
	refused := []string{
		"http://mirror.example.com/releases",       // readable and rewritable in transit
		"http://10.0.0.5/releases",                 // a private network is a network
		"ftp://mirror.example.com/releases",        //
		"file:///etc/passwd",                       //
		"mirror.example.com/releases",              // not absolute
		"https://user:pass@mirror.example.com/r",   // credentials
		"https://mirror.example.com/r?token=abc",   // query
		"https://mirror.example.com/r#frag",        // fragment
		"https://169.254.169.254/latest/meta-data", // cloud metadata
		"https://metadata.google.internal/r",       //
		"https://" + strings.Repeat("a", 2100) + ".example.com/",
	}
	for _, raw := range refused {
		if err := ValidateSource(raw); !errors.Is(err, ErrSource) {
			t.Errorf("ValidateSource(%q) = %v, want ErrSource", raw, err)
		}
	}
}

func TestSourceURLs(t *testing.T) {
	t.Parallel()
	src, err := newSource(" https://mirror.example.com/gateon/releases/ ")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := src.checksumsURL(), "https://mirror.example.com/gateon/releases/latest/download/checksums.txt"; got != want {
		t.Errorf("checksumsURL = %q, want %q", got, want)
	}
	if got, want := src.signatureURL(), "https://mirror.example.com/gateon/releases/latest/download/checksums.txt.sig"; got != want {
		t.Errorf("signatureURL = %q, want %q", got, want)
	}
	if got, want := src.notesURL(Version{1, 8, 3}), "https://mirror.example.com/gateon/releases/tag/v1.8.3"; got != want {
		t.Errorf("notesURL = %q, want %q", got, want)
	}
	if def, _ := newSource(""); def.base != DefaultSource {
		t.Errorf("empty source = %q, want the default", def.base)
	}
}

// releaseServer serves a release source's two files from loopback.
func releaseServer(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestHTTPFetcherBoundsWhatItReads(t *testing.T) {
	t.Parallel()
	var agent string
	base := releaseServer(t, func(w http.ResponseWriter, r *http.Request) {
		agent = r.Header.Get("User-Agent")
		switch r.URL.Path {
		case "/ok":
			_, _ = w.Write([]byte("0123456789"))
		case "/missing":
			http.NotFound(w, r)
		case "/broken":
			http.Error(w, "upstream down", http.StatusBadGateway)
		case "/leaves":
			// Loopback http is accepted for a mirror; a redirect off this
			// host to plain http is not.
			http.Redirect(w, r, "http://mirror.example.com/checksums.txt", http.StatusFound)
		case "/metadata":
			http.Redirect(w, r, "https://169.254.169.254/latest/meta-data/", http.StatusFound)
		}
	})
	f := httpFetcher{client: newClient(), userAgent: "gateon/1.8.2"}

	body, err := f.fetch(t.Context(), base+"/ok", 10)
	if err != nil || string(body) != "0123456789" {
		t.Fatalf("fetch within the limit = %q, %v", body, err)
	}
	if agent != "gateon/1.8.2" {
		t.Errorf("User-Agent = %q, want gateon/1.8.2", agent)
	}
	if _, err := f.fetch(t.Context(), base+"/ok", 9); !errors.Is(err, ErrMalformed) {
		t.Errorf("a body one byte over the limit: %v, want ErrMalformed", err)
	}
	if _, err := f.fetch(t.Context(), base+"/missing", 10); !errors.Is(err, errNotFound) {
		t.Errorf("a 404: %v, want errNotFound", err)
	}
	if body, err := f.fetch(t.Context(), base+"/broken", 100); err == nil {
		t.Errorf("a 502's error page was returned as a release file: %q", body)
	}
	for _, path := range []string{"/leaves", "/metadata"} {
		if _, err := f.fetch(t.Context(), base+path, 100); !errors.Is(err, ErrSource) {
			t.Errorf("redirect %s: %v, want it refused with ErrSource", path, err)
		}
	}
}

func TestEnvSettings(t *testing.T) {
	t.Parallel()
	saved := &gateonv1.UpdateConfig{SourceUrl: " https://saved.example.com/r "}
	cases := []struct {
		name string
		env  Env
		conf *gateonv1.UpdateConfig
		want Settings
	}{
		{"defaults", Env{}, nil, Settings{Enabled: true, Source: DefaultSource}},
		{"environment source", Env{Source: "https://env.example.com/r"}, nil,
			Settings{Enabled: true, Source: "https://env.example.com/r"}},
		{"the saved source wins", Env{Source: "https://env.example.com/r"}, saved,
			Settings{Enabled: true, Source: "https://saved.example.com/r"}},
		{"switched off in settings", Env{}, &gateonv1.UpdateConfig{CheckDisabled: true},
			Settings{Source: DefaultSource}},
		{"switched off by the environment", Env{CheckOff: true}, &gateonv1.UpdateConfig{},
			Settings{DisabledByEnv: true, Source: DefaultSource}},
	}
	for _, c := range cases {
		if got := c.env.Settings(c.conf); got != c.want {
			t.Errorf("%s: Settings = %+v, want %+v", c.name, got, c.want)
		}
	}
}

func TestReadEnv(t *testing.T) {
	def := config.CurrentTierDefaults().UpdateCheckInterval
	if def != MaxInterval/30 {
		t.Fatalf("tier default interval = %v, want 24h", def)
	}
	cases := []struct {
		check, interval string
		want            Env
	}{
		{"", "", Env{Interval: def}},
		{"0", "", Env{CheckOff: true, Interval: def}},
		{"false", "", Env{CheckOff: true, Interval: def}},
		{"1", "", Env{Interval: def}},
		{"offf", "", Env{Interval: def}}, // a typo does not stop the check
		{"", "6h", Env{Interval: 6 * 3600e9}},
		{"", "1s", Env{Interval: MinInterval}},
		{"", "9000h", Env{Interval: MaxInterval}},
		{"", "soon", Env{Interval: def}},
	}
	for _, c := range cases {
		t.Setenv(EnvCheck, c.check)
		t.Setenv(EnvInterval, c.interval)
		t.Setenv(EnvSource, " https://env.example.com/r ")
		c.want.Source = "https://env.example.com/r"
		if got := ReadEnv(); got != c.want {
			t.Errorf("GATEON_UPDATE_CHECK=%q GATEON_UPDATE_CHECK_INTERVAL=%q: %+v, want %+v", c.check, c.interval, got, c.want)
		}
	}
}

func TestInstallKind(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		env   map[string]string
		files map[string]bool
		want  InstallKind
	}{
		{"a binary run by hand", nil, nil, InstallOther},
		{"systemd", map[string]string{envSystemdUnit: "abc"}, nil, InstallSystemd},
		{"docker", nil, map[string]bool{dockerMark: true}, InstallContainer},
		{"podman", nil, map[string]bool{podmanMark: true}, InstallContainer},
		{"kubernetes", map[string]string{envKubernetes: "10.0.0.1"}, map[string]bool{dockerMark: true}, InstallKubernetes},
		{"systemd inside a container", map[string]string{envSystemdUnit: "abc"}, map[string]bool{dockerMark: true}, InstallContainer},
	}
	for _, c := range cases {
		got := installKind(func(k string) string { return c.env[k] }, func(p string) bool { return c.files[p] })
		if got != c.want {
			t.Errorf("%s: kind = %d, want %d", c.name, got, c.want)
		}
	}
}
