// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package aiagent

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func mazePage(t *testing.T, target string, secret string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.Header.Set("Cookie", "session=secret-session-value")
	Maze(rr, r, []byte(secret))
	return rr
}

// TestAMazePageIsStableAndHoldsNothingOfTheRequest is ADR 0109. The page must
// be the same for the same path, so a scraper that comes back finds the same
// maze and the gateway keeps no state; it must differ between paths, or the
// scraper sees through it at the second link; and it must carry nothing of
// the request, which is the scraper's to write.
func TestAMazePageIsStableAndHoldsNothingOfTheRequest(t *testing.T) {
	const evil = "/articles/%3Cscript%3Ealert(1)%3C/script%3E"
	a, b := mazePage(t, evil, "k"), mazePage(t, evil, "k")
	if a.Body.String() != b.Body.String() {
		t.Fatal("the same path gave two different pages")
	}
	if mazePage(t, "/articles/2", "k").Body.String() == a.Body.String() {
		t.Error("two paths gave the same page")
	}
	if mazePage(t, evil, "other").Body.String() == a.Body.String() {
		t.Error("two secrets gave the same page: anyone could predict the maze")
	}
	body := a.Body.String()
	for _, leaked := range []string{"script", "alert", "articles", "secret-session-value"} {
		if strings.Contains(body, leaked) {
			t.Errorf("the page carries %q from the request", leaked)
		}
	}
	if a.Code != http.StatusOK || a.Header().Get("X-Robots-Tag") == "" || a.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("got %d with headers %v; want a 200 that no index and no cache keeps", a.Code, a.Header())
	}
	if n := strings.Count(body, `<a rel="nofollow" href="`+mazeLinkBase); n != mazeLinks {
		t.Errorf("%d maze links, want %d", n, mazeLinks)
	}
	if len(body) > 8<<10 {
		t.Errorf("a maze page is %d bytes; it is meant to cost the gateway next to nothing", len(body))
	}
}

func BenchmarkMaze(b *testing.B) {
	r := httptest.NewRequest(http.MethodGet, "/notes/0123456789abcdef", nil)
	secret := []byte("bench")
	b.ReportAllocs()
	for b.Loop() {
		Maze(httptest.NewRecorder(), r, secret)
	}
}
