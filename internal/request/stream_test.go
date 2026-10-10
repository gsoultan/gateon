// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package request

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeStreamControl struct {
	http.ResponseWriter
	mode StreamMode
}

func (f *fakeStreamControl) SetStreamMode(m StreamMode) { f.mode = m }

type unwrapping struct{ http.ResponseWriter }

func (u unwrapping) Unwrap() http.ResponseWriter { return u.ResponseWriter }

// FindStreamControl finds the listener's decision through writers that
// unwrap, and reports none for a writer that is not one and wraps nothing.
func TestFindStreamControl(t *testing.T) {
	ctl := &fakeStreamControl{ResponseWriter: httptest.NewRecorder()}
	if got := FindStreamControl(ctl); got != ctl {
		t.Fatalf("direct: got %v", got)
	}
	if got := FindStreamControl(unwrapping{unwrapping{ctl}}); got != ctl {
		t.Fatalf("through two wrappers: got %v", got)
	}
	if got := FindStreamControl(httptest.NewRecorder()); got != nil {
		t.Fatalf("plain recorder: got %v, want nil", got)
	}
	if got := FindStreamControl(unwrapping{nil}); got != nil {
		t.Fatalf("a wrapper around nothing: got %v, want nil", got)
	}
}
