// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package schemalearn_test

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/gsoultan/gateon/internal/security/waf/schemalearn"
	"github.com/gsoultan/gwaf/schema"
	"github.com/gsoultan/gwaf/schema/openapi"
)

func draftOf(t *testing.T, b *schemalearn.Book, route string) schemalearn.Draft {
	t.Helper()
	drafts, _ := b.Drafts()
	for _, d := range drafts {
		if d.Route == route {
			return d
		}
	}
	t.Fatalf("no draft for %s in %+v", route, drafts)
	return schemalearn.Draft{}
}

// The draft is only useful if it is a document the route's WAF accepts: the
// dashboard offers it as the route's openapi_spec, and that setting is
// compiled by gwaf's OpenAPI frontend on save.
func TestADraftIsADocumentTheWAFCompiles(t *testing.T) {
	b := schemalearn.NewBook()
	h := b.For("orders")
	for i := range 40 {
		h.Observe("GET", "/api/orders/"+strconv.Itoa(1000+i), "page="+strconv.Itoa(i)+"&q=shoes")
	}

	d := draftOf(t, b, "orders")
	if d.Observed != 40 || d.Operations != 1 || d.Document == "" {
		t.Fatalf("draft %+v", d)
	}
	ops, _, err := openapi.Compile([]byte(d.Document), openapi.Options{})
	if err != nil {
		t.Fatalf("the draft does not compile: %v\n%s", err, d.Document)
	}
	if len(ops) != 1 || ops[0].Method != "GET" || ops[0].Path != "/api/orders/{id}" {
		t.Fatalf("compiled %+v", ops)
	}
	kinds := map[string]schema.Kind{}
	for _, f := range ops[0].Query {
		kinds[f.Name] = f.Kind
	}
	if kinds["page"] != schema.KindInteger || kinds["q"] != schema.KindString {
		t.Errorf("query compiled as %v", kinds)
	}
}

// Shapes, never values.
func TestADraftCarriesNoValue(t *testing.T) {
	b := schemalearn.NewBook()
	h := b.For("login")
	for i := range 40 {
		h.Observe("GET", "/login", fmt.Sprintf("token=s3cr3t-%04d&email=alice%d@example.com", i, i))
	}
	d := draftOf(t, b, "login")
	if d.Operations != 1 {
		t.Fatalf("draft %+v", d)
	}
	for _, leaked := range []string{"s3cr3t", "alice", "example.com"} {
		if strings.Contains(d.Document, leaked) {
			t.Errorf("the draft contains %q:\n%s", leaked, d.Document)
		}
	}
}

func TestTooLittleTrafficDraftsNothingAndSaysSo(t *testing.T) {
	b := schemalearn.NewBook()
	h := b.For("quiet")
	h.Observe("GET", "/a", "")
	d := draftOf(t, b, "quiet")
	if d.Observed != 1 || d.Operations != 0 || d.Document != "" || d.MinSamples < 2 {
		t.Errorf("draft %+v, want one request seen and nothing drafted", d)
	}
}

func TestTheBookIsBoundedAndCountsWhatItTurnsAway(t *testing.T) {
	b := schemalearn.NewBook()
	for i := range schemalearn.MaxRoutes {
		if b.For("r"+strconv.Itoa(i)) == nil {
			t.Fatalf("route %d was turned away below the limit", i)
		}
	}
	over := b.For("one-too-many")
	if over != nil {
		t.Error("a route past the limit was given a learner")
	}
	over.Observe("GET", "/", "") // a nil handle is one that does nothing
	if b.For("r0") == nil {
		t.Error("a route already learning was turned away once the book was full")
	}
	drafts, rejected := b.Drafts()
	if len(drafts) != schemalearn.MaxRoutes || rejected != 1 {
		t.Errorf("%d drafts, %d rejected", len(drafts), rejected)
	}
}

func TestForgetStartsARouteAgain(t *testing.T) {
	b := schemalearn.NewBook()
	h := b.For("orders")
	for range 30 {
		h.Observe("GET", "/old", "")
	}
	if !b.Forget("orders") || b.Forget("never-learned") {
		t.Fatal("Forget reported the wrong thing")
	}
	if d := draftOf(t, b, "orders"); d.Observed != 0 || d.Operations != 0 {
		t.Errorf("after Forget: %+v", d)
	}
	// The handle the route's WAF already holds keeps working.
	for range 30 {
		h.Observe("GET", "/new", "")
	}
	if d := draftOf(t, b, "orders"); !strings.Contains(d.Document, `"/new"`) || strings.Contains(d.Document, `"/old"`) {
		t.Errorf("after Forget and new traffic:\n%s", d.Document)
	}
}

// Learning must never make a request wait, so a request that finds the route
// busy is skipped. Run with -race: writers and readers together.
func TestObserveIsSafeAndNeverLosesTheRoute(t *testing.T) {
	b := schemalearn.NewBook()
	h := b.For("busy")
	var wg sync.WaitGroup
	for w := range 8 {
		wg.Go(func() {
			for i := range 500 {
				h.Observe("GET", "/items/"+strconv.Itoa(i), "w="+strconv.Itoa(w))
				if i%100 == 0 {
					_, _ = b.Drafts()
				}
			}
		})
	}
	wg.Wait()
	d := draftOf(t, b, "busy")
	if d.Observed == 0 || d.Observed > 4000 || d.Operations != 1 {
		t.Errorf("draft %+v", d)
	}
}
