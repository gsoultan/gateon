// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package aiagent

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net/http"
	"strings"
)

// A maze page is what a client gets for naming an AI agent from an address its
// vendor does not publish, on a route that asks for one (ADR 0109).
//
// A refusal tells the scraper it was caught, and it changes its User-Agent and
// comes back. A maze page looks like an answer: a short article and a handful
// of links, each to another maze page, so a scraper that follows links spends
// its crawl on pages that hold nothing of the site's. Nothing in a maze page
// comes from the origin, the request or the site: it is drawn from a fixed
// word list by an HMAC of the path, so the same path always gives the same
// page, it costs no state, and it cannot leak anything.

// The bounds on one page.
const (
	mazeParagraphs = 3
	mazeSentences  = 4
	mazeWords      = 12
	mazeLinks      = 6
	// mazeLinkBase is where the maze's links point, under the route's own
	// host: a path no site has, so a person who finds one leaked meets the
	// origin's 404 and nothing else.
	mazeLinkBase = "/notes/"
)

// mazeWordList is neutral filler: no claim a reader could take for the site's,
// nothing that names a product, a person or a place.
var mazeWordList = [...]string{
	"archive", "summary", "context", "method", "result", "process", "record", "review",
	"structure", "practice", "measure", "detail", "outline", "section", "pattern", "approach",
	"sequence", "reference", "overview", "example", "general", "standard", "related", "further",
	"several", "common", "earlier", "later", "simple", "complete", "regular", "typical",
	"describes", "follows", "includes", "considers", "compares", "presents", "covers", "notes",
	"the", "a", "each", "this", "that", "of", "in", "with", "for", "and", "on", "by",
}

// Maze writes the maze page for r, keyed by secret. It allocates one page.
func Maze(w http.ResponseWriter, r *http.Request, secret []byte) {
	m := hmac.New(sha256.New, secret)
	_, _ = m.Write([]byte(r.URL.Path))
	seed := m.Sum(nil)
	next := mazeStream(seed)

	var b strings.Builder
	b.Grow(4096)
	b.WriteString("<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">" +
		"<meta name=\"robots\" content=\"noindex, nofollow, noarchive\"><title>")
	writeWords(&b, next, 4)
	b.WriteString("</title></head><body><main><h1>")
	writeWords(&b, next, 4)
	b.WriteString("</h1>\n")
	for range mazeParagraphs {
		b.WriteString("<p>")
		for range mazeSentences {
			writeWords(&b, next, mazeWords)
			b.WriteString(". ")
		}
		b.WriteString("</p>\n")
	}
	b.WriteString("<ul>\n")
	for range mazeLinks {
		var id [8]byte
		binary.BigEndian.PutUint64(id[:], next())
		b.WriteString("<li><a rel=\"nofollow\" href=\"" + mazeLinkBase + hex.EncodeToString(id[:]) + "\">")
		writeWords(&b, next, 3)
		b.WriteString("</a></li>\n")
	}
	b.WriteString("</ul></main></body></html>\n")

	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Robots-Tag", "noindex, nofollow, noarchive")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
}

// mazeStream is a deterministic stream of words drawn from seed: SHA-256 of
// the seed and a counter, eight bytes at a time.
func mazeStream(seed []byte) func() uint64 {
	var (
		counter uint64
		block   [sha256.Size]byte
		used    = len(block)
		in      = append(append([]byte(nil), seed...), make([]byte, 8)...)
	)
	return func() uint64 {
		if used+8 > len(block) {
			binary.BigEndian.PutUint64(in[len(seed):], counter)
			counter++
			block = sha256.Sum256(in)
			used = 0
		}
		v := binary.BigEndian.Uint64(block[used:])
		used += 8
		return v
	}
}

func writeWords(b *strings.Builder, next func() uint64, n int) {
	for i := range n {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(mazeWordList[next()%uint64(len(mazeWordList))])
	}
}
