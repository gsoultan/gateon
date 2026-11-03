// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package request

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode"
	"unicode/utf8"
)

// maxJSONKeyDepth matches encoding/json's own nesting limit, so a document
// json.Unmarshal accepted is never refused here for depth alone.
const maxJSONKeyDepth = 10000

// ErrJSONTooDeep is returned when a document nests past maxJSONKeyDepth.
var ErrJSONTooDeep = errors.New("json nests too deeply to check for duplicate keys")

// AmbiguousJSONKey returns the first object key in data that collides with an
// earlier key of the same object, and whether there was one. Keys collide
// when encoding/json would match them to the same struct field: equal under
// Unicode simple case folding, after escapes are decoded.
//
// A JSON object with two such keys means different things to different
// parsers. encoding/json matches "QUERY" to a field tagged "query" and lets the
// last duplicate win; JavaScript reads body.query exactly; simdjson's
// find_field and several streaming parsers take the first. A gateway that
// decides on one reading while the backend executes another has checked a
// document nobody runs, so a caller making a security decision on a decoded
// body must refuse one that is ambiguous rather than pick a reading.
//
// When onlyTop is true, only the top-level object's keys are compared and
// nested values are skipped unchecked. data must already be valid JSON
// (decode it first); an invalid document returns the decoder's error.
func AmbiguousJSONKey(data []byte, onlyTop bool) (string, bool, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	var stack []jsonFrame
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return "", false, nil
		}
		if err != nil {
			return "", false, err
		}
		if key, dup := stepJSONFrames(&stack, tok, onlyTop); dup {
			return key, true, nil
		}
		if len(stack) > maxJSONKeyDepth {
			return "", false, ErrJSONTooDeep
		}
	}
}

// jsonFrame is one open container. keys is nil for an array, and for an
// object whose keys are not compared.
type jsonFrame struct {
	object    bool
	expectKey bool
	keys      map[string]struct{}
}

// stepJSONFrames advances the container stack by one token and reports a key
// that collides with an earlier one in the same object. Inside an object the
// tokens alternate key, value; a value that is itself a container is one
// value however many tokens it spans, so its parent expects a key again once
// it closes.
func stepJSONFrames(stack *[]jsonFrame, tok json.Token, onlyTop bool) (string, bool) {
	s := *stack
	if d, ok := tok.(json.Delim); ok && (d == '}' || d == ']') {
		*stack = s[:len(s)-1]
		return "", false
	}
	if n := len(s); n > 0 && s[n-1].expectKey {
		s[n-1].expectKey = false
		key, _ := tok.(string)
		return key, s[n-1].keys != nil && noteKey(s[n-1].keys, key)
	}
	if n := len(s); n > 0 && s[n-1].object {
		s[n-1].expectKey = true
	}
	if d, ok := tok.(json.Delim); ok {
		frame := jsonFrame{object: d == '{', expectKey: d == '{'}
		if frame.object && (!onlyTop || len(s) == 0) {
			frame.keys = make(map[string]struct{})
		}
		*stack = append(s, frame)
	}
	return "", false
}

// noteKey records key's folded form in set and reports whether it was there.
func noteKey(set map[string]struct{}, key string) bool {
	folded := foldJSONKey(key)
	if _, dup := set[folded]; dup {
		return true
	}
	set[folded] = struct{}{}
	return false
}

// foldJSONKey folds key the way encoding/json compares field names (see its
// fold.go): ASCII letters to upper case and every other rune to the smallest
// member of its simple-fold orbit, so "K" and the Kelvin sign fold together.
func foldJSONKey(key string) string {
	out := make([]byte, 0, len(key))
	for _, r := range key {
		if r < utf8.RuneSelf {
			if 'a' <= r && r <= 'z' {
				r -= 'a' - 'A'
			}
			out = append(out, byte(r))
			continue
		}
		out = utf8.AppendRune(out, smallestFold(r))
	}
	return string(out)
}

func smallestFold(r rune) rune {
	for {
		r2 := unicode.SimpleFold(r)
		if r2 <= r {
			return r2
		}
		r = r2
	}
}
