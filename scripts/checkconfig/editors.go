// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Which middleware type writes which key (truth NEW-10).
//
// The effect registry matched keys by name, so a row proving cors's
// allowed_origins counted for grpcweb's too -- and grpcweb ignored the key and
// let every origin in. A key is proven for the type whose factory a row builds,
// so the dashboard's keys are attributed to types the way the dashboard
// renders them: MiddlewareConfigEditor switches on the type and renders an
// inline form or an editor component, and a component writes its keys and
// renders others.

// dispatcherFile is the editor that switches on the middleware type.
const dispatcherFile = "MiddlewareConfigEditor.tsx"

var (
	componentRE = regexp.MustCompile(`(?m)^(?:export\s+)?(?:function\s+([A-Z]\w*)\s*\(|const\s+([A-Z]\w*)\s*=)`)
	elementRE   = regexp.MustCompile(`<([A-Z]\w*)\b`)
	caseRE      = regexp.MustCompile(`(?m)^\s*(?:case\s+"([A-Za-z_]+)"|default)\s*:`)
)

// component is one editor component: the keys it writes and the components it
// renders.
type component struct {
	keys map[string]bool
	refs []string
}

// typedKey is how the registry, the baseline and the check name a key: "type/key".
func typedKey(typ, key string) string { return typ + "/" + key }

// dashboardTypeKeys reads the editors and returns every "type/key" the
// dashboard writes, and the keys an editor writes that no type renders.
func dashboardTypeKeys(dir string) (map[string]bool, []string, error) {
	sources, err := editorSources(dir)
	if err != nil {
		return nil, nil, err
	}
	comps := map[string]component{}
	all := map[string]bool{}
	for _, src := range sources {
		for name, c := range components(src) {
			comps[name] = c
		}
		for _, m := range dashboardKeyRE.FindAllStringSubmatch(src, -1) {
			all[m[1]] = true
		}
	}
	out := map[string]bool{}
	seen := map[string]bool{}
	for _, seg := range switchSegments(sources[dispatcherFile]) {
		keys := map[string]bool{}
		for _, m := range dashboardKeyRE.FindAllStringSubmatch(seg.body, -1) {
			keys[m[1]] = true
		}
		for _, m := range elementRE.FindAllStringSubmatch(seg.body, -1) {
			collectKeys(m[1], comps, keys, map[string]bool{})
		}
		for _, typ := range seg.types {
			for k := range keys {
				out[typedKey(typ, k)] = true
				seen[k] = true
			}
		}
	}
	var orphans []string
	for k := range all {
		if !seen[k] {
			orphans = append(orphans, k)
		}
	}
	sort.Strings(orphans)
	return out, orphans, nil
}

// editorSources reads every editor (not test) file in dir, by name.
func editorSources(dir string) (map[string]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".tsx") || strings.HasSuffix(name, ".test.tsx") {
			continue
		}
		// #nosec G304 -- a build-time developer command; dir is the editorsDir
		// constant or a t.TempDir() fixture, name comes from ReadDir of it.
		src, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		out[name] = string(src)
	}
	return out, nil
}

// components splits a file at its top-level component declarations.
func components(src string) map[string]component {
	out := map[string]component{}
	locs := componentRE.FindAllStringSubmatchIndex(src, -1)
	for i, loc := range locs {
		end := len(src)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		var name string
		if loc[2] >= 0 {
			name = src[loc[2]:loc[3]] // function Name(
		} else {
			name = src[loc[4]:loc[5]] // const Name =
		}
		body := src[loc[0]:end]
		c := component{keys: map[string]bool{}}
		for _, m := range dashboardKeyRE.FindAllStringSubmatch(body, -1) {
			c.keys[m[1]] = true
		}
		for _, m := range elementRE.FindAllStringSubmatch(body, -1) {
			c.refs = append(c.refs, m[1])
		}
		out[name] = c
	}
	return out
}

// collectKeys adds the keys component name writes, and those of every
// component it renders, to keys.
func collectKeys(name string, comps map[string]component, keys, visited map[string]bool) {
	c, ok := comps[name]
	if !ok || visited[name] {
		return
	}
	visited[name] = true
	for k := range c.keys {
		keys[k] = true
	}
	for _, ref := range c.refs {
		collectKeys(ref, comps, keys, visited)
	}
}

// segment is one arm of the dispatcher's switch: the types its labels name
// (fallthrough labels included) and the code it runs.
type segment struct {
	types []string
	body  string
}

// switchSegments splits the dispatcher's switch on the type into arms. A
// camelCase label is an alias kept for middlewares saved under it; the
// factory builds only the snake_case spelling, so only that is attributed.
func switchSegments(src string) []segment {
	start := strings.Index(src, "switch (type)")
	if start < 0 {
		return nil
	}
	src = src[start:]
	locs := caseRE.FindAllStringSubmatchIndex(src, -1)
	var out []segment
	var pending []string
	for i, loc := range locs {
		if loc[2] < 0 { // default: the arm for unknown types
			break
		}
		typ := src[loc[2]:loc[3]]
		if strings.ToLower(typ) == typ {
			pending = append(pending, typ)
		}
		end := len(src)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		body := src[loc[1]:end]
		if strings.TrimSpace(body) == "" {
			continue // falls through to the next label
		}
		out = append(out, segment{types: pending, body: body})
		pending = nil
	}
	return out
}
