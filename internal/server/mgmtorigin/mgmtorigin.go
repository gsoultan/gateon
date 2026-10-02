// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package mgmtorigin decides whether a browser request to the management plane
// was made by the management origin itself, and refuses the ones that were not
// when they could change something (ADR 0041).
//
// The dashboard authenticates with a cookie, and a browser attaches a cookie
// to a request whoever's page asked for it. SameSite narrows "whoever" to the
// same site, which for a dashboard on an IP address or a shared domain still
// includes every port on that address and every sibling subdomain -- the apps
// this gateway proxies among them. So a write the cookie authorizes has to
// show, separately, that the dashboard asked for it.
package mgmtorigin

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gsoultan/gateon/internal/logger"
)

// Policy holds the origins, other than the management origin itself, that may
// make credentialed requests: the ones an operator configured for management
// CORS. The zero value and a nil *Policy trust no other origin.
type Policy struct {
	trusted map[string]struct{}
}

// New returns a Policy trusting the given origins. "*" is ignored -- a
// wildcard CORS origin grants reads without credentials, never writes with
// them -- as is anything that is not scheme://host[:port], since that is the
// only form a browser's Origin header takes.
func New(origins []string) *Policy {
	p := &Policy{trusted: make(map[string]struct{}, len(origins))}
	for _, o := range origins {
		o = strings.TrimSpace(o)
		if !isSerializedOrigin(o) {
			if o != "" && o != "*" {
				logger.L.LogWarn("management CORS origin is not scheme://host[:port]; it is not trusted for writes",
					"origin", o)
			}
			continue
		}
		p.trusted[strings.ToLower(o)] = struct{}{}
	}
	return p
}

func isSerializedOrigin(o string) bool {
	u, err := url.Parse(o)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" &&
		u.Path == "" && u.RawQuery == "" && u.Fragment == "" && u.User == nil
}

// Allows reports whether r may act with the caller's ambient credentials: it
// came from the management origin, from an origin the operator trusts, or from
// a client that is not a browser.
//
// It is net/http.CrossOriginProtection's algorithm, applied to every method
// rather than only unsafe ones, because a WebSocket handshake is a GET:
//   - Sec-Fetch-Site is set by the browser and no page can change it.
//     same-origin and none (the user typed the address) are allowed;
//     same-site and cross-site are refused unless Origin is trusted.
//   - Without it (a browser older than 2023), an Origin whose host is the
//     request's own Host is allowed; any other, "null" included, is refused
//     unless trusted.
//   - With neither, the client is not a browser -- a script, Prometheus, the
//     CLI. It holds a bearer token rather than an ambient cookie, so there is
//     nobody to forge a request for.
func (p *Policy) Allows(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return true
	case "":
	default:
		return p.trusts(r.Header.Get("Origin"))
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	if u, err := url.Parse(origin); err == nil && u.Host != "" && strings.EqualFold(u.Host, r.Host) {
		return true
	}
	return p.trusts(origin)
}

func (p *Policy) trusts(origin string) bool {
	if p == nil || origin == "" {
		return false
	}
	_, ok := p.trusted[strings.ToLower(origin)]
	return ok
}

// Guard refuses, before next runs, a request that could change state and did
// not come from the management origin, and an API write whose body is not a
// type the API takes. Reads pass through untouched.
func (p *Policy) Guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if changesState(r) && !p.Allows(r) {
			refuse(w, r, http.StatusForbidden, "cross_origin",
				"cross-origin request refused: the management API accepts changes only from its own origin")
			return
		}
		if isMutation(r.Method) && isAPIPath(r.URL.Path) && !acceptableBody(r) {
			refuse(w, r, http.StatusUnsupportedMediaType, "content_type",
				"unsupported content type: send the request body as application/json")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// changesState is a write, or a WebSocket handshake: the one GET that opens a
// channel the page can read from afterwards with the caller's session.
func changesState(r *http.Request) bool {
	return isMutation(r.Method) || strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

func isMutation(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return false
	}
	return true
}

func isAPIPath(path string) bool {
	return strings.HasPrefix(path, "/v1/") || strings.HasPrefix(path, "/gateon.v1.")
}

// uploadPaths take a file as multipart/form-data. That type, like text/plain
// and form-urlencoded, is one a cross-site form can send without a preflight,
// so it is accepted only where a file is expected; the origin check above is
// what refuses a forged upload.
var uploadPaths = map[string]struct{}{
	"/v1/certs/upload": {},
	"/v1/geoip/upload": {},
}

// acceptableBody reports whether an API write's body is a type the API takes.
// Every one of them is a type a page can send cross-origin only after a CORS
// preflight the management plane does not grant by default. A write without a
// body needs no type.
func acceptableBody(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		return r.ContentLength == 0
	}
	mediaType, _, _ := strings.Cut(ct, ";")
	mediaType = strings.ToLower(strings.TrimSpace(mediaType))
	switch {
	case mediaType == "application/json", mediaType == "application/proto",
		strings.HasPrefix(mediaType, "application/connect+"),
		strings.HasPrefix(mediaType, "application/grpc"):
		return true
	case mediaType == "multipart/form-data":
		_, ok := uploadPaths[r.URL.Path]
		return ok
	}
	return false
}

func refuse(w http.ResponseWriter, r *http.Request, status int, reason, message string) {
	logger.SecurityEvent("management_request_refused", r, reason)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":"` + message + `"}`))
}
