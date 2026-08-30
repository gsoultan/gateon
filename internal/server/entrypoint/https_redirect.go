// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"context"
	"net"
	"net/http"
	"sort"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// httpsRedirectStatus is deliberately temporary rather than 301 or 308.
//
// A permanent redirect is cached by browsers and, once issued, keeps sending
// users to HTTPS long after the setting is switched off — an operator who turns
// this on by mistake cannot take it back from clients that already saw it. 307
// also preserves the request method, unlike 302, so a POST is not silently
// downgraded to a GET on the way through.
const httpsRedirectStatus = http.StatusTemporaryRedirect

// httpsRedirectPort returns the port that plain-HTTP entrypoints should redirect
// to, or "" when there is nothing to redirect to.
//
// The target is derived from the entrypoints rather than assumed to be 443,
// because TLS is configured per entrypoint here and a gateway listening on 8443
// would otherwise be told to send everyone to a port with nothing on it. 443 is
// preferred when present; otherwise the lowest port is chosen so the answer does
// not depend on map iteration order.
func httpsRedirectPort(eps []*gateonv1.EntryPoint) string {
	var ports []string
	for _, ep := range eps {
		if ep == nil || ep.GetTls() == nil || !ep.GetTls().GetEnabled() {
			continue
		}
		switch ep.GetType() {
		case gateonv1.EntryPoint_HTTP, gateonv1.EntryPoint_HTTP2,
			gateonv1.EntryPoint_HTTP3, gateonv1.EntryPoint_GRPC:
		default:
			continue
		}
		_, port, err := net.SplitHostPort(ep.GetAddress())
		if err != nil || port == "" {
			continue
		}
		ports = append(ports, port)
	}
	if len(ports) == 0 {
		return ""
	}
	for _, p := range ports {
		if p == "443" {
			return p
		}
	}
	sort.Strings(ports)
	return ports[0]
}

// redirectTargetURL builds the https URL for a request.
//
// The host comes from the request, which is how every gateway does this: the
// client is sent back to the name it asked for, over TLS. That is not an open
// redirect — a caller can only redirect itself, and net/http has already
// rejected a Host containing header-injection characters. Any port on the
// inbound host is dropped, since it is the plaintext one.
func redirectTargetURL(r *http.Request, port string) string {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil && h != "" {
		host = h
	}
	if port != "" && port != "443" {
		host = net.JoinHostPort(host, port)
	}
	return "https://" + host + r.URL.RequestURI()
}

// httpsRedirect returns a handler that sends everything to HTTPS.
func httpsRedirect(port string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTargetURL(r, port), httpsRedirectStatus)
	})
}

// shouldRedirectToHTTPS decides whether this entrypoint serves redirects.
//
// Management is never redirected: it is frequently reached by IP or over a
// private address with no certificate, and an operator who loses the dashboard
// has lost the means to turn the setting back off.
func shouldRedirectToHTTPS(ep *gateonv1.EntryPoint, isMgmt, autoRedirect bool, targetPort string) bool {
	if !autoRedirect || isMgmt || targetPort == "" {
		return false
	}
	// An entrypoint already serving TLS has nothing to redirect.
	return ep.GetTls() == nil || !ep.GetTls().GetEnabled()
}

// autoRedirectEnabled reports whether tls.auto_redirect is set.
func autoRedirectEnabled(ctx context.Context, deps *Deps) bool {
	if deps == nil || deps.GlobalStore == nil {
		return false
	}
	gc := deps.GlobalStore.Get(ctx)
	return gc.GetTls().GetAutoRedirect()
}

// httpsRedirectTargetFor resolves the redirect target from the configured
// entrypoints, returning "" when none of them terminates TLS.
func httpsRedirectTargetFor(ctx context.Context, deps *Deps) string {
	if deps == nil || deps.EpStore == nil {
		return ""
	}
	return httpsRedirectPort(deps.EpStore.List(ctx))
}
