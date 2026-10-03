// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package posture describes what the gateway's protections are doing, from the
// configuration the router builds its chains from -- never from the traffic.
//
// Everything here exists because the Security Hub used to answer these
// questions with constants or with the wrong inputs (ADR 0048): a signature
// engine "11 rules active" whether or not anything scanned, a WAF "Protecting
// all routes" in audit-only, and a posture percentage computed from client
// reputation, which rose as an attacker's reputation fell. An operator acts on
// these numbers, so each is computed from what runs or not shown.
package posture

import (
	"strconv"
	"strings"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Mode is what a WAF does with a request it matches.
type Mode string

const (
	// ModeEnforce refuses what it matches.
	ModeEnforce Mode = "enforce"
	// ModeDetect records what it matches and forwards it (audit-only).
	ModeDetect Mode = "detect"
	// ModeOff means no WAF inspects the request at all.
	ModeOff Mode = "off"
)

// Middleware types and keys read here, spelled as the factory spells them.
const (
	typeWAF           = "waf"
	typeFileSecurity  = "file_security"
	typeBotManagement = "bot_management"
	keyAuditOnly      = "audit_only"
	keySignatureScan  = "enable_signature_scan"
)

// Config is the configuration a posture is computed from: the same objects the
// router composes a route's chain from.
type Config struct {
	Global      *gateonv1.GlobalConfig
	Routes      []*gateonv1.Route
	Middlewares map[string]*gateonv1.Middleware
	EntryPoints []*gateonv1.EntryPoint
	// ManagementWorldOpen is entrypoint.ManagementListenerWorldOpen for the
	// running management config; the caller asks, so this package needs no
	// listener code.
	ManagementWorldOpen bool
	// PublicManagement is whether the management API answers on every
	// entrypoint (management.allow_public_management or its env override).
	PublicManagement bool
	// RouteWAF, when set, is the mode a route WAF with this config runs in,
	// as the WAF package builds it (waf.EffectiveRoute). The server sets it so
	// the report and the engine answer from one rule; without it the
	// coverage falls back to routeWAFConfigMode, a copy of that rule.
	RouteWAF func(cfg map[string]string) Mode
}

// RouteCoverage counts the enabled HTTP routes by what inspects them.
type RouteCoverage struct {
	Total     int `json:"total"`
	Enforcing int `json:"enforcing"`
	Detecting int `json:"detecting"`
	Off       int `json:"unprotected"`
	// SignatureScanning is how many routes run the upload signature engine
	// (a file_security middleware with enable_signature_scan on).
	SignatureScanning int `json:"signatureScanning"`
	// BotManagement is how many routes carry a bot_management middleware. The
	// global bot-management settings only supply defaults to that middleware;
	// they protect no route that does not carry it.
	BotManagement int `json:"botManagement"`
}

// GlobalWAFMode is the mode the gateway-wide WAF runs in.
func GlobalWAFMode(w *gateonv1.WafConfig) Mode {
	switch {
	case !w.GetEnabled():
		return ModeOff
	case w.GetAuditOnly():
		return ModeDetect
	default:
		return ModeEnforce
	}
}

// Coverage walks every enabled HTTP route the way the router composes it: a
// route that attaches its own "waf" middleware runs that WAF instead of the
// gateway-wide one (router.ApplyRouteMiddlewares), so its mode is its own;
// every other route runs the global WAF, if any.
func Coverage(c Config) RouteCoverage {
	var cov RouteCoverage
	global := c.Global.GetWaf()
	for _, rt := range c.Routes {
		if rt.GetDisabled() || isL4(rt.GetType()) {
			continue
		}
		cov.Total++
		switch routeWAFMode(rt, c.Middlewares, global, c.RouteWAF) {
		case ModeEnforce:
			cov.Enforcing++
		case ModeDetect:
			cov.Detecting++
		default:
			cov.Off++
		}
		if routeScansSignatures(rt, c.Middlewares) {
			cov.SignatureScanning++
		}
		if len(routeMiddlewares(rt, c.Middlewares, typeBotManagement)) > 0 {
			cov.BotManagement++
		}
	}
	return cov
}

// isL4 reports whether a route is TCP/UDP, which no HTTP middleware runs on.
func isL4(routeType string) bool {
	t := strings.ToLower(strings.TrimSpace(routeType))
	return t == "tcp" || t == "udp"
}

// routeWAFMode is the mode of the WAF that inspects rt.
//
// Every "waf" middleware a route lists runs, so one that enforces refuses
// what it matches whatever the others do.
func routeWAFMode(rt *gateonv1.Route, mws map[string]*gateonv1.Middleware, global *gateonv1.WafConfig,
	resolve func(map[string]string) Mode) Mode {
	own := routeMiddlewares(rt, mws, typeWAF)
	if len(own) == 0 {
		return GlobalWAFMode(global)
	}
	if resolve == nil {
		resolve = func(cfg map[string]string) Mode { return routeWAFConfigMode(cfg, global) }
	}
	for _, mw := range own {
		if resolve(mw.GetConfig()) == ModeEnforce {
			return ModeEnforce
		}
	}
	return ModeDetect
}

// routeWAFConfigMode reads a route WAF's audit_only the way the WAF factory
// does. A route WAF inherits every setting it leaves unset -- an empty value
// is unset -- from the global WAF whenever that is enabled (ADR 0044,
// mergeGlobalWAF), so an unset audit_only under an enabled audit-only global
// WAF detects. It used to inherit only with use_crs on, which ADR 0044 removed.
func routeWAFConfigMode(cfg map[string]string, global *gateonv1.WafConfig) Mode {
	v := strings.ToLower(strings.TrimSpace(cfg[keyAuditOnly]))
	if v == "" && global.GetEnabled() {
		if global.GetAuditOnly() {
			return ModeDetect
		}
		return ModeEnforce
	}
	switch v {
	case "true", "1":
		return ModeDetect
	default:
		return ModeEnforce
	}
}

// routeScansSignatures reports whether rt runs a file_security middleware
// whose signature engine is on. enable_signature_scan defaults to on, and a
// malformed value refuses the middleware, so it scans nothing.
func routeScansSignatures(rt *gateonv1.Route, mws map[string]*gateonv1.Middleware) bool {
	for _, mw := range routeMiddlewares(rt, mws, typeFileSecurity) {
		if signatureScanOn(mw.GetConfig()[keySignatureScan]) {
			return true
		}
	}
	return false
}

// routeMiddlewares returns rt's middlewares of type typ, in chain order.
func routeMiddlewares(rt *gateonv1.Route, mws map[string]*gateonv1.Middleware, typ string) []*gateonv1.Middleware {
	var out []*gateonv1.Middleware
	for _, id := range rt.GetMiddlewares() {
		if mw, ok := mws[strings.TrimSpace(id)]; ok && mw.GetType() == typ {
			out = append(out, mw)
		}
	}
	return out
}

// signatureScanOn parses enable_signature_scan as the file_security factory
// does (kind.ParseBoolStrict, default on): empty is on, a malformed value
// refuses the whole middleware and so scans nothing.
func signatureScanOn(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return true
	}
	on, err := strconv.ParseBool(v)
	return err == nil && on
}
