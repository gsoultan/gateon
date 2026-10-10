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
	// ModeNoCategories is a WAF with every attack-category switch off: it
	// inspects, but refuses none of the attacks the categories name.
	ModeNoCategories Mode = "no_categories"
)

// Middleware types and keys read here, spelled as the factory spells them.
const (
	typeWAF           = "waf"
	typeFileSecurity  = "file_security"
	typeBotManagement = "bot_management"
	typeRateLimit     = "ratelimit"
	typeInflight      = "inflightreq"
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
	// GlobalWAF, when set, is the mode the gateway-wide WAF runs in, as the
	// WAF package builds it (tier and category switches applied). Without it
	// the mode is read from the proto (GlobalWAFMode).
	GlobalWAF func() Mode
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
	// RateLimited is how many routes carry a ratelimit or inflightreq
	// middleware: the controls that bound what one bursty client costs a
	// backend. The WAF's dos_protection flag selects no rule (ADR 0044).
	RateLimited int `json:"rateLimited"`
	// CategoriesOff is how many routes run a WAF with every attack-category
	// switch off. Such a WAF still runs the rules no switch names (malware,
	// cloud-metadata SSRF), but blocks none of SQLi, XSS, LFI, RCE and the
	// rest, so it earns no WAF credit and is not counted as blocking.
	CategoriesOff int `json:"categoriesOff"`
}

// AttackCategoryKeys are a route WAF's attack-category switches, spelled as
// its config keys. A WAF with all of them off blocks none of the attacks the
// posture's WAF control is about.
var AttackCategoryKeys = []string{
	"sqli", "xss", "lfi", "rce", "php", "java", "nodejs", "scanner", "protocol", "wordpress",
}

// GlobalWAFMode is the mode the gateway-wide WAF runs in, read from its
// config: a WAF whose category switches turn every attack family off (ADR
// 0064) refuses none of them, whatever its mode -- as a route WAF with every
// switch off does not (truth NEW-13). It cannot see the tier; GlobalMode with
// a GlobalWAF resolver can.
func GlobalWAFMode(w *gateonv1.WafConfig) Mode {
	switch {
	case !w.GetEnabled():
		return ModeOff
	case globalCategoriesAllOff(w):
		return ModeNoCategories
	case w.GetAuditOnly():
		return ModeDetect
	default:
		return ModeEnforce
	}
}

// GlobalMode is the gateway-wide WAF's mode for c: its GlobalWAF resolver's
// answer when it has one, else GlobalWAFMode.
func GlobalMode(c Config) Mode {
	if c.GlobalWAF != nil {
		return c.GlobalWAF()
	}
	return GlobalWAFMode(c.Global.GetWaf())
}

// GlobalCategoriesOff names the attack families the gateway-wide WAF's
// switches turn off explicitly, in AttackCategoryKeys order. An unset switch
// is not off (ADR 0064).
func GlobalCategoriesOff(w *gateonv1.WafConfig) []string {
	var off []string
	for _, k := range AttackCategoryKeys {
		if on, set := globalCategory(w, k); set && !on {
			off = append(off, k)
		}
	}
	return off
}

// globalCategoriesAllOff reports whether every attack family is off on the
// gateway-wide WAF: each family switch explicitly false, and the WordPress
// rules, which are opt-in there, not turned on.
func globalCategoriesAllOff(w *gateonv1.WafConfig) bool {
	return len(GlobalCategoriesOff(w)) == len(AttackCategoryKeys)-1 && !w.GetWordpress()
}

// globalRunsFamily reports whether the gateway-wide WAF runs the attack
// family k, which a route WAF leaving k unset inherits: WordPress only when it
// is turned on, every other family unless its switch is explicitly off.
func globalRunsFamily(w *gateonv1.WafConfig, k string) bool {
	if k == "wordpress" {
		return w.GetWordpress()
	}
	on, set := globalCategory(w, k)
	return on || !set
}

// globalCategory is the gateway-wide WAF's switch for the attack family k,
// and whether it is set. WordPress is a plain opt-in there and never reports
// set.
func globalCategory(w *gateonv1.WafConfig, k string) (on, set bool) {
	c := w.GetCategories()
	if c == nil {
		return false, false
	}
	var v *bool
	switch k {
	case "sqli":
		v = c.Sqli
	case "xss":
		v = c.Xss
	case "lfi":
		v = c.Lfi
	case "rce":
		v = c.Rce
	case "php":
		v = c.Php
	case "java":
		v = c.Java
	case "nodejs":
		v = c.Nodejs
	case "scanner":
		v = c.Scanner
	case "protocol":
		v = c.Protocol
	}
	if v == nil {
		return false, false
	}
	return *v, true
}

// Coverage walks every enabled HTTP route the way the router composes it: a
// route that attaches its own "waf" middleware runs that WAF instead of the
// gateway-wide one (router.ApplyRouteMiddlewares), so its mode is its own;
// every other route runs the global WAF, if any.
func Coverage(c Config) RouteCoverage {
	var cov RouteCoverage
	for _, rt := range c.Routes {
		if rt.GetDisabled() || isL4(rt.GetType()) {
			continue
		}
		cov.Total++
		switch routeWAFMode(rt, c) {
		case ModeEnforce:
			cov.Enforcing++
		case ModeDetect:
			cov.Detecting++
		case ModeNoCategories:
			cov.CategoriesOff++
		default:
			cov.Off++
		}
		if routeScansSignatures(rt, c.Middlewares) {
			cov.SignatureScanning++
		}
		if len(routeMiddlewares(rt, c.Middlewares, typeBotManagement)) > 0 {
			cov.BotManagement++
		}
		if len(routeMiddlewares(rt, c.Middlewares, typeRateLimit))+
			len(routeMiddlewares(rt, c.Middlewares, typeInflight)) > 0 {
			cov.RateLimited++
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
func routeWAFMode(rt *gateonv1.Route, c Config) Mode {
	own := routeMiddlewares(rt, c.Middlewares, typeWAF)
	if len(own) == 0 {
		return GlobalMode(c)
	}
	global, resolve := c.Global.GetWaf(), c.RouteWAF
	if resolve == nil {
		resolve = func(cfg map[string]string) Mode { return routeWAFConfigMode(cfg, global) }
	}
	best := ModeNoCategories
	for _, mw := range own {
		switch resolve(mw.GetConfig()) {
		case ModeEnforce:
			return ModeEnforce
		case ModeDetect:
			best = ModeDetect
		}
	}
	return best
}

// routeWAFConfigMode reads a route WAF's audit_only the way the WAF factory
// does. A route WAF inherits every setting it leaves unset -- an empty value
// is unset -- from the global WAF whenever that is enabled (ADR 0044,
// mergeGlobalWAF), so an unset audit_only under an enabled audit-only global
// WAF detects. It used to inherit only with use_crs on, which ADR 0044 removed.
func routeWAFConfigMode(cfg map[string]string, global *gateonv1.WafConfig) Mode {
	if everyCategoryOff(cfg, global) {
		return ModeNoCategories
	}
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

// everyCategoryOff reports whether a route WAF config switches off every
// attack category, read as the WAF factory reads a switch: only an explicit
// "false" turns one off, and an unset key inherits what the enabled global
// WAF runs (globalRunsFamily, ADR 0064).
func everyCategoryOff(cfg map[string]string, global *gateonv1.WafConfig) bool {
	for _, k := range AttackCategoryKeys {
		v := strings.ToLower(strings.TrimSpace(cfg[k]))
		if v == "" && global.GetEnabled() && !globalRunsFamily(global, k) {
			continue
		}
		if v != "false" {
			return false
		}
	}
	return true
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
