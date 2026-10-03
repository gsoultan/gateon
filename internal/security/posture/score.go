// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package posture

import (
	"fmt"
	"math"
	"net"
	"strings"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// State is how much of a control is in effect.
type State string

const (
	// StateOn: the control refuses what it is for.
	StateOn State = "on"
	// StatePartial: it covers some of what it should, or only detects.
	StatePartial State = "partial"
	// StateOff: it is not in effect.
	StateOff State = "off"
)

// Control is one protection the posture score weighs.
type Control struct {
	ID     string  `json:"id"`
	Label  string  `json:"label"`
	Weight int     `json:"weight"`
	State  State   `json:"state"`
	Credit float64 `json:"credit"` // 0..1, the share of Weight earned
	Detail string  `json:"detail"`
}

// Score is the posture percentage and the controls it is the weighted sum of.
//
// The formula, also given in ADR 0048 and the dashboard tooltip:
//
//	percent = round( sum(weight_i * credit_i) ), weights summing to 100
//
// A control earns its full weight when it refuses traffic, half when it only
// detects (an audit-only WAF) or covers part of what it should, and nothing
// when it is off. Only configuration and its effective state are inputs:
// traffic, threats and client reputation are not, so no attacker's activity
// can move the number either way.
type Score struct {
	Percent  int       `json:"percent"`
	Controls []Control `json:"controls"`
}

// Control weights. They sum to 100.
const (
	weightWAF        = 40
	weightTLS        = 20
	weightManagement = 20
	weightAnomaly    = 10
	weightAudit      = 10
	halfCredit       = 0.5
)

// Compute scores the configuration in c.
func Compute(c Config) Score {
	controls := []Control{
		wafControl(c),
		tlsControl(c),
		managementControl(c),
		anomalyControl(c.Global),
		auditControl(c.Global),
	}
	var sum float64
	for _, ctl := range controls {
		sum += float64(ctl.Weight) * ctl.Credit
	}
	return Score{Percent: int(math.Round(sum)), Controls: controls}
}

// stateFor names a credit.
func stateFor(credit float64) State {
	switch {
	case credit >= 1:
		return StateOn
	case credit <= 0:
		return StateOff
	default:
		return StatePartial
	}
}

func newControl(id, label string, weight int, credit float64, detail string) Control {
	return Control{ID: id, Label: label, Weight: weight, State: stateFor(credit), Credit: credit, Detail: detail}
}

// modeCredit is what a WAF mode earns.
func modeCredit(m Mode) float64 {
	switch m {
	case ModeEnforce:
		return 1
	case ModeDetect:
		return halfCredit
	default:
		return 0
	}
}

// wafControl averages the WAF mode over the enabled HTTP routes; with no
// route, the gateway-wide WAF's mode stands for the routes still to come.
func wafControl(c Config) Control {
	const id, label = "waf", "Web application firewall"
	cov := Coverage(c)
	if cov.Total == 0 {
		mode := GlobalWAFMode(c.Global.GetWaf())
		return newControl(id, label, weightWAF, modeCredit(mode),
			fmt.Sprintf("No HTTP route yet; the gateway-wide WAF is %s.", modeWords(mode)))
	}
	credit := (float64(cov.Enforcing) + halfCredit*float64(cov.Detecting)) / float64(cov.Total)
	return newControl(id, label, weightWAF, credit,
		fmt.Sprintf("%d of %d routes blocking, %d detecting only (audit), %d with no WAF.",
			cov.Enforcing, cov.Total, cov.Detecting, cov.Off))
}

// modeWords is a mode as the dashboard says it.
func modeWords(m Mode) string {
	switch m {
	case ModeEnforce:
		return "blocking"
	case ModeDetect:
		return "detecting only (audit)"
	default:
		return "off"
	}
}

// tlsControl is the share of reachable HTTP-serving entrypoints that encrypt,
// counting a plaintext one that redirects every request to HTTPS as the
// listeners do (entrypoint.shouldRedirectToHTTPS).
func tlsControl(c Config) Control {
	const id, label = "tls", "TLS on reachable entrypoints"
	exposed, protected, plain := 0, 0, []string(nil)
	redirect := c.Global.GetTls().GetAutoRedirect() && anyTLSEntryPoint(c.EntryPoints)
	for _, ep := range c.EntryPoints {
		if !servesHTTP(ep) || loopbackOnly(ep.GetAddress()) {
			continue
		}
		exposed++
		if ep.GetTls().GetEnabled() || ep.GetType() == gateonv1.EntryPoint_HTTP3 || redirect {
			protected++
			continue
		}
		plain = append(plain, cmpName(ep))
	}
	if exposed == 0 {
		return newControl(id, label, weightTLS, 1, "No HTTP entrypoint is reachable from another host.")
	}
	detail := fmt.Sprintf("%d of %d reachable entrypoints encrypt.", protected, exposed)
	if len(plain) > 0 {
		detail += " Plaintext: " + strings.Join(plain, ", ") + "."
	}
	return newControl(id, label, weightTLS, float64(protected)/float64(exposed), detail)
}

// servesHTTP: every entrypoint but a UDP-only one can carry HTTP (a plaintext
// TCP entrypoint detects it), so every other one is weighed.
func servesHTTP(ep *gateonv1.EntryPoint) bool {
	return ep.GetType() != gateonv1.EntryPoint_UDP
}

func anyTLSEntryPoint(eps []*gateonv1.EntryPoint) bool {
	for _, ep := range eps {
		if ep.GetTls().GetEnabled() && servesHTTP(ep) {
			return true
		}
	}
	return false
}

// loopbackOnly reports whether addr binds only a loopback interface.
func loopbackOnly(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func cmpName(ep *gateonv1.EntryPoint) string {
	if n := strings.TrimSpace(ep.GetName()); n != "" {
		return n
	}
	return ep.GetAddress()
}

// managementControl: the dashboard served on every entrypoint earns nothing; a
// dedicated listener open to every address earns half.
func managementControl(c Config) Control {
	const id, label = "management", "Management plane not exposed"
	switch {
	case c.PublicManagement:
		return newControl(id, label, weightManagement, 0, "Public management is on: the admin API answers on every entrypoint.")
	case c.ManagementWorldOpen:
		return newControl(id, label, weightManagement, halfCredit, "The management listener accepts connections from any address.")
	default:
		return newControl(id, label, weightManagement, 1, "The management API is served only on its own restricted listener.")
	}
}

// anomalyControl: anomaly detection shuns brute force and exploit probing.
func anomalyControl(g *gateonv1.GlobalConfig) Control {
	const id, label = "anomaly", "Anomaly detection"
	if g.GetAnomalyDetection().GetEnabled() {
		return newControl(id, label, weightAnomaly, 1, "On: brute force and exploit probing are shunned.")
	}
	return newControl(id, label, weightAnomaly, 0, "Off.")
}

// auditControl: logging earns half, signing the entries the other half.
func auditControl(g *gateonv1.GlobalConfig) Control {
	const id, label = "audit", "Audit logging"
	switch a := g.GetAudit(); {
	case !a.GetEnabled():
		return newControl(id, label, weightAudit, 0, "Off: administrative actions are not recorded.")
	case !a.GetSignEntries():
		return newControl(id, label, weightAudit, halfCredit, "On, entries unsigned: tampering cannot be detected.")
	default:
		return newControl(id, label, weightAudit, 1, "On, entries signed.")
	}
}
