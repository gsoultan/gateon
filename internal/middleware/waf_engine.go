// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package middleware

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/request"
	secwaf "github.com/gsoultan/gateon/internal/security/waf"
	"github.com/gsoultan/gwaf"
)

// wafEngine is gateon's binding to gwaf.
//
// It replaces createWAFInstance, which built the engine by concatenating about
// twenty SecLang directives into a string. The difference that matters is not
// tidiness: a mistyped directive produced a rule that silently never fired and
// nothing could check it, whereas a Policy either compiles or returns an error.
type wafEngine struct {
	waf    *gwaf.WAF
	cfg    WAFConfig
	policy secwaf.Policy
	audit  *auditLog

	// allowedAdminNets is the parsed admin allowlist. It is computed once per
	// engine rather than re-split from a comma-separated string per request.
	allowedAdminNets []*net.IPNet
}

// categoryDisables maps gateon's per-family switches onto the rule categories
// and tags they turn off.
//
// Under Coraza these switches chose which CRS files to Include. There are no
// files now, so the same intent is expressed as selection over the corpus —
// which is strictly more precise, because a category and a tag describe what a
// rule detects rather than which file somebody filed it in.
type categoryDisable struct {
	categories []string
	tags       []string
}

func wafSelection(cfg WAFConfig) (categories, tags map[string]bool) {
	categories, tags = map[string]bool{}, map[string]bool{}

	switches := []struct {
		disabled bool
		d        categoryDisable
	}{
		{cfg.DisableSQLI, categoryDisable{[]string{"SQLi"}, []string{"attack-sqli"}}},
		{cfg.DisableXSS, categoryDisable{[]string{"XSS"}, []string{"attack-xss"}}},
		{cfg.DisableRCE, categoryDisable{[]string{"RCE"}, []string{"attack-rce", "rce"}}},
		{cfg.DisablePHP, categoryDisable{nil, []string{"php"}}},
		{cfg.DisableJava, categoryDisable{nil, []string{"java"}}},
		{cfg.DisableScanner, categoryDisable{[]string{"Scanner"}, []string{"scanner"}}},
		{cfg.DisableProtocol, categoryDisable{[]string{"Protocol"}, []string{"protocol"}}},
		{cfg.DisableWordPress, categoryDisable{[]string{"WordPress"}, []string{"wp_scan"}}},
		{cfg.DisableLFI, categoryDisable{nil, []string{"lfi"}}},
		{!cfg.EnableMalwareDetection, categoryDisable{[]string{"Malware"}, []string{"malware"}}},
		{!cfg.EnableRansomwareDetection, categoryDisable{[]string{"Ransomware"}, []string{"ransomware"}}},
		{!cfg.EnableDLP, categoryDisable{[]string{"DLP"}, []string{"dlp"}}},
		{!cfg.EnableIPReputation, categoryDisable{[]string{"Reputation"}, []string{"reputation"}}},
	}

	for _, s := range switches {
		if !s.disabled {
			continue
		}
		for _, c := range s.d.categories {
			categories[c] = true
		}
		for _, t := range s.d.tags {
			tags[t] = true
		}
	}
	return categories, tags
}

// newWAFEngine builds the engine a config describes.
func newWAFEngine(cfg WAFConfig, onDecision func(gwaf.Decision)) (*wafEngine, error) {
	categories, tags := wafSelection(cfg)

	policy := secwaf.Policy{
		ParanoiaLevel:      cfg.ParanoiaLevel,
		AnomalyThreshold:   cfg.AnomalyThreshold,
		DetectionOnly:      cfg.AuditOnly,
		FailOpen:           cfg.FailOpen,
		Limits:             wafLimits(cfg),
		ResponseInspection: cfg.EnableResponseInspection,
		DisabledCategories: categories,
		DisabledTags:       tags,
		AppProfiles:        cfg.AppProfiles,
		SSRFProtection:     cfg.EnableSSRFProtection,
		OnDecision:         onDecision,
	}

	policy.ExtraRules = append(policy.ExtraRules, cfg.ExtraRules...)
	loadOperatorTuning(&policy, cfg)

	w, err := policy.NewEngine()
	if err != nil {
		return nil, err
	}
	// A failing audit log is reported, not fatal. Refusing to start a gateway
	// because a log file could not be opened trades a security control for an
	// outage, and the WAF still blocks without it.
	audit, err := newAuditLog(cfg)
	if err != nil {
		logger.L.LogWarn("WAF audit log is disabled", "route", cfg.RouteID, "error", err)
	}
	return &wafEngine{
		audit:            audit,
		waf:              w,
		cfg:              cfg,
		policy:           policy,
		allowedAdminNets: secwaf.ParseAllowedAdminIPs(cfg.AllowedAdminIps),
	}, nil
}

// loadOperatorTuning folds the dashboard-authored parts of the policy in: the
// stored rules, the stored exceptions, and the platform profiles.
//
// Everything it cannot apply is logged rather than swallowed, and that is the
// reason it exists as one function. All three failures are the same failure —
// the operator is looking at a dashboard that says a protection or a suppression
// is in force, and it is not. Silence there is worse than the misconfiguration,
// because nothing else will ever reveal it.
func loadOperatorTuning(policy *secwaf.Policy, cfg WAFConfig) {
	if cfg.WafRules != nil {
		extra, problems := cfg.WafRules.CompiledRules(policy.ParanoiaLevel)
		policy.ExtraRules = append(policy.ExtraRules, extra...)
		for _, p := range problems {
			logger.L.LogWarn("WAF rule is not enforceable",
				"rule", p.ID, "name", p.Name, "route", cfg.RouteID, "error", p.Err)
		}
	}

	if store := secwaf.GetExceptionStore(); store != nil {
		exceptions, problems := store.Compiled()
		policy.Exceptions = exceptions
		for _, err := range problems {
			logger.L.LogWarn("WAF exception is not applied", "route", cfg.RouteID, "error", err)
		}
	}

	for _, name := range policy.UnknownAppProfiles() {
		logger.L.LogWarn("WAF app profile is not recognised",
			"profile", name, "route", cfg.RouteID, "known", secwaf.AppProfileNames())
	}
}

// wafLimits maps the configured byte ceilings onto the engine's.
//
// Every bound is stated. gwaf's defaults are sane, but a gateway inheriting a
// library's idea of how large a request may be is how an install ends up with a
// limit nobody chose and nobody can find.
func wafLimits(cfg WAFConfig) gwaf.Limits {
	l := gwaf.DefaultLimits()
	if cfg.RequestBodyLimit > 0 {
		l.MaxBodySize = cfg.RequestBodyLimit
		// A single value has to be able to hold a body-sized field, or an
		// ordinary base64 upload is refused as oversize. base64 expands by 4/3.
		if l.MaxValueLen < l.MaxBodySize*2 {
			l.MaxValueLen = l.MaxBodySize * 2
		}
		if l.MaxArenaSize < l.MaxBodySize*4 {
			l.MaxArenaSize = l.MaxBodySize * 4
		}
	}
	return l
}

// inspectRequest drives the request phases of one transaction.
//
// It returns the transaction so the caller can run the response phases, and a
// decision that is non-nil only when the request must be refused.
func (e *wafEngine) inspectRequest(r *http.Request, reputation float64) (*gwaf.Transaction, *gwaf.Decision, error) {
	tx := e.waf.NewTransaction()

	e.addResolvers(tx, r, reputation)

	host, port := splitAddr(r.RemoteAddr)
	tx.SetRemoteAddr(net.JoinHostPort(host, strconv.Itoa(port)))
	tx.SetRequestLine(r.Method, r.RequestURI, r.Proto)
	for name, values := range r.Header {
		for _, v := range values {
			tx.AddRequestHeader(name, v)
		}
	}

	if d := tx.ProcessRequestHeaders(); d.Blocked() {
		return tx, &d, nil
	}

	// The request-body phase runs whether or not there is a body. Query
	// arguments are recorded during SetRequestLine and stay visible here, and
	// most of the corpus inspects arguments, so skipping this phase on a GET
	// would silently disable those rules.
	if err := e.readRequestBody(tx, r); err != nil {
		return tx, nil, err
	}
	if d := tx.ProcessRequestBody(); d.Blocked() {
		return tx, &d, nil
	}
	return tx, nil, nil
}

// addResolvers supplies the signals gateon owns and gwaf never will.
//
// They are registered per transaction because each closes over this request.
// The engine calls a resolver only when a rule in the phase reads it, so an
// install whose reputation rules are disabled pays nothing for these.
func (e *wafEngine) addResolvers(tx *gwaf.Transaction, r *http.Request, reputation float64) {
	feedBlocked := false
	if e.cfg.EnableIPReputation && e.cfg.Reputation != nil {
		clientIP := request.GetClientIP(r, e.cfg.TrustCloudflare)
		if bad, score := e.cfg.Reputation.IsBad(clientIP); bad {
			feedBlocked = score >= e.cfg.Reputation.GetBlockThreshold()
		}
	}
	tx.AddResolver(secwaf.ReputationResolver{Score: reputation, FeedBlocked: feedBlocked})

	if !e.cfg.DisableWordPress {
		tx.AddResolver(secwaf.AdminAccessResolver{
			Path:     strings.ToLower(r.URL.Path),
			ClientIP: request.GetClientIP(r, e.cfg.TrustCloudflare),
			Allowed:  e.allowedAdminNets,
		})
	}
	tx.AddResolver(secwaf.OriginResolver{Request: r})
}

// readRequestBody hands the body to the engine and puts it back for the proxy.
//
// The body is read once, up to the configured limit, and replayed downstream
// from the buffer followed by whatever is left on the wire. Reading it twice
// would be wrong for a streaming upload and reading all of it would be an
// unbounded allocation keyed on request data.
func (e *wafEngine) readRequestBody(tx *gwaf.Transaction, r *http.Request) error {
	if r.Body == nil || r.Body == http.NoBody {
		return nil
	}
	limit := int64(e.policy.Limits.MaxBodySize)
	if limit <= 0 {
		limit = int64(gwaf.DefaultLimits().MaxBodySize)
	}

	buf := &bytes.Buffer{}
	original := r.Body
	// One byte past the limit, deliberately.
	//
	// Reading exactly the limit would hand the engine a body that is precisely
	// MaxBodySize long, which it accepts and inspects — while the remainder
	// went on to the origin uninspected. That is a bypass: an attacker pads to
	// the limit and puts the payload after it. The extra byte is what lets the
	// engine see that the body is oversize and refuse it.
	inspected, err := io.ReadAll(io.LimitReader(io.TeeReader(original, buf), limit+1))
	if err != nil {
		r.Body = struct {
			io.Reader
			io.Closer
		}{Reader: io.MultiReader(buf, original), Closer: original}
		return err
	}

	r.Body = struct {
		io.Reader
		io.Closer
	}{Reader: io.MultiReader(buf, original), Closer: original}

	tx.SetRequestBody(inspected)
	return nil
}
