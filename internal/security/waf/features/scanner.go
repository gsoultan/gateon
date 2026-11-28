// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package features

import (
	"net/url"
	"slices"
	"strings"

	secwaf "github.com/gsoultan/gateon/internal/security/waf"
	"github.com/gsoultan/gateon/internal/security/waf/corpus"
	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/types"
)

// Hit is one rule the strict rules matched in a sample.
type Hit struct {
	Rule uint32
	// Column is the family the rule is counted in.
	Column     string
	Confidence types.Confidence
	Score      int
}

// Scanner runs the gateway's rules over a sample with every family on, at a
// paranoia level, detecting only, so every rule that matches is counted and
// not just the one that would have refused. Those counts are the weak signals
// a model weighs: a single low-confidence match is noise, several families at
// once on the same request rarely are.
//
// It is safe for concurrent use.
type Scanner struct {
	engine *gwaf.WAF
	// column is the column each loaded rule is counted in, worked out once
	// from the rule's tags when the scanner is built.
	column map[uint32]string
}

// NewScanner returns a scanner at paranoia level pl, 1 to 4.
func NewScanner(pl int) (*Scanner, error) {
	engine, err := secwaf.Policy{ParanoiaLevel: pl, FailOpen: true, DetectionOnly: true}.NewEngine()
	if err != nil {
		return nil, err
	}
	column := make(map[uint32]string)
	for _, r := range engine.Ruleset().All() {
		column[uint32(r.Rule.ID)] = columnFor(uint32(r.Rule.ID), r.Rule.Tags)
	}
	return &Scanner{engine: engine, column: column}, nil
}

// Scan returns every rule that matched e, once each. A rule that refuses on
// reputation is left out (see columnFor).
func (s *Scanner) Scan(e *corpus.Entry) []Hit {
	if e == nil || e.Target == "" {
		return nil
	}
	tx := s.engine.NewTransaction()
	defer tx.Close()
	tx.AddResolver(secwaf.ReputationResolver{Score: 100})

	method := e.Method
	if method == "" {
		method = "GET"
	}
	tx.SetRequestLine(method, RequestURI(e.Target, e.Args), "HTTP/1.1")
	for name, value := range e.Headers {
		tx.AddRequestHeader(name, value)
	}
	var hits []Hit
	tx.ProcessRequestHeaders()
	hits = s.appendHits(hits, tx.Matches())
	tx.ProcessRequestBody()
	return s.appendHits(hits, tx.Matches())
}

// appendHits copies ms, which the transaction owns, onto hits, once per
// rule however many phases matched it.
func (s *Scanner) appendHits(hits []Hit, ms []gwaf.Match) []Hit {
next:
	for _, m := range ms {
		id := uint32(m.RuleID)
		col := s.column[id]
		if col == "" || secwaf.RepeatsEarlierDecision(id) {
			continue
		}
		for _, h := range hits {
			if h.Rule == id {
				continue next
			}
		}
		score := m.Score
		if score == 0 {
			score = m.Severity.Score()
		}
		hits = append(hits, Hit{Rule: id, Column: col, Confidence: m.Confidence, Score: score})
	}
	return hits
}

// RequestURI puts a sample's query parameters back on its path. The order
// and the encoding the client used are not in a sample, so an attack that
// lives in either is not one a scanner can see. A target that already
// carries a query, as a hand-written corpus's does, keeps it.
func RequestURI(target string, args map[string]string) string {
	if len(args) == 0 {
		return target
	}
	q := make(url.Values, len(args))
	for name, value := range args {
		q.Set(name, value)
	}
	sep := "?"
	if strings.Contains(target, "?") {
		sep = "&"
	}
	return target + sep + q.Encode()
}

// tagColumn is the column a rule is counted in by its tags, the first tag
// that names a family winning. The tags are gwaf's and the gateway's own, so
// a family a rule belongs to is the one its authors gave it.
var tagColumn = map[string]string{
	"sqli": colSQLi, "nosqli": colSQLi, secwaf.TagAttackSqli: colSQLi,
	"xss": colXSS, secwaf.TagAttackXss: colXSS,
	secwaf.TagRce: colRCE, secwaf.TagAttackRce: colRCE, "shelli": colRCE, "webshell": colRCE,
	secwaf.TagPhp: colRCE, secwaf.TagJava: colRCE, "deserialization": colRCE,
	"ssti": colInjection, "spel": colInjection, "xxe": colInjection, "xslt": colInjection,
	"yaml": colInjection, "llm": colInjection, "ldapi": colInjection, "crlf": colInjection,
	"traversal": colExploit, "lfi": colExploit, "rfi": colExploit, "ssrf": colExploit,
	"redirect": colExploit, "upload": colExploit,
	secwaf.TagProtocol: colProtocol, "dos": colProtocol, "response-splitting": colProtocol,
	secwaf.TagScanner: colScanner, "recon": colScanner,
}

// categoryColumn is the column of a gateway rule's category, for a rule
// whose tags name no family.
var categoryColumn = map[string]string{
	secwaf.CategorySQLi:      colSQLi,
	secwaf.CategoryXSS:       colXSS,
	secwaf.CategoryRCE:       colRCE,
	secwaf.CategoryInjection: colInjection,
	secwaf.CategoryExploit:   colExploit,
	secwaf.CategoryProtocol:  colProtocol,
	secwaf.CategoryScanner:   colScanner,
}

// columnFor is the column rule id is counted in, or "" for a rule that is
// not counted: one that refuses on reputation, which the scanner can only
// ever feed the score it was given.
func columnFor(id uint32, tags []string) string {
	category := ""
	if info, ok := secwaf.LookupRule(id); ok {
		category = info.Category
	}
	if category == secwaf.CategoryReputation || slices.Contains(tags, secwaf.TagReputation) {
		return ""
	}
	for _, t := range tags {
		if col, ok := tagColumn[t]; ok {
			return col
		}
	}
	if col, ok := categoryColumn[category]; ok {
		return col
	}
	return colOther
}

// familyColumns are the columns rules are counted in.
var familyColumns = []string{colSQLi, colXSS, colRCE, colInjection, colExploit, colProtocol, colScanner, colOther}

// signals fills the columns that come from the rules.
func signals(set setter, in Input, hits []Hit) {
	counts := make(map[string]int, len(familyColumns))
	maxConf, anomaly := -1, 0
	for _, h := range hits {
		counts[h.Column]++
		maxConf = max(maxConf, int(h.Confidence))
		anomaly += h.Score
	}
	for _, col := range familyColumns {
		set(col, itoa(counts[col]))
	}
	// -1 is "nothing matched", below Heuristic's 0, so that no match and a
	// research-grade match are not the same number.
	set(colMaxConfidence, itoa(maxConf))
	set(colAnomaly, itoa(anomaly))
	set(colGatewayRules, itoa(len(in.Rules)))
	set(colWhy, whyValue(in.Why))
}

func whyValue(why string) string {
	switch why {
	case "matched", "outside_schema", "sampled":
		return why
	}
	return valueNone
}
