// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package features turns one advisory sample into the row a learned model
// reads (ADR 0108).
//
// The same code builds a row when a model is taught and when it is asked. If
// the two ever differed, the model would be scored on something it never
// learned and nothing would say so, so there is exactly one Extract and both
// `gateon export-waf-features` and the advisory worker call it.
//
// Every column is computed from the sample the gateway already sends (ADR
// 0104): no body, no credential, no client address, no time. No column holds
// text the client wrote, only counts, shares and a few closed lists of
// categories, so a model cannot memorise a payload and an operator can read
// every column it was taught on.
package features

import (
	"strconv"

	"github.com/gsoultan/gateon/internal/security/waf/corpus"
)

// The answer column and its two values. A model taught on these rows picks
// one of them, and the worker reads the chance of LabelAttack.
const (
	LabelColumn = "label"
	LabelAttack = "attack"
	LabelClean  = "clean"
)

// Column names. They are the contract with a model already taught: renaming
// one makes every model taught before the rename read it as empty.
const (
	colSQLi          = "hits_sqli"
	colXSS           = "hits_xss"
	colRCE           = "hits_rce"
	colInjection     = "hits_injection"
	colExploit       = "hits_exploit"
	colProtocol      = "hits_protocol"
	colScanner       = "hits_scanner"
	colOther         = "hits_other"
	colMaxConfidence = "max_confidence"
	colAnomaly       = "anomaly_score"
	colGatewayRules  = "gateway_rules"
	colWhy           = "why"
	colMethod        = "method"
	colPathDepth     = "path_depth"
	colPathLength    = "path_length"
	colExtension     = "extension"
	colArgs          = "args"
	colHeaders       = "headers"
	colLongest       = "longest_value"
	colEncoded       = "encoded_share"
	colDouble        = "double_encoded"
	colEntropy       = "entropy_longest"
	colSymbols       = "symbol_share"
	colTraversal     = "dot_segments"
	colControl       = "control_bytes"
	colAgent         = "user_agent"
	colAccept        = "accept_missing"
	colContentType   = "content_type"
)

// Columns is every column of a row, in the order a CSV writes them.
var Columns = []string{
	colSQLi, colXSS, colRCE, colInjection, colExploit, colProtocol, colScanner, colOther,
	colMaxConfidence, colAnomaly, colGatewayRules, colWhy,
	colMethod, colPathDepth, colPathLength, colExtension, colArgs, colHeaders,
	colLongest, colEncoded, colDouble, colEntropy, colSymbols, colTraversal, colControl,
	colAgent, colAccept, colContentType,
}

// Input is one sample as Extract reads it.
type Input struct {
	Entry *corpus.Entry
	// Why is the reason the gateway sent it, or "" for a row built from a
	// corpus, which reads as "none".
	Why string
	// Rules are the rule numbers the gateway's own WAF matched.
	Rules []uint32
}

// Row is one sample's columns, in the order of Columns.
type Row struct {
	values []string
}

// index is each column's position in a row.
var index = func() map[string]int {
	m := make(map[string]int, len(Columns))
	for i, c := range Columns {
		m[c] = i
	}
	return m
}()

// Values returns the row in the order of Columns.
func (r Row) Values() []string { return r.values }

// Fields returns the row by column name, as a model is asked.
func (r Row) Fields() map[string]string {
	m := make(map[string]string, len(Columns))
	for i, c := range Columns {
		m[c] = r.values[i]
	}
	return m
}

// Extract builds the row for in, given what the strict rules found in it.
func Extract(in Input, hits []Hit) Row {
	r := Row{values: make([]string, len(Columns))}
	set := r.setter()
	signals(set, in, hits)
	e := in.Entry
	if e == nil {
		e = &corpus.Entry{}
	}
	shape(set, e)
	headers(set, e)
	return r
}

type setter func(column, value string)

func (r *Row) setter() setter {
	return func(column, value string) { r.values[index[column]] = value }
}

func itoa(n int) string { return strconv.Itoa(n) }

// ratio is a share or a measure, rounded so the same sample gives the same
// text on every platform.
func ratio(f float64) string { return strconv.FormatFloat(f, 'f', 3, 64) }

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
