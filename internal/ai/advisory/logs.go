// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package advisory

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// logTally counts what a batch of log lines says. levels come from the line's
// own level; the request counts come from the status and path an access-log
// line carries, which is INFO whatever the status -- so a level count alone
// called 401s and a /.env probe healthy (truth T41).
type logTally struct {
	errors, warns, infos       int
	refused, serverErrs, probe int
	msgs                       map[string]int
}

// analyzeLogs produces a deterministic, human-readable summary of recent log
// lines (levels, refused and failed requests, probes, most frequent
// messages), without any external model.
func analyzeLogs(logs []string) string {
	if len(logs) == 0 {
		return "No logs were provided to analyze."
	}
	t := logTally{msgs: make(map[string]int)}
	for _, line := range logs {
		t.add(line)
	}
	var b strings.Builder
	b.Grow(256)
	fmt.Fprintf(&b, "Analyzed %d log lines: %d error, %d warning, %d info/other. ", len(logs), t.errors, t.warns, t.infos)
	b.WriteString(t.requestSentence())
	b.WriteString(t.verdict())
	writeTopMessages(&b, t.msgs)
	b.WriteString("(Local Mode: deterministic analysis on this server.)")
	return b.String()
}

func (t *logTally) add(line string) {
	fields := parseLogFields(line)
	t.addLevel(line, fields)
	switch status := fields["status"]; {
	case status == "401" || status == "403" || status == "429":
		t.refused++
	case len(status) == 3 && status[0] == '5':
		t.serverErrs++
	}
	if sensitiveProbePath(fields["path"]) {
		t.probe++
	}
	if key := extractLogMessage(line, fields); key != "" {
		t.msgs[key]++
	}
}

// addLevel counts the line's level: its level field, or for an unstructured
// line the level named as a word.
func (t *logTally) addLevel(line string, fields map[string]string) {
	level := strings.ToLower(fields["level"])
	switch {
	case level == logLevelError || (fields == nil && lineHasBareLevel(line, logLevelError, "ERROR")):
		t.errors++
	case level == "warn" || level == "warning" || (fields == nil && lineHasBareLevel(line, "warn", "WARN")):
		t.warns++
	default:
		t.infos++
	}
}

// logLevelError is slog's error level as a field value, lower-cased.
const logLevelError = "error"

// lineHasBareLevel reports whether an unstructured line (log.Logger's
// "2026/10/14 06:32:26 ERROR ...") names the level as a word. A structured
// line is never read this way: its level is a field, and the rest of it is
// text a client may have written.
func lineHasBareLevel(line, lower, upper string) bool {
	return strings.Contains(line, " "+lower+" ") || strings.Contains(line, " "+upper+" ")
}

// maxParsedLogLine bounds the line parseLogFields reads.
const maxParsedLogLine = 64 << 10

// parseLogFields reads the top-level fields of a slog JSON or text line, or
// returns nil for a line in neither form.
//
// The tally used to search the raw line for " status=" and " error ", and an
// access line carries the client's path before its status: a 503 to
// "/ status=200" read as served, and "/ error x" as an error. Reading fields
// the way slog wrote them -- a JSON object, or key=value pairs with quoted
// values unquoted -- leaves what the client wrote inside its own field.
func parseLogFields(line string) map[string]string {
	line = strings.TrimSpace(line)
	if len(line) > maxParsedLogLine {
		return nil
	}
	if strings.HasPrefix(line, "{") {
		return parseJSONLogFields(line)
	}
	return parseTextLogFields(line)
}

func parseJSONLogFields(line string) map[string]string {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return nil
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		var str string
		if err := json.Unmarshal(v, &str); err == nil {
			out[k] = str
			continue
		}
		if len(v) > 0 && v[0] != '{' && v[0] != '[' {
			out[k] = string(v)
		}
	}
	return out
}

// parseTextLogFields reads slog's text form: key=value pairs separated by a
// space, a value quoted (strconv.Quote) when it holds a space, '=' or '"'.
// A line without a level field is not one slog wrote.
func parseTextLogFields(line string) map[string]string {
	out := map[string]string{}
	for line != "" {
		eq := strings.IndexByte(line, '=')
		if eq <= 0 || strings.ContainsAny(line[:eq], ` "`) {
			break
		}
		value, next, ok := cutLogValue(line[eq+1:])
		if !ok {
			break
		}
		out[line[:eq]] = value
		line = strings.TrimLeft(next, " ")
	}
	if out["level"] == "" {
		return nil
	}
	return out
}

// cutLogValue reads one value from the front of s: a quoted string, or the
// text up to the next space.
func cutLogValue(s string) (value, rest string, ok bool) {
	if !strings.HasPrefix(s, `"`) {
		if sp := strings.IndexByte(s, ' '); sp >= 0 {
			return s[:sp], s[sp:], true
		}
		return s, "", true
	}
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			v, err := strconv.Unquote(s[:i+1])
			return v, s[i+1:], err == nil
		}
	}
	return "", "", false
}

// sensitiveProbePaths are paths only a scanner asks for: credentials,
// repository metadata and admin consoles that are not this gateway's.
var sensitiveProbePaths = []string{
	"/.env", "/.git", "/.aws", "/.ssh", "/.htpasswd", "/etc/passwd", "/wp-login.php", "/phpmyadmin", "/server-status",
}

func sensitiveProbePath(path string) bool {
	p := strings.ToLower(path)
	for _, s := range sensitiveProbePaths {
		if strings.HasPrefix(p, s) {
			return true
		}
	}
	return false
}

func (t *logTally) requestSentence() string {
	if t.refused == 0 && t.serverErrs == 0 && t.probe == 0 {
		return ""
	}
	return fmt.Sprintf("Requests: %d refused (401/403/429), %s, %s. ",
		t.refused, countOf(t.serverErrs, "server error (5xx)", "server errors (5xx)"),
		countOf(t.probe, "probe for a sensitive path", "probes for sensitive paths"))
}

// countOf is n with the noun it counts.
func countOf(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func (t *logTally) verdict() string {
	switch {
	case t.errors > 0 || t.serverErrs > 0:
		return "Errors are present and should be investigated first. "
	case t.refused > 0 || t.probe > 0:
		return "Requests were refused or probed for sensitive paths; check whether one client accounts for them. "
	case t.warns > 0:
		return "Warnings are present; review them for early signs of trouble. "
	default:
		return "No errors, warnings, refusals or probes detected — the gateway appears healthy. "
	}
}

// writeTopMessages appends the three most frequent messages.
func writeTopMessages(b *strings.Builder, msgCounts map[string]int) {
	type kv struct {
		msg   string
		count int
	}
	top := make([]kv, 0, len(msgCounts))
	for m, c := range msgCounts {
		top = append(top, kv{m, c})
	}
	if len(top) == 0 {
		return
	}
	slices.SortFunc(top, func(a, b kv) int {
		if a.count != b.count {
			return cmp.Compare(b.count, a.count)
		}
		return strings.Compare(a.msg, b.msg)
	})
	b.WriteString("Most frequent messages: ")
	for i := range min(3, len(top)) {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(b, "%q (×%d)", top[i].msg, top[i].count)
	}
	b.WriteString(". ")
}

// extractLogMessage is the line's msg field, or a trimmed prefix of an
// unstructured line, so similar lines group together.
func extractLogMessage(line string, fields map[string]string) string {
	if fields != nil {
		return fields["msg"]
	}
	line = strings.TrimSpace(line)
	if len(line) > 60 {
		return line[:60]
	}
	return line
}

func humanizeThreatType(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "unknown"
	}
	return strings.ReplaceAll(s, "_", " ")
}
