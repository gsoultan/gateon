package siem

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// Format selects the wire encoding for exported events.
type Format string

const (
	// FormatJSON emits newline-delimited JSON (Elastic/OpenSearch/Wazuh, Splunk HEC).
	FormatJSON Format = "json"
	// FormatCEF emits ArcSight Common Event Format.
	FormatCEF Format = "cef"
	// FormatSyslog emits RFC 5424 structured syslog.
	FormatSyslog Format = "syslog"
)

const (
	vendor  = "JetBrains"
	product = "Gateon"
)

// formatter renders an Event into bytes for a given wire format.
type formatter interface {
	format(Event) []byte
}

// newFormatter returns the formatter for f, defaulting to JSON.
func newFormatter(f Format, version string) formatter {
	switch f {
	case FormatCEF:
		return cefFormatter{version: version}
	case FormatSyslog:
		return syslogFormatter{version: version, hostname: hostname()}
	default:
		return jsonFormatter{}
	}
}

type jsonFormatter struct{}

func (jsonFormatter) format(e Event) []byte {
	b, err := json.Marshal(e)
	if err != nil {
		return nil
	}
	return append(b, '\n')
}

type cefFormatter struct{ version string }

// format renders the ArcSight CEF header plus an extension of key=value pairs.
// Header: CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension
func (c cefFormatter) format(e Event) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "CEF:0|%s|%s|%s|%s|%s|%d|",
		cefEscapeHeader(vendor),
		cefEscapeHeader(product),
		cefEscapeHeader(cefVersion(c.version)),
		cefEscapeHeader(string(e.Kind)),
		cefEscapeHeader(cefName(e)),
		cefSeverity(e.Severity),
	)

	ext := map[string]string{}
	if e.SourceIP != "" {
		ext["src"] = e.SourceIP
	}
	if e.Message != "" {
		ext["msg"] = e.Message
	}
	ext["cat"] = string(e.Kind)
	ext["rt"] = fmt.Sprintf("%d", e.Time.UnixMilli())
	for k, v := range e.Fields {
		ext["cs_"+k] = v
	}

	for i, k := range sortedKeys(ext) {
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%s=%s", cefEscapeKey(k), cefEscapeValue(ext[k]))
	}
	b.WriteByte('\n')
	return []byte(b.String())
}

type syslogFormatter struct {
	version  string
	hostname string
}

// format renders an RFC 5424 message: <PRI>1 TIMESTAMP HOST APP - - SD MSG.
// Facility local0 (16); severity is mapped from the event severity.
func (s syslogFormatter) format(e Event) []byte {
	const facility = 16
	pri := facility*8 + syslogSeverity(e.Severity)
	ts := e.Time.UTC().Format(time.RFC3339Nano)

	var sd strings.Builder
	sd.WriteString("[gateon@0")
	fmt.Fprintf(&sd, " kind=%s", sdValue(string(e.Kind)))
	fmt.Fprintf(&sd, " severity=%s", sdValue(e.Severity))
	if e.SourceIP != "" {
		fmt.Fprintf(&sd, " src=%s", sdValue(e.SourceIP))
	}
	for _, k := range sortedKeys(e.Fields) {
		fmt.Fprintf(&sd, " %s=%s", sdName(k), sdValue(e.Fields[k]))
	}
	sd.WriteByte(']')

	msg := fmt.Sprintf("<%d>1 %s %s %s - - %s %s\n",
		pri, ts, s.hostname, product, sd.String(), e.Message)
	return []byte(msg)
}

// cefSeverity maps a textual severity to the CEF 0-10 scale.
func cefSeverity(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 10
	case "high":
		return 8
	case "medium":
		return 5
	case "low":
		return 2
	default:
		return 3
	}
}

// syslogSeverity maps a textual severity to RFC 5424 severity codes.
func syslogSeverity(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 2 // Critical
	case "high":
		return 3 // Error
	case "medium":
		return 4 // Warning
	case "low":
		return 5 // Notice
	default:
		return 6 // Informational
	}
}

func cefName(e Event) string {
	if e.Name != "" {
		return e.Name
	}
	return string(e.Kind)
}

func cefVersion(v string) string {
	if v == "" {
		return "dev"
	}
	return v
}

// CEF header fields escape backslash and pipe.
func cefEscapeHeader(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, "|", `\|`)
}

// CEF extension keys must not contain spaces or equals signs.
func cefEscapeKey(s string) string {
	s = strings.ReplaceAll(s, " ", "_")
	return strings.ReplaceAll(s, "=", "_")
}

// CEF extension values escape backslash, equals, and newlines.
func cefEscapeValue(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "=", `\=`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return strings.ReplaceAll(s, "\r", `\r`)
}

// sdName sanitizes an RFC 5424 SD-PARAM name (no space, =, ], ").
func sdName(s string) string {
	r := strings.NewReplacer(" ", "_", "=", "_", "]", "_", `"`, "_")
	return r.Replace(s)
}

// sdValue escapes an RFC 5424 SD-PARAM value (", \, ]) and wraps in quotes.
func sdValue(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "]", `\]`)
	return `"` + s + `"`
}

func sortedKeys(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "gateon"
	}
	return h
}
