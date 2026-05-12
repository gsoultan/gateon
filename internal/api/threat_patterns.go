package api

import (
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"sync"

	"github.com/gsoultan/gateon/internal/logger"
)

type ThreatPatterns struct {
	SuspiciousPath    string   `json:"suspicious_path"`
	SQLI              string   `json:"sqli"`
	XSS               string   `json:"xss"`
	Traversal         string   `json:"traversal"`
	RCE               string   `json:"rce"`
	SuspiciousAgent   string   `json:"suspicious_agent"`
	SuspiciousReferer string   `json:"suspicious_referer"`
	SSRF              string   `json:"ssrf"`
	NoSQLI            string   `json:"nosqli"`
	CommandInjection  string   `json:"command_injection"`
	ProtoPollution    string   `json:"proto_pollution"`
	HoneypotPaths     []string `json:"honeypot_paths"`
}

var (
	defaultPatterns = ThreatPatterns{
		SuspiciousPath:    `(?i)(\.env|\.git|\.htaccess|\.config|wp-admin|wp-login|phpinfo|/etc/passwd|win\.ini|cgi-bin|bin/sh|backup|db\.sql|config\.php|web-config|node_modules|169\.254\.169\.254|metadata\.google\.internal|\.aws/credentials|/etc/shadow|\.ssh/|/proc/self/|\.docker/config\.json|autoexec\.bat|web\.config)`,
		SQLI:              `(?i)(union\s+select|union\s+all\s+select|waitfor\s+delay|pg_sleep|sleep\(|benchmark\(|'(\s+)?or(\s+)?'1'(\s+)?=|--|;|\/\*|xp_cmdshell|information_schema|drop\s+table|truncate\s+table)`,
		XSS:               `(?i)(<script>|javascript:|onload=|onerror=|alert\(|prompt\(|confirm\(|eval\(|document\.cookie|window\.location|onmouseover=)`,
		Traversal:         `(?i)(\.\./|\.\.\\|/etc/|/var/log/|/windows/|/boot\.ini)`,
		RCE:               `(?i)(\$\{jndi:|()\s*\{\s*:\s*;\s*\}\s*;|base64\s*--decode|python\s+-c|perl\s+-e|php\s+-r|sh\s+-c|nc\s+-e|cmd\.exe|powershell\.exe)`,
		SuspiciousAgent:   `(?i)(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirb|dirbuster|ffuf|hydra|burp|metasploit|w3af)`,
		SuspiciousReferer: `(?i)(evil\.com|attacker|hacker|exploit|malicious|pwned)`,
		SSRF:              `(?i)(169\.254\.169\.254|metadata\.google\.internal|instance-data|v1/meta-data|latest/meta-data|localhost|127\.0\.0\.1|0\.0\.0\.0)`,
		NoSQLI:            `(?i)(\$gt|\$ne|\$in|\$where|\$regex|\$expr|\$exists)`,
		CommandInjection:  `(?i)(;|\d|\||&|\$\(|\x60)(?i)(cat|ls|id|whoami|pwd|uname|netstat|nc|bash|curl|wget|powershell|cmd|type|dir)`,
		ProtoPollution:    `(?i)(__proto__|constructor\.prototype)`,
		HoneypotPaths: []string{
			"/admin/setup.php",
			"/wp-content/plugins/wp-config.php",
			"/.aws/credentials",
			"/.env",
			"/.git/config",
			"/debug/vars",
			"/server-status",
			"/phpmyadmin/index.php",
		},
	}

	activePatterns   ThreatPatterns
	compiledPatterns struct {
		sync.RWMutex
		suspiciousPath    *regexp.Regexp
		sqlI              *regexp.Regexp
		xss               *regexp.Regexp
		traversal         *regexp.Regexp
		rce               *regexp.Regexp
		suspiciousAgent   *regexp.Regexp
		suspiciousReferer *regexp.Regexp
		ssrf              *regexp.Regexp
		nosqlI            *regexp.Regexp
		commandInjection  *regexp.Regexp
		protoPollution    *regexp.Regexp
	}
)

func init() {
	LoadPatterns("")
}

func LoadPatterns(path string) {
	patterns := defaultPatterns
	if path != "" {
		if data, err := os.ReadFile(path); err == nil {
			var p ThreatPatterns
			if err := json.Unmarshal(data, &p); err == nil {
				patterns = p
			}
		}
	}

	compiledPatterns.Lock()
	defer compiledPatterns.Unlock()

	activePatterns = patterns
	compiledPatterns.suspiciousPath = regexp.MustCompile(patterns.SuspiciousPath)
	compiledPatterns.sqlI = regexp.MustCompile(patterns.SQLI)
	compiledPatterns.xss = regexp.MustCompile(patterns.XSS)
	compiledPatterns.traversal = regexp.MustCompile(patterns.Traversal)
	compiledPatterns.rce = regexp.MustCompile(patterns.RCE)
	compiledPatterns.suspiciousAgent = regexp.MustCompile(patterns.SuspiciousAgent)
	compiledPatterns.suspiciousReferer = regexp.MustCompile(patterns.SuspiciousReferer)
	compiledPatterns.ssrf = regexp.MustCompile(patterns.SSRF)
	compiledPatterns.nosqlI = regexp.MustCompile(patterns.NoSQLI)
	compiledPatterns.commandInjection = regexp.MustCompile(patterns.CommandInjection)
	compiledPatterns.protoPollution = regexp.MustCompile(patterns.ProtoPollution)

	logger.L.LogInfo("Security threat patterns loaded")
}

func GetCompiledPatterns() (p struct {
	SuspiciousPath    *regexp.Regexp
	SQLI              *regexp.Regexp
	XSS               *regexp.Regexp
	Traversal         *regexp.Regexp
	RCE               *regexp.Regexp
	SuspiciousAgent   *regexp.Regexp
	SuspiciousReferer *regexp.Regexp
	SSRF              *regexp.Regexp
	NoSQLI            *regexp.Regexp
	CommandInjection  *regexp.Regexp
	ProtoPollution    *regexp.Regexp
	HoneypotPaths     []string
}) {
	compiledPatterns.RLock()
	defer compiledPatterns.RUnlock()

	p.SuspiciousPath = compiledPatterns.suspiciousPath
	p.SQLI = compiledPatterns.sqlI
	p.XSS = compiledPatterns.xss
	p.Traversal = compiledPatterns.traversal
	p.RCE = compiledPatterns.rce
	p.SuspiciousAgent = compiledPatterns.suspiciousAgent
	p.SuspiciousReferer = compiledPatterns.suspiciousReferer
	p.SSRF = compiledPatterns.ssrf
	p.NoSQLI = compiledPatterns.nosqlI
	p.CommandInjection = compiledPatterns.commandInjection
	p.ProtoPollution = compiledPatterns.protoPollution
	p.HoneypotPaths = slices.Clone(activePatterns.HoneypotPaths)
	return
}
