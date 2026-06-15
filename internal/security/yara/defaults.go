package yara

// defaultEngine is the built-in ruleset, compiled once at package init. It is
// intentionally conservative: rules block on High/Critical signatures that are
// strong indicators of malicious uploads, while lower-confidence indicators are
// Medium/Low so consumers can log-only.
var defaultEngine = mustBuild(defaultRules())

// mustBuild compiles rules and panics on error. It is only ever called with the
// static built-in ruleset, so a panic indicates a programming error caught by
// the package's tests rather than a runtime/operator condition.
func mustBuild(rules []Rule) *Engine {
	e, err := New(rules)
	if err != nil {
		panic("yara: invalid built-in ruleset: " + err.Error())
	}
	return e
}

// DefaultRules returns a copy of the built-in rule definitions. Operators can
// use it as a starting point for custom rule sets.
func DefaultRules() []Rule {
	return defaultRules()
}

// defaultRules returns the built-in detection signatures. Each call returns a
// fresh slice so callers cannot mutate shared state.
func defaultRules() []Rule {
	return []Rule{
		{
			Name:        "eicar_test_file",
			Description: "EICAR anti-malware test file",
			Severity:    SeverityCritical,
			Tags:        []string{"test", "malware"},
			Strings: []Pattern{
				{Text: `EICAR-STANDARD-ANTIVIRUS-TEST-FILE`},
			},
		},
		{
			Name:        "windows_pe_dropper",
			Description: "Windows PE executable (DOS stub) embedded in upload",
			Severity:    SeverityHigh,
			Tags:        []string{"executable", "windows"},
			MITRE:       []string{"T1204"},
			Strings: []Pattern{
				{Text: "This program cannot be run in DOS mode"},
			},
		},
		{
			Name:        "elf_executable",
			Description: "Linux ELF executable magic bytes",
			Severity:    SeverityHigh,
			Tags:        []string{"executable", "linux"},
			MITRE:       []string{"T1204"},
			Strings: []Pattern{
				{Hex: "7f454c46"}, // \x7fELF
			},
		},
		{
			Name:        "php_webshell",
			Description: "PHP code executing attacker-controlled input (webshell)",
			Severity:    SeverityCritical,
			Tags:        []string{"webshell", "php"},
			MITRE:       []string{"T1505.003"},
			Mode:        MatchAny,
			Strings: []Pattern{
				{Text: `eval($_POST`, CaseInsensitive: true},
				{Text: `eval($_GET`, CaseInsensitive: true},
				{Text: `eval($_REQUEST`, CaseInsensitive: true},
				{Text: `assert($_`, CaseInsensitive: true},
				{Text: `base64_decode($_`, CaseInsensitive: true},
				{Text: `system($_`, CaseInsensitive: true},
				{Text: `shell_exec($_`, CaseInsensitive: true},
				{Text: `passthru($_`, CaseInsensitive: true},
				{Text: `preg_replace("/.*/e"`, CaseInsensitive: true},
			},
		},
		{
			Name:        "jsp_aspx_webshell",
			Description: "JSP/ASPX code spawning a process (webshell)",
			Severity:    SeverityCritical,
			Tags:        []string{"webshell", "java", "dotnet"},
			MITRE:       []string{"T1505.003"},
			Mode:        MatchAny,
			Strings: []Pattern{
				{Text: `Runtime.getRuntime().exec`},
				{Text: `new ProcessBuilder`},
				{Text: `System.Diagnostics.Process`},
			},
		},
		{
			Name:        "reverse_shell",
			Description: "Reverse-shell / remote-command payload",
			Severity:    SeverityHigh,
			Tags:        []string{"reverse-shell"},
			MITRE:       []string{"T1059"},
			Mode:        MatchAny,
			Strings: []Pattern{
				{Text: `/dev/tcp/`},
				{Text: `bash -i >&`},
				{Text: `nc -e `},
				{Text: `mkfifo /tmp/`},
				{Text: `socket.SOCK_STREAM`},
			},
		},
		{
			Name:        "powershell_encoded_command",
			Description: "PowerShell encoded/hidden command execution",
			Severity:    SeverityHigh,
			Tags:        []string{"powershell", "windows"},
			MITRE:       []string{"T1059.001"},
			Mode:        MatchAll,
			Strings: []Pattern{
				{Text: `powershell`, CaseInsensitive: true},
				{Text: `-enc`, CaseInsensitive: true},
			},
		},
		{
			Name:        "pdf_javascript",
			Description: "PDF document with embedded JavaScript",
			Severity:    SeverityMedium,
			Tags:        []string{"pdf", "active-content"},
			MITRE:       []string{"T1204.002"},
			Mode:        MatchAll,
			Strings: []Pattern{
				{Text: `%PDF-`},
				{Text: `/JavaScript`},
			},
		},
		{
			Name:        "pdf_auto_launch",
			Description: "PDF document with auto-launch/open action",
			Severity:    SeverityHigh,
			Tags:        []string{"pdf", "active-content"},
			MITRE:       []string{"T1204.002"},
			Mode:        MatchAll,
			Strings: []Pattern{
				{Text: `%PDF-`},
				{Text: `/Launch`},
			},
		},
		{
			Name:        "office_macro_autoexec",
			Description: "Office document with auto-executing VBA macro",
			Severity:    SeverityMedium,
			Tags:        []string{"office", "macro"},
			MITRE:       []string{"T1059.005"},
			Mode:        MatchAny,
			Strings: []Pattern{
				{Text: `Auto_Open`},
				{Text: `AutoOpen`},
				{Text: `Document_Open`},
				{Text: `Workbook_Open`},
			},
		},
		{
			Name:        "embedded_html_script",
			Description: "HTML <script> content embedded in an upload (possible polyglot/XSS)",
			Severity:    SeverityMedium,
			Tags:        []string{"html", "xss", "polyglot"},
			MITRE:       []string{"T1059.007"},
			Mode:        MatchAny,
			Strings: []Pattern{
				{Text: `<script`, CaseInsensitive: true},
				{Text: `javascript:`, CaseInsensitive: true},
				{Text: `onerror=`, CaseInsensitive: true},
			},
		},
	}
}
