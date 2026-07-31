package waf

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gsoultan/gateon/internal/db"
	"github.com/gsoultan/gateon/internal/logger"
)

type Invalidator interface {
	Invalidate()
}

type Store struct {
	db          *sql.DB
	dialect     db.Dialect
	cache       []Rule
	mu          sync.RWMutex
	invalidator Invalidator
}

var (
	globalStore *Store
	storeOnce   sync.Once
)

// NewStore creates a new WAF rule store.
func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// NewStoreWithDialect creates a new WAF rule store with a specific dialect.
func NewStoreWithDialect(db *sql.DB, dialect db.Dialect) *Store {
	return &Store{db: db, dialect: dialect}
}

// InitStore initializes the WAF rule store and loads rules into memory.
func InitStore(databaseURL string) error {
	var err error
	storeOnce.Do(func() {
		d, dialect, openErr := db.Open(databaseURL)
		if openErr != nil {
			err = openErr
			return
		}
		globalStore = &Store{db: d, dialect: dialect}
		if migrateErr := db.Migrate(d, dialect); migrateErr != nil {
			logger.L.LogError("failed to migrate WAF rules table", "error", migrateErr)
		}
		if reloadErr := globalStore.Reload(context.Background()); reloadErr != nil {
			logger.L.LogWarn("failed to load initial WAF rules", "error", reloadErr)
		}
		if seedErr := globalStore.Seed(context.Background()); seedErr != nil {
			logger.L.LogWarn("failed to seed WAF rules", "error", seedErr)
		}
	})
	return err
}

// GetStore returns the global WAF rule store.
func GetStore() *Store {
	return globalStore
}

// Reload refreshes the in-memory cache from the database.
func (s *Store) Reload(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, "SELECT id, name, directive, enabled, paranoia_level, category, created_at, updated_at FROM waf_rules ORDER BY id ASC")
	if err != nil {
		return err
	}
	defer rows.Close()

	var rules []Rule
	for rows.Next() {
		var r Rule
		if err := rows.Scan(&r.ID, &r.Name, &r.Directive, &r.Enabled, &r.ParanoiaLevel, &r.Category, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return err
		}
		rules = append(rules, r)
	}

	s.mu.Lock()
	s.cache = rules
	s.mu.Unlock()
	return nil
}

// GetEnabledRules returns all currently enabled WAF rules from the cache.
func (s *Store) GetEnabledRules() []Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var enabled []Rule
	for _, r := range s.cache {
		if r.Enabled {
			enabled = append(enabled, r)
		}
	}
	return enabled
}

// GetRule returns a specific rule by ID from the cache.
func (s *Store) GetRule(id string) (Rule, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.cache {
		if r.ID == id {
			return r, true
		}
	}
	return Rule{}, false
}

// GetAllRules returns all WAF rules from the cache.
func (s *Store) GetAllRules() []Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	// Return a copy to avoid external modification of cache
	res := make([]Rule, len(s.cache))
	copy(res, s.cache)
	return res
}

// ListRules returns a paginated list of WAF rules from the database with optional search and category filter.
func (s *Store) ListRules(ctx context.Context, limit, offset int, search, category string) ([]Rule, int, error) {
	var rules []Rule
	var total int

	query := "SELECT id, name, directive, enabled, paranoia_level, category, created_at, updated_at FROM waf_rules"
	countQuery := "SELECT COUNT(*) FROM waf_rules"
	var args []any
	var conditions []string

	if search != "" {
		conditions = append(conditions, "(id LIKE ? OR name LIKE ? OR directive LIKE ? OR category LIKE ?)")
		searchArg := "%" + search + "%"
		args = append(args, searchArg, searchArg, searchArg, searchArg)
	}

	if category != "" && category != "all" {
		conditions = append(conditions, "category = ?")
		args = append(args, category)
	}

	if len(conditions) > 0 {
		where := " WHERE " + strings.Join(conditions, " AND ")
		query += where
		countQuery += where
	}

	// Get total count
	err := s.db.QueryRowContext(ctx, s.dialect.Rebind(countQuery), args...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	query += " ORDER BY id ASC"
	if limit > 0 {
		query += " LIMIT ? OFFSET ?"
		args = append(args, limit, offset)
	}

	rows, err := s.db.QueryContext(ctx, s.dialect.Rebind(query), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	for rows.Next() {
		var r Rule
		if err := rows.Scan(&r.ID, &r.Name, &r.Directive, &r.Enabled, &r.ParanoiaLevel, &r.Category, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, 0, err
		}
		rules = append(rules, r)
	}

	return rules, total, nil
}

func (s *Store) SetInvalidator(i Invalidator) {
	s.mu.Lock()
	s.invalidator = i
	s.mu.Unlock()
}

func (s *Store) notifyInvalidation() {
	s.mu.RLock()
	i := s.invalidator
	s.mu.RUnlock()
	if i != nil {
		i.Invalidate()
	}
}

// AddRule inserts a new rule into the database and reloads the cache.
func (s *Store) AddRule(ctx context.Context, r *Rule) error {
	if r.ID == "" {
		r.ID = uuid.New().String()
	}
	now := time.Now()
	query := s.dialect.Rebind("INSERT INTO waf_rules (id, name, directive, enabled, paranoia_level, category, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
	_, err := s.db.ExecContext(ctx, query,
		r.ID, r.Name, r.Directive, r.Enabled, r.ParanoiaLevel, r.Category, now, now)
	if err != nil {
		return err
	}
	r.CreatedAt = now
	r.UpdatedAt = now
	if err := s.Reload(ctx); err != nil {
		return err
	}
	s.notifyInvalidation()
	return nil
}

// UpdateRule updates an existing rule in the database and reloads the cache.
func (s *Store) UpdateRule(ctx context.Context, r *Rule) error {
	now := time.Now()
	query := s.dialect.Rebind("UPDATE waf_rules SET name = ?, directive = ?, enabled = ?, paranoia_level = ?, category = ?, updated_at = ? WHERE id = ?")
	_, err := s.db.ExecContext(ctx, query,
		r.Name, r.Directive, r.Enabled, r.ParanoiaLevel, r.Category, now, r.ID)
	if err != nil {
		return err
	}
	r.UpdatedAt = now
	if err := s.Reload(ctx); err != nil {
		return err
	}
	s.notifyInvalidation()
	return nil
}

// DeleteRule removes a rule from the database and reloads the cache.
func (s *Store) DeleteRule(ctx context.Context, id string) error {
	query := s.dialect.Rebind("DELETE FROM waf_rules WHERE id = ?")
	_, err := s.db.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}
	if err := s.Reload(ctx); err != nil {
		return err
	}
	s.notifyInvalidation()
	return nil
}

// Seed populates the database with default rules. It ensures all initial rules exist
// and adds any missing ones, even if the table is not empty.
func (s *Store) Seed(ctx context.Context) error {
	initialRules := []Rule{
		{
			ID:            "1900300",
			Name:          "Redact Sensitive Headers",
			Directive:     `SecAction "id:1900300,phase:1,nolog,pass,setvar:tx.redact_headers=Authorization,setvar:tx.redact_headers=X-Api-Key,setvar:tx.redact_headers=Cookie,setvar:tx.redact_headers=Set-Cookie"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Compliance",
		},
		{
			ID:            "1900015",
			Name:          "Set Server Name from Host",
			Directive:     `SecRule REQUEST_HEADERS:Host "^(.+)$" "id:1900015,phase:1,nolog,pass,t:none,setvar:tx.server_name=%{MATCHED_VAR}"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Initialization",
		},
		{
			ID:            "1210001",
			Name:          "Online Gambling Site Detection",
			Directive:     `SecRule ARGS|REQUEST_HEADERS|REQUEST_FILENAME|XML:/* "@pm betting gambling casino slot machine poker sportsbook jackpot lottery bookmaker odds payout wagering baccarat blackjack roulette" "id:1210001,phase:2,block,t:none,t:lowercase,msg:'Online Gambling Site Detected',logdata:'Matched Data: %{MATCHED_VAR}',severity:'CRITICAL',tag:'gambling'"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Content-Scanner",
		},
		{
			ID:            "1210002",
			Name:          "Malicious JavaScript Detection",
			Directive:     `SecRule ARGS|REQUEST_HEADERS|XML:/* "@pm String.fromCharCode unescape( %u00 eval(atob( navigator.sendBeacon new WebSocket( document.write( document.createElement('script')" "id:1210002,phase:2,block,t:none,t:lowercase,msg:'Malicious JavaScript Detected',logdata:'Matched Data: %{MATCHED_VAR}',severity:'CRITICAL',tag:'javascript',tag:'malware'"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Content-Scanner",
		},
		{
			ID:            "1210003",
			Name:          "PHP Vulnerability Exploit Attempt",
			Directive:     `SecRule ARGS|REQUEST_HEADERS|XML:/* "@pm <?php file_get_contents( include( require( eval( exec( system( passthru( shell_exec( base64_decode( $_GET $_POST $_REQUEST $_SERVER $_COOKIE $_FILES" "id:1210003,phase:2,block,t:none,t:lowercase,msg:'PHP Vulnerability Exploit Attempt',logdata:'Matched Data: %{MATCHED_VAR}',severity:'CRITICAL',tag:'php',tag:'injection'"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Injection",
		},
		{
			ID:            "1210004",
			Name:          "Arbitrary File Upload Execution Attempt",
			Directive:     `SecRule REQUEST_FILENAME "@rx \.(php[345]?|phtml|asp[x]?|jsp[x]?|sh|py|pl|exe|cgi|htaccess)$" "id:1210004,phase:2,block,t:none,t:lowercase,msg:'Arbitrary File Upload Execution Attempt',logdata:'Matched Data: %{MATCHED_VAR}',severity:'CRITICAL',tag:'fileupload',tag:'rce'"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Injection",
		},
		{
			ID:            "1900001",
			Name:          "Default Anomaly Threshold",
			Directive:     `SecAction "id:1900001,phase:1,nolog,pass,setvar:tx.inbound_anomaly_score_threshold=5,setvar:tx.outbound_anomaly_score_threshold=4"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Adaptive",
		},
		{
			ID:            "1900012",
			Name:          "Adaptive Threshold: Reputation 15+",
			Directive:     `SecRule REQUEST_HEADERS:X-Gateon-Reputation "@ge 15" "id:1900012,phase:2,nolog,pass,setvar:tx.inbound_anomaly_score_threshold=7"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Adaptive",
		},
		{
			ID:            "1900013",
			Name:          "Adaptive Threshold: Reputation 40+",
			Directive:     `SecRule REQUEST_HEADERS:X-Gateon-Reputation "@ge 40" "id:1900013,phase:2,nolog,pass,setvar:tx.inbound_anomaly_score_threshold=10"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Adaptive",
		},
		{
			ID:            "1900011",
			Name:          "Adaptive Threshold: Reputation 80+",
			Directive:     `SecRule REQUEST_HEADERS:X-Gateon-Reputation "@ge 80" "id:1900011,phase:2,nolog,pass,setvar:tx.inbound_anomaly_score_threshold=12"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Adaptive",
		},
		{
			ID:            "1900010",
			Name:          "Adaptive Threshold: Reputation 95+",
			Directive:     `SecRule REQUEST_HEADERS:X-Gateon-Reputation "@ge 95" "id:1900010,phase:2,nolog,pass,setvar:tx.inbound_anomaly_score_threshold=15"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Adaptive",
		},
		{
			ID:            "1900400",
			Name:          "Adaptive Body Limit: High Reputation",
			Directive:     `SecRule REQUEST_HEADERS:X-Gateon-Reputation "@ge 90" "id:1900400,phase:1,nolog,pass,ctl:requestBodyLimit=1073741824"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Adaptive",
		},
		{
			ID:            "1900401",
			Name:          "Adaptive Body Limit: Standard Reputation",
			Directive:     `SecRule REQUEST_HEADERS:X-Gateon-Reputation "@ge 40" "id:1900401,phase:1,nolog,pass,ctl:requestBodyLimit=104857600"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Adaptive",
		},
		{
			ID:            "1900402",
			Name:          "Adaptive Body Limit: Low Reputation",
			Directive:     `SecRule REQUEST_HEADERS:X-Gateon-Reputation "@lt 40" "id:1900402,phase:1,nolog,pass,ctl:requestBodyLimit=1048576"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Adaptive",
		},
		{
			ID:            "1910000",
			Name:          "IP Reputation Flagging",
			Directive:     `SecRule REQUEST_HEADERS:X-Gateon-IP-Reputation-Block "@eq 1" "id:1910000,phase:1,nolog,pass,setvar:tx.ip_reputation_block_flag=1"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Reputation",
		},
		{
			ID:            "1910001",
			Name:          "IP Reputation Blocking (External)",
			Directive:     `SecRule TX:ip_reputation_block_flag "@eq 1" "id:1910001,phase:2,deny,status:403,msg:'IP Reputation block (External)',tag:'reputation',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Reputation",
		},
		{
			ID:            "1910002",
			Name:          "IP Reputation Blocking (Internal)",
			Directive:     `SecRule REQUEST_HEADERS:X-Gateon-Reputation "@lt 20" "id:1910002,phase:1,deny,status:403,msg:'Internal behavior reputation block',tag:'reputation',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Reputation",
		},
		{
			ID:            "1900200",
			Name:          "gRPC Content-Type Compatibility",
			Directive:     `SecRule TX:grpc_mode "@eq 1" "id:1900200,phase:1,nolog,pass,t:none,setvar:'tx.allowed_request_content_type=|application/x-www-form-urlencoded| |multipart/form-data| |multipart/related| |text/xml| |application/xml| |application/soap+xml| |application/json| |application/cloudevents+json| |application/cloudevents-batch+json| |application/grpc| |application/grpc+proto| |application/grpc+json| |application/grpc-web| |application/grpc-web+proto| |application/grpc-web+json| |application/grpc-web-text| |application/grpc-web-text+proto|'"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "gRPC",
		},
		{
			ID:   "1900201",
			Name: "gRPC Body Access Control",
			Directive: `SecRule TX:grpc_mode "@eq 1" "id:1900201,phase:1,nolog,pass,t:none,chain"
  SecRule REQUEST_HEADERS:Content-Type "@rx ^application/grpc" "t:lowercase,ctl:ruleRemoveById=920180,ctl:requestBodyAccess=Off"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "gRPC",
		},
		{
			ID:            "1100010",
			Name:          "Golang Injection Protection",
			Directive:     `SecRule ARGS|REQUEST_HEADERS|REQUEST_URI "@rx (os/exec|net/http/httputil|reflect\.ValueOf|unsafe\.Pointer|go\s+func\()" "id:1100010,phase:2,deny,status:403,msg:'Potential Golang code injection',tag:'rce',tag:'golang',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "RCE",
		},
		{
			ID:            "1100011",
			Name:          "Java Injection Protection",
			Directive:     `SecRule ARGS|REQUEST_HEADERS|REQUEST_URI "@rx (runtime\.exec|java\.lang\.Runtime|java\.lang\.ProcessBuilder|javax\.crypto|javax\.script|ognl\.|java\.net\.URLClassLoader)" "id:1100011,phase:2,deny,status:403,msg:'Potential Java code injection',tag:'rce',tag:'java',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "RCE",
		},
		{
			ID:            "1100013",
			Name:          "Log4Shell Protection",
			Directive:     `SecRule ARGS|REQUEST_HEADERS|REQUEST_URI "@rx \$\{jndi:(ldap|rmi|dns|nis|iiop|corba|nds|http):" "id:1100013,phase:2,deny,status:403,msg:'Potential Log4Shell (CVE-2021-44228) attempt',tag:'rce',tag:'java',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "RCE",
		},
		{
			ID:            "1100014",
			Name:          "Shellshock Protection",
			Directive:     `SecRule REQUEST_HEADERS|REQUEST_HEADERS_NAMES|ARGS|ARGS_NAMES "@rx \(\)\s*\{\s*[:;]\s*\}" "id:1100014,phase:1,deny,status:403,msg:'CVE-2014-6271 - Shellshock attempt',tag:'rce',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "RCE",
		},
		{
			ID:   "1100001",
			Name: "WordPress Admin Protection",
			Directive: `SecRule REQUEST_URI "@contains /wp-admin" "id:1100001,phase:1,deny,status:403,msg:'WordPress admin access attempt',tag:'wp_scan',severity:CRITICAL,chain"
  SecRule REMOTE_ADDR "!@ipMatch %{tx.allowed_admin_ips}"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "WordPress",
		},
		{
			ID:   "1100002",
			Name: "WordPress Login Protection",
			Directive: `SecRule REQUEST_URI "@contains /wp-login.php" "id:1100002,phase:1,deny,status:403,msg:'WordPress login attempt',tag:'wp_scan',severity:CRITICAL,chain"
  SecRule REMOTE_ADDR "!@ipMatch %{tx.allowed_admin_ips}"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "WordPress",
		},
		{
			ID:            "1100003",
			Name:          "WordPress Plugin Execution",
			Directive:     `SecRule REQUEST_URI "@rx /wp-content/plugins/.*\.php" "id:1100003,phase:1,deny,status:403,msg:'WordPress plugin execution attempt',tag:'wp_scan',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "WordPress",
		},
		{
			ID:            "1100012",
			Name:          "WordPress Info Leakage Protection",
			Directive:     `SecRule REQUEST_URI "@rx (wp-json/wp/v2/users|wp-links-opml\.php|wp-config-sample\.php|wp-content/debug\.log|readme\.html|license\.txt|wp-content/uploads/.*\.php)" "id:1100012,phase:1,deny,status:403,msg:'WordPress enumeration/info leak attempt',tag:'wp_scan',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "WordPress",
		},
		{
			ID:            "1100004",
			Name:          "Malicious File Upload Extension",
			Directive:     `SecRule FILES_NAMES "@rx \.(exe|php|phtml|sh|py|pl|rb|jsp|asp|aspx)$" "id:1100004,phase:2,deny,status:403,msg:'Suspicious file upload extension',tag:'malware',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Malware",
		},
		{
			ID:            "1100005",
			Name:          "Malicious PHP Upload Content",
			Directive:     `SecRule FILES "@contains <?php" "id:1100005,phase:2,deny,status:403,msg:'PHP code injection in file upload',tag:'malware',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Malware",
		},
		{
			ID:            "1100006",
			Name:          "PDF JavaScript Protection",
			Directive:     `SecRule FILES "@rx %PDF-1\.[0-7].*obj.*<<.*\/JS.*>>.*endobj" "id:1100006,phase:2,deny,status:403,msg:'PDF with JavaScript detected',tag:'malware',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Malware",
		},
		{
			ID:            "1100007",
			Name:          "Ransomware Extension Protection",
			Directive:     `SecRule FILES_NAMES "@rx \.(locky|crypt|wncry|cryptolocker|zepto|aesir|thor|lockbit|clop|conti|ryuk|cerber|gandcrab|pysa)$" "id:1100007,phase:2,deny,status:403,msg:'Ransomware file extension detected',tag:'ransomware',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Ransomware",
		},
		{
			ID:            "1100008",
			Name:          "Malware: Web Shell Common Filenames",
			Directive:     `SecRule REQUEST_URI "@rx /(c99|r57|sh3ll|weevely|pas|cmd|shell|backdoor|tunnel|proxy)\.(php|asp|aspx|jsp|pl|py|sh|cgi)" "id:1100008,phase:1,deny,status:403,msg:'Web shell filename detected',tag:'malware',tag:'rce',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Malware",
		},
		{
			ID:            "1100009",
			Name:          "Ransomware: Note Filename Search",
			Directive:     `SecRule REQUEST_URI "@rx (READ_ME|DECRYPT_FILES|YOUR_FILES_ARE_ENCRYPTED|RECOVER_FILES|README_FOR_DECRYPT)\.(txt|html|htm|png)" "id:1100009,phase:1,deny,status:403,msg:'Ransomware note filename detected',tag:'ransomware',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Ransomware",
		},
		{
			ID:            "1110000",
			Name:          "Scanner: Common Vulnerability Scanners",
			Directive:     `SecRule REQUEST_HEADERS:User-Agent "@rx (?i)(nikto|sqlmap|acunetix|nessus|openvas|arachni|w3af|zap|dirbuster|gobuster|rustscan|masscan|zgrab|nmap|netsparker|qualys|censys|shodan)" "id:1110000,phase:1,deny,status:403,msg:'Vulnerability scanner detected',tag:'scanner',tag:'recon',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Scanner",
		},
		{
			ID:            "1110001",
			Name:          "Scanner: Specific Tool Headers",
			Directive:     `SecRule REQUEST_HEADERS_NAMES "@rx (?i)(x-scanner|acunetix-product|acunetix-scanning-agreement|nessus-check|qualys-scan-as|netsparker-scan-id)" "id:1110001,phase:1,deny,status:403,msg:'Vulnerability scanner header detected',tag:'scanner',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Scanner",
		},
		{
			ID:   "1110003",
			Name: "Scanner: Automated Attack Tool User-Agent",
			Directive: `SecRule REQUEST_HEADERS:User-Agent "@rx (?i)(python-requests|go-http-client|curl|libwww-perl|php|ruby|urllib|postman|insomnia|js-client)" "id:1110003,phase:1,deny,status:403,msg:'Automated client detected (Non-Browser)',tag:'scanner',tag:'bot',severity:NOTICE,chain"
  SecRule REQUEST_URI "!@rx ^(/api/|/v[0-9]/)"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Scanner",
		},
		{
			ID:            "1110002",
			Name:          "Scanner: Web Shell & Backdoor Search",
			Directive:     `SecRule REQUEST_URI "@rx \b(shell|cmd|sh|bash|zsh|powershell|nc|netcat|web-shell|backdoor)\.(php|asp|aspx|jsp|sh|py|pl)\b" "id:1110002,phase:1,deny,status:403,msg:'Search for common web shells/backdoors',tag:'scanner',tag:'rce',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Scanner",
		},
		{
			ID:            "1120010",
			Name:          "DDoS: Too Many Headers",
			Directive:     `SecRule &REQUEST_HEADERS "@gt 100" "id:1120010,phase:1,deny,status:431,msg:'Header flood detected (DDoS)',tag:'ddos',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "DoS",
		},
		{
			ID:            "1120011",
			Name:          "DDoS: Header Key Length Limit",
			Directive:     `SecRule REQUEST_HEADERS_NAMES "@gt 256" "id:1120011,phase:1,deny,status:400,msg:'Header name too long (DDoS)',tag:'ddos',severity:WARNING"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "DoS",
		},
		{
			ID:            "1130000",
			Name:          "DLP: Credit Card Number Detection",
			Directive:     `SecRule RESPONSE_BODY "@rx \b4[0-9]{12}(?:[0-9]{3})?\b" "id:1130000,phase:4,deny,status:403,msg:'Credit card number detected in response',tag:'dlp',tag:'compliance',severity:CRITICAL"`,
			Enabled:       false,
			ParanoiaLevel: 1,
			Category:      "DLP",
		},
		{
			ID:            "1130001",
			Name:          "DLP: US Social Security Number Detection",
			Directive:     `SecRule RESPONSE_BODY "@rx \b\d{3}-\d{2}-\d{4}\b" "id:1130001,phase:4,deny,status:403,msg:'SSN detected in response',tag:'dlp',severity:CRITICAL"`,
			Enabled:       false,
			ParanoiaLevel: 1,
			Category:      "DLP",
		},
		{
			ID:            "1130004",
			Name:          "DLP: Google/AWS API Key Leakage",
			Directive:     `SecRule RESPONSE_BODY "@rx (AIza[0-9A-Za-z-_]{35}|AKIA[0-9A-Z]{16})" "id:1130004,phase:4,deny,status:403,msg:'Cloud API Key detected in response',tag:'dlp',severity:CRITICAL"`,
			Enabled:       false,
			ParanoiaLevel: 1,
			Category:      "DLP",
		},
		{
			ID:            "1130002",
			Name:          "DLP: Private Key Leakage Detection",
			Directive:     `SecRule RESPONSE_BODY "@rx (-----BEGIN [A-Z ]+ PRIVATE KEY-----|BEGIN RSA PRIVATE KEY|BEGIN DSA PRIVATE KEY|BEGIN EC PRIVATE KEY|BEGIN OPENSSH PRIVATE KEY)" "id:1130002,phase:4,deny,status:403,msg:'Private key detected in response',tag:'dlp',severity:CRITICAL"`,
			Enabled:       false,
			ParanoiaLevel: 1,
			Category:      "DLP",
		},
		{
			ID:            "1130003",
			Name:          "DLP: AWS Access Key Detection",
			Directive:     `SecRule RESPONSE_BODY "@rx \bAKIA[0-9A-Z]{16}\b" "id:1130003,phase:4,deny,status:403,msg:'AWS Access Key detected in response',tag:'dlp',severity:CRITICAL"`,
			Enabled:       false,
			ParanoiaLevel: 1,
			Category:      "DLP",
		},
		{
			ID:            "1130005",
			Name:          "DLP: Slack Webhook Leakage",
			Directive:     `SecRule RESPONSE_BODY "@rx https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+" "id:1130005,phase:4,deny,status:403,msg:'Slack Webhook URL detected in response',tag:'dlp',severity:CRITICAL"`,
			Enabled:       false,
			ParanoiaLevel: 1,
			Category:      "DLP",
		},
		{
			ID:            "1130006",
			Name:          "DLP: GitHub Personal Access Token",
			Directive:     `SecRule RESPONSE_BODY "@rx ghp_[a-zA-Z0-9]{36}" "id:1130006,phase:4,deny,status:403,msg:'GitHub PAT detected in response',tag:'dlp',severity:CRITICAL"`,
			Enabled:       false,
			ParanoiaLevel: 1,
			Category:      "DLP",
		},
		{
			ID:            "1130007",
			Name:          "DLP: Google OAuth Client Secret",
			Directive:     `SecRule RESPONSE_BODY "@rx GOCSPX-[a-zA-Z0-9-_]{28}" "id:1130007,phase:4,deny,status:403,msg:'Google OAuth Client Secret detected in response',tag:'dlp',severity:CRITICAL"`,
			Enabled:       false,
			ParanoiaLevel: 1,
			Category:      "DLP",
		},
		{
			ID:            "1140000",
			Name:          "SQLi: Blind Injection (Sleep/Benchmark)",
			Directive:     `SecRule ARGS|REQUEST_HEADERS|REQUEST_URI "@rx (sleep\(|benchmark\(|pg_sleep\(|dbms_lock\.sleep\(|waitfor\s+delay)" "id:1140000,phase:2,deny,status:403,msg:'Blind SQL Injection (Time-based) attempt',tag:'attack-sqli',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "SQLi",
		},
		{
			ID:            "1140002",
			Name:          "SQLi: Database Schema Enumeration",
			Directive:     `SecRule ARGS "@rx (information_schema\.|sys\.tables|sys\.objects|pg_catalog\.|mysql\.db|@@version)" "id:1140002,phase:2,deny,status:403,msg:'SQL Schema enumeration attempt',tag:'attack-sqli',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "SQLi",
		},
		{
			ID:            "1140001",
			Name:          "SQLi: Common Authentication Bypass",
			Directive:     `SecRule ARGS "@rx \b('?\s+or\s+'?1'?\s*=\s*'?1|'?\s+or\s+true|--|#|\/\*)" "id:1140001,phase:2,deny,status:403,msg:'Common SQLi Authentication Bypass',tag:'attack-sqli',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "SQLi",
		},
		{
			ID:            "1141000",
			Name:          "XSS: Script Tag & Event Handlers",
			Directive:     `SecRule ARGS|REQUEST_HEADERS|REQUEST_URI "@rx (?i)(<script|on(load|error|click|mouseover|focus|submit|keydown|change)\s*=)" "id:1141000,phase:2,deny,status:403,msg:'Cross-site Scripting (XSS) attempt',tag:'attack-xss',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "XSS",
		},
		{
			ID:            "1141002",
			Name:          "XSS: Advanced JavaScript Obfuscation",
			Directive:     `SecRule ARGS "@rx (String\.fromCharCode|eval\(.*atob\(|eval\(.*base64|document\.write\(|unescape\()" "id:1141002,phase:2,deny,status:403,msg:'XSS Obfuscation detected',tag:'attack-xss',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "XSS",
		},
		{
			ID:            "1141001",
			Name:          "XSS: SVG/Iframe/Object Injection",
			Directive:     `SecRule ARGS|REQUEST_HEADERS|REQUEST_URI "@rx (<svg|<iframe|<object|<embed|<base|<applet|<meta)" "id:1141001,phase:2,deny,status:403,msg:'HTML Tag Injection (XSS potential)',tag:'attack-xss',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "XSS",
		},
		{
			ID:            "1150000",
			Name:          "API: Excessive Path Segments",
			Directive:     `SecRule REQUEST_URI "@rx (/[^/]+){15,}" "id:1150000,phase:1,deny,status:403,msg:'Excessive path depth (DDoS/Scanner)',tag:'protocol',severity:WARNING"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Protocol",
		},
		{
			ID:            "1150001",
			Name:          "API: Null Byte Injection",
			Directive:     `SecRule ARGS|REQUEST_HEADERS|REQUEST_URI "@contains \x00" "id:1150001,phase:1,deny,status:403,msg:'Null byte injection attempt',tag:'attack-generic',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Protocol",
		},
		{
			ID:            "1150002",
			Name:          "API: Multiple Content-Type Headers",
			Directive:     `SecRule &REQUEST_HEADERS:Content-Type "@gt 1" "id:1150002,phase:1,deny,status:400,msg:'Multiple Content-Type headers detected',tag:'protocol',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Protocol",
		},
		{
			ID:            "1142000",
			Name:          "Ransomware: Malicious File Pattern Detection",
			Directive:     `SecRule FILES "@rx (encrypt|decrypt|ransom|key|payment|bitcoin|tor|onion|vault|lock)" "id:1142000,phase:2,deny,status:403,msg:'Ransomware keywords in file upload',tag:'ransomware',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Ransomware",
		},
		{
			ID:            "1151000",
			Name:          "RCE: Log4Shell (CVE-2021-44228)",
			Directive:     `SecRule ARGS|REQUEST_HEADERS|REQUEST_URI|REQUEST_BODY "@rx \$\{jndi:(?:ldap|rmi|dns|nis|iiop|corba|nds|http):" "id:1151000,phase:2,deny,status:403,msg:'Log4Shell RCE attempt',tag:'attack-rce',tag:'cve-2021-44228',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "RCE",
		},
		{
			ID:            "1151001",
			Name:          "RCE: Spring4Shell (CVE-2022-22965)",
			Directive:     `SecRule ARGS|REQUEST_BODY "@rx class\.module\.classLoader" "id:1151001,phase:2,deny,status:403,msg:'Spring4Shell RCE attempt',tag:'attack-rce',tag:'cve-2022-22965',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "RCE",
		},
		{
			ID:            "1151002",
			Name:          "RCE: Generic Command Injection",
			Directive:     `SecRule ARGS|REQUEST_BODY "@rx (?:;|\||&|\$|\n|\r)\s*(?:cat|ls|id|whoami|pwd|uname|netcat|nc|curl|wget|bash|sh|zsh|powershell|cmd\.exe)\b" "id:1151002,phase:2,deny,status:403,msg:'Generic RCE attempt',tag:'attack-rce',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "RCE",
		},
		{
			ID:            "1160000",
			Name:          "NoSQL: MongoDB Injection",
			Directive:     `SecRule ARGS|REQUEST_BODY "@rx (\$where|\$gt|\$ne|\$lt|\$in|\$nin|\$exists|\$regex)" "id:1160000,phase:2,deny,status:403,msg:'NoSQL Injection attempt',tag:'attack-nosql',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Injection",
		},
		{
			ID:            "1170000",
			Name:          "Generic: Prototype Pollution",
			Directive:     `SecRule ARGS|REQUEST_BODY "@rx (__proto__|constructor\.prototype)" "id:1170000,phase:2,deny,status:403,msg:'Prototype Pollution attempt',tag:'attack-generic',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Exploit",
		},
		{
			ID:            "1170001",
			Name:          "Generic: Advanced Prototype Pollution",
			Directive:     `SecRule ARGS|REQUEST_BODY "@rx (__proto__|constructor\[prototype\]|\.prototype\.)" "id:1170001,phase:2,deny,status:403,msg:'Advanced Prototype Pollution attempt',tag:'attack-generic',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Exploit",
		},
		{
			ID:            "1151003",
			Name:          "RCE: Apache Struts Path Traversal (CVE-2023-50164)",
			Directive:     `SecRule FILES_NAMES|ARGS_NAMES "@rx (?i)\.\./" "id:1151003,phase:2,deny,status:403,msg:'Potential Apache Struts Path Traversal (CVE-2023-50164)',tag:'attack-rce',tag:'cve-2023-50164',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "RCE",
		},
		{
			ID:            "1151004",
			Name:          "RCE: Spring Cloud Gateway SpEL Injection (CVE-2022-22947)",
			Directive:     `SecRule ARGS|REQUEST_BODY "@rx (?:#|\\$)\\{.*\\}" "id:1151004,phase:2,deny,status:403,msg:'Potential Spring Cloud Gateway SpEL Injection (CVE-2022-22947)',tag:'attack-rce',tag:'cve-2022-22947',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "RCE",
		},
		{
			ID:            "1151005",
			Name:          "RCE: Fortra GoAnywhere MFT (CVE-2023-0669)",
			Directive:     `SecRule REQUEST_URI "@rx /goanywhere/licensing/accept" "id:1151005,phase:1,deny,status:403,msg:'Potential Fortra GoAnywhere MFT RCE attempt (CVE-2023-0669)',tag:'attack-rce',tag:'cve-2023-0669',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "RCE",
		},
		{
			ID:            "1140003",
			Name:          "SQLi: MOVEit Transfer (CVE-2023-34362)",
			Directive:     `SecRule REQUEST_HEADERS:X-siis-session-id ".*" "id:1140003,phase:1,deny,status:403,msg:'Potential MOVEit Transfer SQLi attempt (CVE-2023-34362)',tag:'attack-sqli',tag:'cve-2023-34362',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "SQLi",
		},
		{
			ID:            "1120012",
			Name:          "DDoS: HTTP Request Smuggling (CL)",
			Directive:     `SecRule &REQUEST_HEADERS:Content-Length "@gt 1" "id:1120012,phase:1,deny,status:400,msg:'HTTP Request Smuggling: Multiple Content-Length headers',tag:'ddos',tag:'protocol',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "DoS",
		},
		{
			ID:            "1150003",
			Name:          "Protocol: SSRF Internal Target Detection",
			Directive:     `SecRule ARGS "@rx (?i)(?:127\.0\.0\.1|localhost|169\.254\.169\.254|metadata\.google\.internal|kubernetes\.default\.svc)" "id:1150003,phase:2,deny,status:403,msg:'Potential SSRF attempt (Internal target)',tag:'attack-ssrf',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Protocol",
		},
		{
			ID:            "1110004",
			Name:          "Scanner: Sensitive File Discovery",
			Directive:     `SecRule REQUEST_URI "@rx /(?:\.env|\.git|\.vscode|\.idea|docker-compose\.yml|config\.php\.bak)" "id:1110004,phase:1,deny,status:403,msg:'Sensitive file discovery attempt',tag:'scanner',tag:'recon',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Scanner",
		},
		{
			ID:            "1151006",
			Name:          "RCE: Text4Shell (CVE-2022-42889)",
			Directive:     `SecRule ARGS|REQUEST_BODY "@rx \$\{(?:script|dns|url):" "id:1151006,phase:2,deny,status:403,msg:'Potential Text4Shell RCE attempt (CVE-2022-42889)',tag:'attack-rce',tag:'cve-2022-42889',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "RCE",
		},
		{
			ID:            "1151007",
			Name:          "RCE: Follina (CVE-2022-30190)",
			Directive:     `SecRule ARGS|REQUEST_BODY "@rx ms-msdt:/id\s+IT_BrowseForFile" "id:1151007,phase:2,deny,status:403,msg:'Potential Follina RCE attempt (CVE-2022-30190)',tag:'attack-rce',tag:'cve-2022-30190',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "RCE",
		},
		{
			ID:            "1151008",
			Name:          "RCE: Advanced Shell Injection Patterns",
			Directive:     `SecRule ARGS|REQUEST_BODY "@rx (?:;|\||&|\$|\n|\r|` + "`" + `)\s*(?:env|set|export|eval|exec|system|passthru|shell_exec|base64|python|perl|ruby|php|gcc|make|apt-get|yum|dnf)\b" "id:1151008,phase:2,deny,status:403,msg:'Advanced Shell Injection attempt',tag:'attack-rce',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "RCE",
		},
		{
			ID:            "1180000",
			Name:          "Scanner: AMP Source Origin Spoofing",
			Directive:     `SecRule ARGS:__amp_source_origin "!@rx ^https?://%{REQUEST_HEADERS:Host}" "id:1180000,phase:2,deny,status:403,msg:'AMP Source Origin spoofing attempt',tag:'attack-amp',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Exploit",
		},
		{
			ID:            "1190000",
			Name:          "Exploit: Unwanted Malicious Script Detection",
			Directive:     `SecRule ARGS|REQUEST_BODY "@rx (?:coinhive\.min\.js|authedmine\.min\.js|cryptonight\.wasm|monerominer|miner\.start)" "id:1190000,phase:2,deny,status:403,msg:'Malicious script/miner detected',tag:'attack-malware',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Exploit",
		},
	}

	now := time.Now()
	query := s.dialect.Rebind("INSERT INTO waf_rules (id, name, directive, enabled, paranoia_level, category, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
	checkQuery := s.dialect.Rebind("SELECT COUNT(*) FROM waf_rules WHERE id = ?")

	for _, r := range initialRules {
		var count int
		err := s.db.QueryRowContext(ctx, checkQuery, r.ID).Scan(&count)
		if err != nil {
			return fmt.Errorf("check rule %s: %w", r.ID, err)
		}
		if count == 0 {
			_, err := s.db.ExecContext(ctx, query,
				r.ID, r.Name, r.Directive, r.Enabled, r.ParanoiaLevel, r.Category, now, now)
			if err != nil {
				return fmt.Errorf("seed rule %s: %w", r.ID, err)
			}
		}
	}

	if err := s.Reload(ctx); err != nil {
		return err
	}
	s.notifyInvalidation()
	return nil
}
