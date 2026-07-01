package waf

import (
	"context"
	"database/sql"
	"fmt"
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

// InitStore initializes the WAF rule store and loads rules into memory.
func InitStore(databaseURL string) error {
	var err error
	storeOnce.Do(func() {
		d, _, openErr := db.Open(databaseURL)
		if openErr != nil {
			err = openErr
			return
		}
		globalStore = &Store{db: d}
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
	rows, err := s.db.QueryContext(ctx, "SELECT id, name, directive, enabled, paranoia_level, category, created_at, updated_at FROM waf_rules ORDER BY created_at ASC")
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

// GetAllRules returns all WAF rules from the cache.
func (s *Store) GetAllRules() []Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	// Return a copy to avoid external modification of cache
	res := make([]Rule, len(s.cache))
	copy(res, s.cache)
	return res
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
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO waf_rules (id, name, directive, enabled, paranoia_level, category, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
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
	_, err := s.db.ExecContext(ctx,
		"UPDATE waf_rules SET name = ?, directive = ?, enabled = ?, paranoia_level = ?, category = ?, updated_at = ? WHERE id = ?",
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
	_, err := s.db.ExecContext(ctx, "DELETE FROM waf_rules WHERE id = ?", id)
	if err != nil {
		return err
	}
	if err := s.Reload(ctx); err != nil {
		return err
	}
	s.notifyInvalidation()
	return nil
}

// Seed populates the database with default rules if it's currently empty.
func (s *Store) Seed(ctx context.Context) error {
	count := 0
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM waf_rules").Scan(&count)
	if err != nil {
		return err
	}
	if count > 0 {
		return nil
	}

	initialRules := []Rule{
		{
			ID:            "900300",
			Name:          "Redact Sensitive Headers",
			Directive:     `SecAction "id:900300,phase:1,nolog,pass,setvar:tx.redact_headers=Authorization,setvar:tx.redact_headers=X-Api-Key,setvar:tx.redact_headers=Cookie,setvar:tx.redact_headers=Set-Cookie"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Compliance",
		},
		{
			ID:            "900015",
			Name:          "Set Server Name from Host",
			Directive:     `SecRule REQUEST_HEADERS:Host "^(.+)$" "id:900015,phase:1,nolog,pass,t:none,setvar:tx.server_name=%{MATCHED_VAR}"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Initialization",
		},
		{
			ID:            "900001",
			Name:          "Adaptive Threshold: Reputation 0+",
			Directive:     `SecRule REQUEST_HEADERS:X-Gateon-Reputation "@ge 0"  "id:900001,phase:2,nolog,pass,setvar:tx.inbound_anomaly_score_threshold=2"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Adaptive",
		},
		{
			ID:            "900012",
			Name:          "Adaptive Threshold: Reputation 15+",
			Directive:     `SecRule REQUEST_HEADERS:X-Gateon-Reputation "@ge 15" "id:900012,phase:2,nolog,pass,setvar:tx.inbound_anomaly_score_threshold=3"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Adaptive",
		},
		{
			ID:            "900013",
			Name:          "Adaptive Threshold: Reputation 40+",
			Directive:     `SecRule REQUEST_HEADERS:X-Gateon-Reputation "@ge 40" "id:900013,phase:2,nolog,pass,setvar:tx.inbound_anomaly_score_threshold=4"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Adaptive",
		},
		{
			ID:            "900011",
			Name:          "Adaptive Threshold: Reputation 80+",
			Directive:     `SecRule REQUEST_HEADERS:X-Gateon-Reputation "@ge 80" "id:900011,phase:2,nolog,pass,setvar:tx.inbound_anomaly_score_threshold=5"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Adaptive",
		},
		{
			ID:            "900010",
			Name:          "Adaptive Threshold: Reputation 95+",
			Directive:     `SecRule REQUEST_HEADERS:X-Gateon-Reputation "@ge 95" "id:900010,phase:2,nolog,pass,setvar:tx.inbound_anomaly_score_threshold=5"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Adaptive",
		},
		{
			ID:            "900400",
			Name:          "Adaptive Body Limit: High Reputation",
			Directive:     `SecRule REQUEST_HEADERS:X-Gateon-Reputation "@ge 90" "id:900400,phase:1,nolog,pass,ctl:requestBodyLimit=1073741824"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Adaptive",
		},
		{
			ID:            "900401",
			Name:          "Adaptive Body Limit: Standard Reputation",
			Directive:     `SecRule REQUEST_HEADERS:X-Gateon-Reputation "@ge 40" "id:900401,phase:1,nolog,pass,ctl:requestBodyLimit=104857600"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Adaptive",
		},
		{
			ID:            "900402",
			Name:          "Adaptive Body Limit: Low Reputation",
			Directive:     `SecRule REQUEST_HEADERS:X-Gateon-Reputation "@lt 40" "id:900402,phase:1,nolog,pass,ctl:requestBodyLimit=1048576"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Adaptive",
		},
		{
			ID:            "910000",
			Name:          "IP Reputation Flagging",
			Directive:     `SecRule REQUEST_HEADERS:X-Gateon-IP-Reputation-Block "@eq 1" "id:910000,phase:1,nolog,pass,setvar:tx.ip_reputation_block_flag=1"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Reputation",
		},
		{
			ID:            "910001",
			Name:          "IP Reputation Blocking",
			Directive:     `SecRule TX:ip_reputation_block_flag "@eq 1" "id:910001,phase:2,deny,status:403,msg:'IP Reputation block',tag:'reputation',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Reputation",
		},
		{
			ID:            "900002",
			Name:          "DoS Protection Initialization",
			Directive:     `SecAction "id:900002,phase:1,nolog,pass,setvar:tx.dos_burst_time_slice=60,setvar:tx.dos_counter_threshold=100,setvar:tx.dos_block_timeout=600"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "DoS",
		},
		{
			ID:            "900200",
			Name:          "gRPC Content-Type Compatibility",
			Directive:     `SecAction "id:900200,phase:1,nolog,pass,t:none,setvar:'tx.allowed_request_content_type=|application/x-www-form-urlencoded| |multipart/form-data| |multipart/related| |text/xml| |application/xml| |application/soap+xml| |application/json| |application/cloudevents+json| |application/grpc| |application/grpc+proto| |application/grpc+json|'"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "gRPC",
		},
		{
			ID:            "900201",
			Name:          "gRPC Body Access Control",
			Directive:     `SecRule REQUEST_HEADERS:Content-Type "@rx ^application/grpc" "id:900201,phase:1,nolog,pass,t:lowercase,ctl:ruleRemoveById=920180,ctl:requestBodyAccess=Off"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "gRPC",
		},
		{
			ID:            "100010",
			Name:          "Golang Injection Protection",
			Directive:     `SecRule ARGS|REQUEST_HEADERS|REQUEST_URI "@rx (os/exec|net/http/httputil|reflect\.ValueOf|unsafe\.Pointer|go\s+func\()" "id:100010,phase:2,deny,status:403,msg:'Potential Golang code injection',tag:'rce',tag:'golang',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Injection",
		},
		{
			ID:            "100011",
			Name:          "Java Injection Protection",
			Directive:     `SecRule ARGS|REQUEST_HEADERS|REQUEST_URI "@rx (runtime\.exec|java\.lang\.Runtime|java\.lang\.ProcessBuilder|javax\.crypto|javax\.script|ognl\.|java\.net\.URLClassLoader)" "id:100011,phase:2,deny,status:403,msg:'Potential Java code injection',tag:'rce',tag:'java',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Injection",
		},
		{
			ID:            "100013",
			Name:          "Log4Shell Protection",
			Directive:     `SecRule ARGS|REQUEST_HEADERS|REQUEST_URI "@rx \$\{jndi:(ldap|rmi|dns|nis|iiop|corba|nds|http):" "id:100013,phase:2,deny,status:403,msg:'Potential Log4Shell (CVE-2021-44228) attempt',tag:'rce',tag:'java',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Injection",
		},
		{
			ID:   "100001",
			Name: "WordPress Admin Protection",
			Directive: `SecRule REQUEST_URI "@contains /wp-admin" "id:100001,phase:1,deny,status:403,msg:'WordPress admin access attempt',tag:'wp_scan',severity:CRITICAL,chain"
  SecRule REMOTE_ADDR "!@ipMatch %{tx.allowed_admin_ips}"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "WordPress",
		},
		{
			ID:   "100002",
			Name: "WordPress Login Protection",
			Directive: `SecRule REQUEST_URI "@contains /wp-login.php" "id:100002,phase:1,deny,status:403,msg:'WordPress login attempt',tag:'wp_scan',severity:CRITICAL,chain"
  SecRule REMOTE_ADDR "!@ipMatch %{tx.allowed_admin_ips}"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "WordPress",
		},
		{
			ID:            "100003",
			Name:          "WordPress Plugin Execution",
			Directive:     `SecRule REQUEST_URI "@rx /wp-content/plugins/.*\.php" "id:100003,phase:1,deny,status:403,msg:'WordPress plugin execution attempt',tag:'wp_scan',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "WordPress",
		},
		{
			ID:            "100012",
			Name:          "WordPress Info Leakage Protection",
			Directive:     `SecRule REQUEST_URI "@rx (wp-json/wp/v2/users|wp-links-opml\.php|wp-config-sample\.php|wp-content/debug\.log|readme\.html|license\.txt|wp-content/uploads/.*\.php)" "id:100012,phase:1,deny,status:403,msg:'WordPress enumeration/info leak attempt',tag:'wp_scan',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "WordPress",
		},
		{
			ID:            "100004",
			Name:          "Malicious File Upload Extension",
			Directive:     `SecRule FILES_NAMES "@rx \.(exe|php|phtml|sh|py|pl|rb|jsp|asp|aspx)$" "id:100004,phase:2,deny,status:403,msg:'Suspicious file upload extension',tag:'malware',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Malware",
		},
		{
			ID:            "100005",
			Name:          "Malicious PHP Upload Content",
			Directive:     `SecRule FILES "@contains <?php" "id:100005,phase:2,deny,status:403,msg:'PHP code injection in file upload',tag:'malware',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Malware",
		},
		{
			ID:            "100006",
			Name:          "PDF JavaScript Protection",
			Directive:     `SecRule FILES "@rx %PDF-1\.[0-7].*obj.*<<.*\/JS.*>>.*endobj" "id:100006,phase:2,deny,status:403,msg:'PDF with JavaScript detected',tag:'malware',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Malware",
		},
		{
			ID:            "100007",
			Name:          "Ransomware Extension Protection",
			Directive:     `SecRule FILES_NAMES "@rx \.(locky|crypt|wncry|cryptolocker|zepto|aesir|thor|lockbit|clop|conti|ryuk|cerber|gandcrab|pysa)$" "id:100007,phase:2,deny,status:403,msg:'Ransomware file extension detected',tag:'ransomware',severity:CRITICAL"`,
			Enabled:       true,
			ParanoiaLevel: 1,
			Category:      "Malware",
		},
	}

	now := time.Now()
	for _, r := range initialRules {
		_, err := s.db.ExecContext(ctx,
			"INSERT INTO waf_rules (id, name, directive, enabled, paranoia_level, category, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
			r.ID, r.Name, r.Directive, r.Enabled, r.ParanoiaLevel, r.Category, now, now)
		if err != nil {
			return fmt.Errorf("seed rule %s: %w", r.ID, err)
		}
	}

	return s.Reload(ctx)
}
