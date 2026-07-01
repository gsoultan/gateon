package waf

import "time"

// Rule represents a WAF security rule stored in the database.
type Rule struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Directive     string    `json:"directive"`
	Enabled       bool      `json:"enabled"`
	ParanoiaLevel int       `json:"paranoia_level"`
	Category      string    `json:"category"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}
