package yara

import (
	"encoding/json"
	"fmt"
	"os"
)

// LoadFile reads a JSON rule file and returns an Engine combining the built-in
// rules with the loaded ones. The file format is a JSON array of Rule objects.
// Custom rules are appended after the built-ins so operators can extend, not
// replace, default coverage.
func LoadFile(path string) (*Engine, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- path comes from operator config, not user input
	if err != nil {
		return nil, fmt.Errorf("yara: read rules file: %w", err)
	}
	var custom []Rule
	if err := json.Unmarshal(raw, &custom); err != nil {
		return nil, fmt.Errorf("yara: parse rules file %q: %w", path, err)
	}
	rules := append(defaultRules(), custom...)
	return New(rules)
}
