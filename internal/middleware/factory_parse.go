package middleware

import (
	"strconv"
	"strings"
)

func parseBool(s string, defaultVal bool) bool {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return defaultVal
	}
	return s == "true" || s == "1" || s == "yes"
}

func parsePositiveInt(s string, defaultVal int) int {
	if s == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return defaultVal
	}
	return n
}

func strconvParseInt(s string, defaultVal int) (int, error) {
	if s == "" {
		return defaultVal, nil
	}
	n, err := strconv.ParseInt(s, 10, 0)
	if err != nil {
		return defaultVal, err
	}
	return int(n), nil
}

func parseBoolStrict(s string, defaultVal bool) bool {
	if s == "" {
		return defaultVal
	}
	parsed, err := strconv.ParseBool(strings.TrimSpace(s))
	if err != nil {
		return defaultVal
	}
	return parsed
}
