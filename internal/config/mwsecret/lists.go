// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package mwsecret

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"

	"github.com/gsoultan/gateon/internal/config/storedsecret"
)

// An API key is its own identity: the apikey middleware stores each key as a
// config key, "key_<APIKEY>", with the tenant label as the value. Shown to a
// caller it becomes "key_<Sentinel>_<fingerprint>", and sent back that way it
// keeps the stored key with that fingerprint -- whatever the tenant label now
// says and wherever it sits in the map. Position is not an identity (a JSON
// object has no order to keep) and neither is the tenant label, which the
// operator is free to change and several keys may share.
//
// The fingerprint is keyed. An unkeyed hash of an API key would let anyone who
// can read middlewares test guesses offline, and a key typed by hand
// ("partner-2024") falls to that at once. The key is derived from
// GATEON_ENCRYPTION_KEY when it is set, so fingerprints survive a restart and
// agree across gateways that share it; without it the key is random per
// process, and a form opened or an export taken before a restart can no longer
// keep an API key -- it is refused, naming the element, and has to be entered
// again.
var fingerprintKey = newFingerprintKey()

// minSeedLen is the shortest GATEON_ENCRYPTION_KEY used as a seed, the same
// floor the config encryption applies to it.
const minSeedLen = 16

func newFingerprintKey() []byte {
	if seed := os.Getenv("GATEON_ENCRYPTION_KEY"); len(seed) >= minSeedLen {
		mac := hmac.New(sha256.New, []byte(seed))
		mac.Write([]byte("gateon/mwsecret/api-key-fingerprint/v1"))
		return mac.Sum(nil)
	}
	key := make([]byte, sha256.Size)
	_, _ = rand.Read(key) // crypto/rand.Read does not fail; it crashes the process instead
	return key
}

// fingerprint identifies one API key of one middleware without disclosing it.
func fingerprint(middlewareID, apiKey string) string {
	mac := hmac.New(sha256.New, fingerprintKey)
	mac.Write([]byte(middlewareID + "\x00" + apiKey))
	return hex.EncodeToString(mac.Sum(nil)[:8])
}

// apiKeyMarker is the config key an API key is shown as.
func apiKeyMarker(middlewareID, apiKey string) string {
	return apiKeyPrefix + Sentinel + "_" + fingerprint(middlewareID, apiKey)
}

// markerFingerprint is the fingerprint in a config key shown by apiKeyMarker,
// and whether key is one.
func markerFingerprint(key string) (string, bool) {
	fp, ok := strings.CutPrefix(key, apiKeyPrefix+Sentinel+"_")
	if !ok || len(fp) != 16 || strings.Trim(fp, "0123456789abcdef") != "" {
		return "", false
	}
	return fp, true
}

// storedAPIKey is the stored API key with fingerprint fp, if one has it.
func storedAPIKey(middlewareID string, stored map[string]string, fp string) (string, bool) {
	for k := range stored {
		apiKey, ok := strings.CutPrefix(k, apiKeyPrefix)
		if ok && apiKey != "" && !strings.Contains(apiKey, Sentinel) &&
			hmac.Equal([]byte(fingerprint(middlewareID, apiKey)), []byte(fp)) {
			return apiKey, true
		}
	}
	return "", false
}

// user is one "name:password" of a basic-auth user list.
type user struct{ name, password string }

// parseUsers reads a user list the way the basic-auth middleware does: comma
// separated, each part trimmed, empty parts skipped, the name ending at the
// first colon. A list the middleware would refuse is not a list here either.
func parseUsers(v string) ([]user, bool) {
	var out []user
	for part := range strings.SplitSeq(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, password, ok := strings.Cut(part, ":")
		if !ok {
			return nil, false
		}
		out = append(out, user{name: name, password: password})
	}
	return out, true
}

// joinUsers writes a user list back.
func joinUsers(users []user) string {
	parts := make([]string, len(users))
	for i, u := range users {
		parts[i] = u.name + ":" + u.password
	}
	return strings.Join(parts, ",")
}

// usersByName is a stored user list by name, the last entry winning as it does
// in the middleware. Nil when the stored value is not a literal list.
func usersByName(v string) map[string]string {
	if isOpaque(v) {
		return nil
	}
	users, ok := parseUsers(v)
	if !ok {
		return nil
	}
	byName := make(map[string]string, len(users))
	for _, u := range users {
		byName[u.name] = u.password
	}
	return byName
}

// isOpaque reports whether a value is resolved as a whole before the
// middleware reads it -- a reference or an encrypted value -- so its parts are
// not what they look like.
func isOpaque(v string) bool {
	return storedsecret.IsReference(v) || strings.HasPrefix(v, "enc:")
}
