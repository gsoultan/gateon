// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package mwsecret

import (
	"os"
	"strings"
)

// SecretRefsEnv names the environment variable that lists, one per comma, the
// secret references a middleware field may resolve.
//
// A middleware is written by an operator, not only an administrator, and its
// fields resolve $env:, $vault: and $aws-sm: references (see the factory). With
// nothing to stop it, an operator could name any secret the process can reach
// -- the encryption key, a database password, a session key held as a
// reference -- and read it back through a response header, or send it to a URL
// the same middleware names. So which references a middleware may resolve is the
// host's to decide, not the API's: it is set in the environment, which the API
// cannot write, and lists the exact references (whole strings, not prefixes) the
// operator is trusted to use. Unset, no middleware field may resolve a reference.
const SecretRefsEnv = "GATEON_MIDDLEWARE_SECRET_REFS"

// RefAllowed reports whether ref is a secret reference the host has allow-listed
// for a middleware field, by exact match. Read from the environment on each
// call: a middleware chain is built when the configuration changes, not per
// request, and the list is short.
func RefAllowed(ref string) bool {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return false
	}
	for _, allowed := range strings.Split(os.Getenv(SecretRefsEnv), ",") {
		if strings.TrimSpace(allowed) == ref {
			return true
		}
	}
	return false
}
