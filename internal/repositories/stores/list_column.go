// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package stores

import (
	"fmt"
	"strings"
)

// Several schema columns hold a repeated string field as one comma-separated
// value: a route's entrypoints and middlewares, an entrypoint's protocols, a TLS
// option's cipher suites, ALPN protocols and client authority IDs.
//
// The load path splits on the comma, so any member that contains one comes back
// as two members. For the fixed vocabularies (TCP/UDP, cipher names, h2) that is
// theoretical, but entrypoint names, middleware names and client authority IDs
// are chosen by whoever uses the API, and there the failure is silent and
// security-relevant in both directions: a route can come back carrying a
// middleware nobody configured, or missing the one that was protecting it, with
// nothing logged and nothing to notice.
//
// Rejecting on write is the cheap half of the fix. It needs no migration and
// turns silent corruption into an error at the point someone can still do
// something about it. Storing these as JSON would remove the restriction
// entirely and is the better long-term shape, but that is a schema change with a
// migration for existing rows, so it is deliberately not done here.

// joinListColumn serialises values into a comma-separated column, refusing any
// member that contains the separator. field names the column for the error.
func joinListColumn(field string, values []string) (string, error) {
	for _, v := range values {
		if strings.Contains(v, ",") {
			return "", fmt.Errorf(
				"stores: %s %q contains a comma, which is the separator this column is stored with; "+
					"it would be read back as two entries", field, v)
		}
	}
	return strings.Join(values, ","), nil
}
