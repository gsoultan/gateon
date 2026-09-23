// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package stores

import "github.com/gsoultan/gateon/internal/logger"

// The five DB-backed registries each swallowed three kinds of failure without
// a word: the query error, a row that would not Scan, and a column that would
// not decode.
//
// The third is the dangerous one, because it does not remove the record -- it
// removes a *field* from it, and for the TLS columns an absent field is not a
// smaller configuration, it is a different one. entrypoint_http.go gates
// termination on `ep.Tls != nil`, so an entrypoint whose tls column failed to
// decode came up serving plaintext on a port the operator had configured for
// HTTPS, with nothing logged and a non-empty tls column still sitting in the
// database saying otherwise.
//
// So a record with an undecodable column is dropped rather than registered
// without it. A listener that never starts refuses connections, which an
// operator notices in minutes; one that starts without TLS is noticed by
// whoever is reading the traffic. Dropping is safe because the layer above
// already fails closed on a missing record -- a route naming a middleware that
// is not in the store refuses requests rather than running without it.

// logLoadQueryFailed reports a registry that cannot read its table at all.
// Returning quietly is how this stayed invisible: a gateway with no routes
// looks exactly like a gateway that was never given any.
func logLoadQueryFailed(what string, err error) {
	logger.L.LogError("cannot load "+what+"; the gateway will start with none",
		"error", err)
}

// logRecordDropped reports a record that will not be registered. id is "" when
// the failure was the Scan itself, because then there is no id to report.
func logRecordDropped(what, id, column string, err error) {
	logger.L.LogError("dropping a "+what+" record that cannot be read; it will not "+
		"be served until the stored value is fixed",
		"id", id, "column", column, "error", err)
}

// logLoadTruncated reports an iteration that ended before the table did --
// a dropped connection mid-read, most often. This is worse than a failed
// query: the registry comes up *partially* populated, which looks like a
// working gateway that is missing things nobody asked it to miss.
func logLoadTruncated(what string, err error) {
	logger.L.LogError("stopped reading "+what+" before the end of the table; "+
		"the configuration loaded is incomplete",
		"error", err)
}
