// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"net/http"

	"github.com/gsoultan/gateon/internal/middleware"
)

// authWaived marks r the way the management base handler marks a request it
// decided needs no credential -- authentication off for the deployment, or a
// path that must work before a session exists. Tests that call a handler
// directly, without the base handler in front, use it to say which of those
// they model; a request with no claims and no mark is refused (ADR 0027).
func authWaived(r *http.Request) *http.Request {
	return r.WithContext(middleware.WithAuthNotRequired(r.Context()))
}
