// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package kind

import (
	"cmp"
	"net/http"
)

// RefusalMessage is the whole of what a client is told when a security
// decision refuses it, whichever decision that was (ADR 0106).
//
// Each refusal used to name its check: "High Entropy Detected", "Client
// Spoofing Detected", "Suspicious Client", "Malformed Security Token",
// "request could not be inspected", "Reputation Block", "Browser Integrity
// Check Failed", "Session binding mismatch", the zero-trust error's own text.
// To a person that is a curiosity. To an attacker that adapts its payload from
// each answer -- a fuzzer, or a language model running a loop -- it is the
// gradient: "High Entropy Detected" is an instruction to lower the entropy and
// try again, and "could not be inspected" says the payload found the edge of
// the inspection budget. The reason is the operator's, and stays where the
// operator reads it: the Security Hub entry, the log line and the trace, which
// the X-Request-Id the response already carries finds.
const RefusalMessage = "Forbidden by Security Policy"

// RefusalBody is the refusal's body exactly as http.Error writes it, for the
// writers that frame a refusal themselves (a refused response, whose framing
// replaces the origin's).
const RefusalBody = RefusalMessage + "\n"

// Refuse answers r with the one refusal every security decision gives.
// status is the decision's own (0 is 403); a status carries HTTP semantics a
// well-behaved client needs (405, 413, 431) and says nothing the request
// itself does not, so it is kept, and only the body is made uniform.
func Refuse(w http.ResponseWriter, status int) {
	http.Error(w, RefusalMessage, cmp.Or(status, http.StatusForbidden))
}
