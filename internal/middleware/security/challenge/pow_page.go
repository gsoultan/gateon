// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package challenge

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
)

const (
	// PowPassCookieName holds a proof-of-work pass.
	PowPassCookieName = "gateon_pow_pass"
	// #nosec G101 -- a domain-separation label mixed into the MAC, public by
	// design; the secret is the route's proof-of-work key.
	powPassContext = "gateon-pow-pass-v1"
	// powPassLifetime is how long one solved proof of work admits its client.
	//
	// The pass exists because the browser page could never get through without
	// it: a solution was honoured only on the request that carried it, so the
	// page's reload was challenged again, solved again, and reloaded again, for
	// as long as the tab stayed open. That loop was invisible while the
	// threshold was inverted and nobody was challenged; ADR 0045 fixed both.
	// A constant, not a tunable: ten minutes of access per proof is the
	// price, and the reputation that triggered it still decides whether the
	// next one is asked for.
	powPassLifetime = 10 * time.Minute
)

// hasPass reports whether the request carries a current pass this route
// issued to this client.
func (c powChallenge) hasPass(r *http.Request) bool {
	if len(c.key) == 0 {
		return false
	}
	cookie, err := r.Cookie(PowPassCookieName)
	if err != nil {
		return false
	}
	age, ok := tokenAge(powPassContext, cookie.Value, string(c.key), r.UserAgent(), telemetry.ClientIPOf(r), time.Now())
	return ok && age <= powPassLifetime
}

// setPass hands a client that has just proved work a pass for powPassLifetime,
// bound to its address and User-Agent as the challenge was.
func (c powChallenge) setPass(w http.ResponseWriter, r *http.Request) {
	// #nosec G124 -- Secure is set from the resolved scheme just below.
	http.SetCookie(w, &http.Cookie{
		Name:     PowPassCookieName,
		Value:    signBotToken(powPassContext, string(c.key), r.UserAgent(), telemetry.ClientIPOf(r), time.Now()),
		Path:     "/",
		HttpOnly: true,
		Secure:   request.IsSecure(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(powPassLifetime / time.Second),
	})
}

// issuedChallenge is one challenge handed to one client: the id it must
// answer, the salt and difficulty it is told.
type issuedChallenge struct {
	id         string
	salt       string
	difficulty int
}

// wantsJSON reports whether the caller is an XHR or fetch rather than a
// navigation, and so wants a machine-readable challenge.
func wantsJSON(r *http.Request) bool {
	return r.Header.Get("X-Requested-With") == "XMLHttpRequest" ||
		strings.Contains(r.Header.Get(kind.HeaderAccept), "application/json")
}

// writeJSON answers an XHR caller with the challenge as JSON.
func (ch issuedChallenge) writeJSON(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)
	// #nosec G705 -- constrained alphabets only: id is [0-9a-f-] by
	// construction in powChallenge.id, salt is base 36, difficulty an int.
	fmt.Fprintf(w, `{"error":"proof_of_work_required","challenge_id":"%s","salt":"%s","difficulty":%d}`,
		ch.id, ch.salt, ch.difficulty)
}

// serve issues a challenge: headers plus a JSON body for XHR callers, or the
// challenge page, whose script solves it, for browsers.
func (c powChallenge) serve(w http.ResponseWriter, r *http.Request) {
	ch := issuedChallenge{
		id:         c.id(time.Now().Unix(), r),
		salt:       strconv.FormatInt(time.Now().UnixNano(), 36),
		difficulty: c.difficulty,
	}

	w.Header().Set(PowHeaderID, ch.id)
	w.Header().Set(PowHeaderChallenge, ch.salt)
	w.Header().Set("X-Gateon-Pow-Difficulty", strconv.Itoa(ch.difficulty))

	if wantsJSON(r) {
		ch.writeJSON(w)
		return
	}
	writeChallengePage(w, http.StatusTooManyRequests, pageData{
		ID:     ch.id,
		Method: challengeMethod(r.Method),
		Bits:   4 * ch.difficulty,
		Mode:   modePow,
	})
}
