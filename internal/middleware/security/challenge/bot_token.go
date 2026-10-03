// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package challenge

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"io"
	"strconv"
	"strings"
	"time"
)

// The JS challenge hands out two tokens, signed in two different contexts, and
// the only way from the first to the second is to do the work (ADR 0045).
//
//   - The challenge ID is printed into the challenge page. It is bound to the
//     client's address and User-Agent and answerable for challengeLifetime.
//     Holding it proves nothing: it is in the page source.
//   - The pass is the cookie. It is issued only for an answer: a nonce such that
//     SHA-256(id ":" nonce) begins with challengeBits zero bits. Finding one
//     takes about 2^challengeBits hashes, which is what running the page's
//     script does; reading the page does not.
//
// Until ADR 0045 the "work" was a two-second wait: the page fetched a signed
// seed and posted it back, and curl could do the same with no JavaScript. The
// pass context moved to v3 with this change so that a pass minted that way
// stops verifying.
//
// No store backs either token. A replayed answer yields another pass for the
// same address and User-Agent, which the client already holds, so a
// single-use list would bound nothing an attacker wants; the lifetime bounds the
// replay instead, and the gateway keeps no per-client state.
const (
	challengeContext = "gateon-bot-challenge-v3"
	// #nosec G101 -- a domain-separation label mixed into the MAC so a
	// challenge ID can never verify as a pass. It is public by design; the
	// secret is cfg.SecretKey.
	passContext = "gateon-bot-pass-v3"
	// challengeBits is the work an answer proves: about 2^18 SHA-256
	// evaluations on average, well under a second of script on a phone and
	// a fixed CPU price per address and User-Agent for a client that solves it
	// natively. It is a constant, not a tunable: it is the cost of one pass,
	// and the pass lifetime is what an operator adjusts.
	challengeBits = 18
	// challengeLifetime bounds how long a printed challenge stays answerable.
	challengeLifetime = 5 * time.Minute
	// maxNonceLen bounds the answer's nonce: decimal digits, enough for 10^16
	// attempts, far past what challengeBits ever needs.
	maxNonceLen = 16
	// clockSkew is how far ahead of this gateway's clock a token's issue time
	// may be; in a cluster another instance may have issued it.
	clockSkew = 5 * time.Second
	// defaultPassLifetime is used when the route configures no timeout.
	defaultPassLifetime = time.Hour
)

// answerVerdict is what checking a challenge answer concluded.
type answerVerdict int

const (
	// answerAccepted: the ID is this client's, current, and the work is done.
	answerAccepted answerVerdict = iota
	// answerExpired: a genuine ID for this client that outlived
	// challengeLifetime -- a tab left open, not an attack.
	answerExpired
	// answerRefused: a forged or foreign ID, or a nonce that does not do the work.
	answerRefused
)

func challengeFor(secret, ua, ip string, at time.Time) string {
	return signBotToken(challengeContext, secret, ua, ip, at)
}

func passFor(secret, ua, ip string, at time.Time) string {
	return signBotToken(passContext, secret, ua, ip, at)
}

func passLifetime(cfg BotManagementConfig) time.Duration {
	if cfg.ChallengeTimeoutSeconds > 0 {
		return time.Duration(cfg.ChallengeTimeoutSeconds) * time.Second
	}
	return defaultPassLifetime
}

// signBotToken returns "<issued unix ms>.<hex MAC>". Every field is written
// length-prefixed, so no field can borrow bytes from its neighbour.
func signBotToken(context, secret, ua, ip string, at time.Time) string {
	issued := strconv.FormatInt(at.UnixMilli(), 10)
	return issued + "." + hex.EncodeToString(botMAC(context, secret, issued, ua, ip))
}

func botMAC(context, secret string, fields ...string) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	for _, f := range append([]string{context}, fields...) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(f)))
		_, _ = mac.Write(n[:])
		_, _ = io.WriteString(mac, f)
	}
	return mac.Sum(nil)
}

// tokenAge checks token's MAC in context and returns how long ago it was
// issued. A token issued in the future, beyond clock skew, is invalid.
func tokenAge(context, token, secret, ua, ip string, now time.Time) (time.Duration, bool) {
	issued, sig, ok := strings.Cut(token, ".")
	if !ok || len(sig) != hex.EncodedLen(sha256.Size) {
		return 0, false
	}
	var got [sha256.Size]byte
	if _, err := hex.Decode(got[:], []byte(sig)); err != nil {
		return 0, false
	}
	if subtle.ConstantTimeCompare(got[:], botMAC(context, secret, issued, ua, ip)) != 1 {
		return 0, false
	}
	ms, err := strconv.ParseInt(issued, 10, 64)
	if err != nil {
		return 0, false
	}
	age := now.Sub(time.UnixMilli(ms))
	return age, age >= -clockSkew
}

func verifyPass(token, secret, ua, ip string, now time.Time, lifetime time.Duration) bool {
	age, ok := tokenAge(passContext, token, secret, ua, ip, now)
	return ok && age <= lifetime
}

// answer is what a client presents for a challenge: the ID it was given and
// the nonce it found, plus the identity the ID must have been issued to.
type answer struct {
	id, nonce string
	ua, ip    string
}

// check verifies an answer under secret. The MAC is checked before the age so
// that "expired" is only ever said of an ID this gateway issued to this
// client, and the work is checked last because it is the only step that
// hashes attacker-chosen input of the attacker's choosing length.
func (a answer) check(secret string, now time.Time) answerVerdict {
	age, ok := tokenAge(challengeContext, a.id, secret, a.ua, a.ip, now)
	if !ok {
		return answerRefused
	}
	if age > challengeLifetime {
		return answerExpired
	}
	if !validNonce(a.nonce) || !workDone(a.id, a.nonce, challengeBits) {
		return answerRefused
	}
	return answerAccepted
}

// validNonce accepts 1 to maxNonceLen decimal digits.
func validNonce(nonce string) bool {
	if nonce == "" || len(nonce) > maxNonceLen {
		return false
	}
	for i := 0; i < len(nonce); i++ {
		if nonce[i] < '0' || nonce[i] > '9' {
			return false
		}
	}
	return true
}

// workDone reports whether SHA-256(id ":" nonce) begins with bits zero bits,
// for bits in 1..32. It is the check the page's script searches for.
func workDone(id, nonce string, bits uint) bool {
	sum := sha256.Sum256([]byte(id + ":" + nonce))
	return binary.BigEndian.Uint32(sum[:4])>>(32-bits) == 0
}
