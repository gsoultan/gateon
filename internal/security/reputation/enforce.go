// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package reputation

import "sync/atomic"

// published is the store the request path consults. The feed switch is a
// gateway-wide setting -- "sync with threat feeds to block known malicious
// actors" -- and it used to be enforced only by a WAF rule behind a second,
// separate switch, so a feed that loaded thousands of addresses refused none
// of them on a route without that WAF (truth T3, ADR 0044). Publishing the one
// store lets the IP decision every entrypoint and route already makes
// (identity.AddressBlocked) ask it too, with no new dependency to thread
// through every chain builder.
var published atomic.Pointer[IPReputationStore]

// Publish makes s the store Listed consults. main publishes the store it
// starts; before that, and in a process that has none, nothing is listed.
// Publishing nil withdraws it.
func Publish(s *IPReputationStore) { published.Store(s) }

// Listed reports whether the published store's feeds list ip at or above the
// block threshold. It takes no lock, and with no feed entries it costs one
// atomic load past the nil check.
func Listed(ip string) bool {
	s := published.Load()
	return s != nil && s.Listed(ip)
}
