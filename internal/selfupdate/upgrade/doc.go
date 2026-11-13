// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package upgrade is the gateway's half of installing a release (ADR 0087).
//
// The gateway cannot replace its own binary, and must not be able to: it runs
// as an unprivileged account under ProtectSystem=strict (ADR 0019), and it is
// the process that parses hostile traffic. So an install is two programs.
// This one downloads a release into the gateway's own data directory,
// verifies it, and leaves a request beside it. The helper, a root-owned
// oneshot unit, picks the request up, verifies the same bytes again with the
// keys compiled into the binary root already trusts, and only then swaps the
// binary (package helper).
//
// The two share exactly the files named here. Nothing the gateway writes is
// believed by the helper except what a release signature covers; what the
// helper writes lives in a directory the gateway can read and cannot change.
package upgrade
