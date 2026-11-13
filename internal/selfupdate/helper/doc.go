// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package helper is the privileged half of installing a release (ADR 0087):
// the code gateon-upgrade.service runs as root, and that `gateon upgrade`
// runs for an operator who is already root.
//
// Its caller is the gateway, which runs unprivileged and parses hostile
// traffic, so this package is written as if the gateway were compromised.
// It believes one thing the gateway hands it: bytes that a release key
// compiled into the installed binary has signed. Everything else is checked
// here or ignored:
//
//   - which release may be installed is decided by the signed list and by the
//     installed version, never by the request. A request cannot ask for a
//     downgrade; only an operator at a root shell can.
//   - every file is opened beneath the gateway's data directory through
//     os.Root, so a symlink cannot make root read or delete something else,
//     and is refused unless it is a regular file within a size bound.
//   - the archive is copied into the helper's own directory before it is
//     hashed, so what is unpacked is what was verified.
//   - nothing the gateway wrote is executed, and nothing is parsed as an
//     archive until its SHA-256 has matched the signed list.
//
// What the gateway does get to say is whether it became ready and whether it
// migrated a database. Both are statements about itself, and the worst a
// false one achieves is choosing between two binaries that were each
// verified.
package helper
