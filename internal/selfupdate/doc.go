// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package selfupdate finds out whether a newer release of gateon exists, and
// whether the list describing it was signed by a key this binary trusts
// (ADR 0085).
//
// It reads two small files from the release source: checksums.txt, which
// names every artifact of the newest release with its SHA-256, and
// checksums.txt.sig, an Ed25519 signature over that file. The version comes
// from the artifact names inside the signed file, never from an unsigned
// page, so whoever can rewrite the answer in transit can at most hide a
// release, not invent one.
//
// This package only looks. Nothing here downloads an artifact, replaces the
// binary or restarts the process.
package selfupdate
