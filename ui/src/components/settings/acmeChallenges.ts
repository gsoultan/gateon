// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// The ACME challenges the gateway can run. It uses autocert, which implements
// HTTP-01 and TLS-ALPN-01 only; the settings page offered DNS-01 as well, and
// the gateway logged an error and fell back to HTTP-01 -- so an operator who
// chose it for a wildcard certificate got none, with nothing on the page to
// say why. Keep in step with acmeChallengeType in internal/server/tls.go.
export const ACME_CHALLENGE_TYPES = [
  { label: "HTTP-01", value: "http" },
  { label: "TLS-ALPN-01", value: "tls-alpn" },
];

export const ACME_CHALLENGE_NOTE =
  "Wildcard certificates need DNS-01, which this gateway does not support; issue them elsewhere and upload them.";
