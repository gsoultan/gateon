// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { ACME_CHALLENGE_TYPES } from "./acmeChallenges";

describe("ACME challenge types", () => {
  // acmeChallengeType (internal/server/tls.go) accepts these and nothing else.
  // DNS-01 was offered and silently replaced by HTTP-01 on the gateway.
  test("offers only challenges the gateway can run", () => {
    expect(ACME_CHALLENGE_TYPES.map((c) => c.value)).toEqual(["http", "tls-alpn"]);
  });
});
