// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, mock, test } from "bun:test";

// The API answers a block it did not apply with success: false and a reason --
// a fingerprint named without a network, or one an operator released in the
// last day. The dashboard showed that as a green "Success" carrying the refusal.
let answer: { success: boolean; message: string } = { success: true, message: "" };
let lastRequest: Record<string, unknown> | undefined;
mock.module("../services/client", () => ({
  api: {
    mitigateThreat: async (req: Record<string, unknown>) => {
      lastRequest = req;
      return answer;
    },
  },
}));

const { mitigateOrThrow } = await import("./useMitigateThreat");

describe("mitigateOrThrow", () => {
  test("fails with the gateway's reason when the block is not in force", async () => {
    answer = { success: false, message: "fp was not blocked: it is not an address." };
    await expect(mitigateOrThrow({ source: "fp", type: "JA4+", reason: "", category: "manual" }))
      .rejects.toThrow("fp was not blocked: it is not an address.");
  });

  test("resolves when it is", async () => {
    answer = { success: true, message: "Source 203.0.113.7 successfully mitigated." };
    const res = await mitigateOrThrow({ source: "203.0.113.7", type: "IP", reason: "", category: "manual" });
    expect(res.message).toBe(answer.message);
  });

  // A bounded block's duration must reach the API, or the control does nothing
  // and every manual block is open-ended (ADR 0037).
  test("forwards a bounded block's duration to the API", async () => {
    answer = { success: true, message: "ok" };
    await mitigateOrThrow({ source: "203.0.113.7", type: "IP", reason: "", category: "manual", durationSeconds: 3600 });
    expect(lastRequest?.durationSeconds).toBe(3600);
  });

  // With no duration the request still carries an explicit 0, so an open-ended
  // block is unambiguous rather than an omitted field the backend must guess.
  test("sends 0 when no duration is chosen", async () => {
    answer = { success: true, message: "ok" };
    await mitigateOrThrow({ source: "203.0.113.7", type: "IP", reason: "", category: "manual" });
    expect(lastRequest?.durationSeconds).toBe(0);
  });
});
