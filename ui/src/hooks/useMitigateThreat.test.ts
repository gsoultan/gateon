// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, mock, test } from "bun:test";

// The API answers a block it did not apply with success: false and a reason --
// a fingerprint named without a network, or one an operator released in the
// last day. The dashboard showed that as a green "Success" carrying the refusal.
let answer: { success: boolean; message: string } = { success: true, message: "" };
mock.module("../services/client", () => ({
  api: { mitigateThreat: async () => answer },
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
});
