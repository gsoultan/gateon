// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, mock, test } from "bun:test";

// The Connect client is the wire; what reaches it is what the gateway gets.
let sent: unknown;
mock.module("../services/client", () => ({
  api: {
    applyRecommendation: async (req: unknown) => {
      sent = req;
      return { success: true, message: "" };
    },
  },
}));

const { applyAnomalyFix } = await import("./api");

describe("applyAnomalyFix", () => {
  test("sends where the finding happened, not only who caused it", async () => {
    await applyAnomalyFix({
      type: "unlisted_route",
      source: "203.0.113.11",
      id: "finding-1",
      requestUri: "/unlisted-path",
      entrypoint: "http-plain",
      host: "localhost:8081",
    });

    // The fix creates a route for requestUri on entrypoint. It used to be sent
    // the source alone -- the client's address -- as if it were the path.
    expect(sent).toEqual({
      anomalyType: "unlisted_route",
      source: "203.0.113.11",
      threatId: "finding-1",
      requestUri: "/unlisted-path",
      entrypoint: "http-plain",
      host: "localhost:8081",
    });
  });
});
