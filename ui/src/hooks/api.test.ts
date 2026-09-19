// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test, mock } from "bun:test";
import type { SetupRequest } from "../types/gateon";

// The client reads window.location when it is imported; there is no window
// under bun:test, and the setup RPC itself is not what is under test.
mock.module("../services/client", () => ({
  api: { setup: async () => ({ success: true, error: "" }) },
}));

const { setupGateon } = await import("./api");
const { queryClient } = await import("../queryClient");

describe("setupGateon", () => {
  test("forgets the cached 'setup required' answer once setup has succeeded", async () => {
    // What the root route cached before it sent the operator to /setup. The
    // route answers every later navigation from this entry without refetching,
    // so a stale `true` here bounces the post-setup navigation back to /setup.
    queryClient.setQueryData(["setup-required"], { required: true });

    await setupGateon({} as SetupRequest);

    expect(queryClient.getQueryData(["setup-required"])).toBeUndefined();
  });
});
