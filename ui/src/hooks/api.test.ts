// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test, mock } from "bun:test";
import type { DatabaseConfig, SetupRequest } from "../types/gateon";
import type { SetupRequest as WireSetupRequest } from "../services/gen/gateon/v1/auth_pb";
import type { DatabaseConfig as WireDatabaseConfig } from "../services/gen/gateon/v1/common_pb";

// Compiles only when T is never; otherwise the type checker names what T is.
function assertNone<T extends never>(): T[] {
  return [];
}

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

  test("sends no key the proto message lacks", () => {
    // setupGateon hands this hand-written type to the generated client, which
    // serialises through the proto schema and drops a key the schema lacks --
    // as protojson does on the server -- without an error. The setup wizard's
    // logging database was sent that way and went nowhere. The check is the
    // type checker's, which `bun run build` runs first: a key missing from the
    // proto fails the build with `Type '"<key>"' does not satisfy the
    // constraint 'never'`.
    expect(assertNone<Exclude<keyof SetupRequest, keyof WireSetupRequest>>()).toEqual([]);
    expect(assertNone<Exclude<keyof DatabaseConfig, keyof WireDatabaseConfig>>()).toEqual([]);
  });
});
