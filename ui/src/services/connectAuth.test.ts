// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, mock, test } from "bun:test";
import { Code, ConnectError } from "@connectrpc/connect";

let logouts = 0;
mock.module("../store/useAuthStore", () => ({
  useAuthStore: { getState: () => ({ token: "__cookie__", logout: () => { logouts++; } }) },
}));

const { endSessionOnUnauthenticated } = await import("./connectAuth");

type Next = Parameters<typeof endSessionOnUnauthenticated>[0];
type Req = Parameters<ReturnType<typeof endSessionOnUnauthenticated>>[0];

const failingWith = (code: Code) =>
  (async () => {
    throw new ConnectError("refused", code);
  }) as unknown as Next;

describe("endSessionOnUnauthenticated", () => {
  // apiFetch signs the dashboard out on a 401; calls moved to the generated
  // client lost that until this interceptor.
  test("a call refused for want of a session signs the dashboard out", async () => {
    logouts = 0;
    await expect(endSessionOnUnauthenticated(failingWith(Code.Unauthenticated))({} as Req)).rejects.toThrow("refused");
    expect(logouts).toBe(1);
  });

  test("a permission refusal leaves the session alone", async () => {
    logouts = 0;
    await expect(endSessionOnUnauthenticated(failingWith(Code.PermissionDenied))({} as Req)).rejects.toThrow("refused");
    expect(logouts).toBe(0);
  });
});
