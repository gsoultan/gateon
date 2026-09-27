// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { afterAll, beforeEach, describe, expect, mock, test } from "bun:test";

// The calls go through the real apiFetch; only the network under it is
// replaced, so each test decides what the gateway answers and reads back what
// was sent.
interface Sent {
  path: string;
  body: Record<string, unknown>;
}
let sent: Sent[] = [];
let answer: () => Promise<Response> = async () => new Response("{}", { status: 200 });

// hooks/api builds the Connect client from window.location at import; there
// is no window under bun:test.
mock.module("../services/client", () => ({ api: {} }));

const realFetch = globalThis.fetch;
globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
  sent.push({ path: new URL(String(input), "http://gateway.test").pathname, body: JSON.parse(String(init?.body)) });
  return answer();
}) as typeof fetch;
afterAll(() => {
  globalThis.fetch = realFetch;
});

const { changeOwnPassword, resetPassword } = await import("./passwordChange");

// What the gateway writes on a refusal. None of it may reach the form.
const SERVER_TEXT = '{"error":"rpc error: code = Internal desc = pq: deadlock detected"}';
const refusal = (status: number) => async () => new Response(SERVER_TEXT, { status });

beforeEach(() => {
  sent = [];
  answer = async () => new Response(JSON.stringify({ success: true }), { status: 200 });
});

describe("changeOwnPassword", () => {
  test("proves the account with its current password", async () => {
    expect(await changeOwnPassword("user-1", "old-pass", "new-pass")).toEqual({ ok: true });
    expect(sent).toEqual([
      { path: "/v1/users/password", body: { id: "user-1", password: "new-pass", currentPassword: "old-pass" } },
    ]);
  });

  test.each([
    [400, "Enter your current password to change it."],
    [403, "Your current password is not correct."],
    [429, "Too many failed attempts. The account is locked for a while; try again later."],
    [500, "The password could not be changed. Please try again."],
  ])("a %i says what happened in its own words, never the server's", async (status, message) => {
    answer = refusal(status);
    const outcome = await changeOwnPassword("user-1", "old-pass", "new-pass");

    expect(outcome).toEqual({ ok: false, message });
    expect(JSON.stringify(outcome)).not.toContain("pq:");
  });
});

describe("resetPassword", () => {
  test("sends no current password: an administrator resetting another account has none", async () => {
    expect(await resetPassword("user-2", "new-pass")).toEqual({ ok: true });
    expect(sent).toEqual([{ path: "/v1/users/password", body: { id: "user-2", password: "new-pass" } }]);
  });

  test("a refusal is about permission, not about a current password", async () => {
    answer = refusal(403);
    expect(await resetPassword("user-2", "new-pass")).toEqual({
      ok: false,
      message: "You do not have permission to change this password.",
    });
  });

  test("an unreachable gateway is told apart from a refusal", async () => {
    answer = async () => {
      throw new TypeError("Failed to fetch");
    };
    expect(await resetPassword("user-2", "new-pass")).toEqual({
      ok: false,
      message: "The gateway could not be reached. Check your connection and try again.",
    });
  });
});
