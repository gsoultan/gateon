// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { afterAll, beforeEach, describe, expect, mock, test } from "bun:test";

// The calls go through the real apiFetch; only the network under it is
// replaced, so each test decides what the gateway answers and reads back what
// was sent. (Mocking hooks/api itself would replace it for every later test
// file in the run, and most of them use its other exports.)
interface Sent {
  path: string;
  body: Record<string, unknown>;
}
let sent: Sent[] = [];
let answer: () => Promise<Response> = async () => new Response("{}", { status: 200 });

// hooks/api builds the Connect client from window.location at import; there
// is no window under bun:test, and the client is not what is under test.
mock.module("../services/client", () => ({ api: {} }));

const realFetch = globalThis.fetch;
globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
  sent.push({ path: new URL(String(input), "http://gateway.test").pathname, body: JSON.parse(String(init?.body)) });
  return answer();
}) as typeof fetch;
afterAll(() => {
  globalThis.fetch = realFetch;
});

const { startTwoFactorSetup, verifyTwoFactorCode } = await import("./twoFactorSetup");

// What the gateway writes on a refusal. None of it may reach the dialog.
const SERVER_TEXT = '{"error":"pq: relation users does not exist","message":"internal detail"}';
const refusal = (status: number) => async () => new Response(SERVER_TEXT, { status });

beforeEach(() => {
  sent = [];
});

describe("startTwoFactorSetup", () => {
  test("proves the account with its current password", async () => {
    answer = async () =>
      new Response(JSON.stringify({ secret: "S", qrCodeUrl: "data:image/png;base64,QR", recoveryCodes: ["r1"] }), {
        status: 200,
      });
    const outcome = await startTwoFactorSetup("user-1", "hunter2");

    expect(sent).toEqual([{ path: "/v1/auth/2fa/setup", body: { id: "user-1", password: "hunter2" } }]);
    expect(outcome).toEqual({
      ok: true,
      data: { secret: "S", qrCodeUrl: "data:image/png;base64,QR", recoveryCodes: ["r1"] },
    });
  });

  test.each([
    [400, "Enter your current password to continue."],
    [403, "That password is not correct."],
    [429, "Too many failed attempts. The account is locked for a while; try again later."],
    [500, "Two-factor setup could not be started. Please try again."],
  ])("a %i says what happened in its own words, never the server's", async (status, message) => {
    answer = refusal(status);
    const outcome = await startTwoFactorSetup("user-1", "wrong");

    expect(outcome).toEqual({ ok: false, message });
    expect(JSON.stringify(outcome)).not.toContain("pq:");
  });

  test("an unreachable gateway is told apart from a refusal", async () => {
    answer = async () => {
      throw new TypeError("Failed to fetch");
    };
    const outcome = await startTwoFactorSetup("user-1", "pw");

    expect(outcome).toEqual({
      ok: false,
      message: "The gateway could not be reached. Check your connection and try again.",
    });
  });
});

describe("verifyTwoFactorCode", () => {
  test("a verified code completes enrolment", async () => {
    answer = async () => new Response(JSON.stringify({ success: true }), { status: 200 });
    const outcome = await verifyTwoFactorCode("user-1", "123456");

    expect(sent).toEqual([{ path: "/v1/auth/2fa/verify", body: { id: "user-1", code: "123456" } }]);
    expect(outcome).toEqual({ ok: true, data: null });
  });

  test.each([
    ["an unsuccessful answer", async () => new Response(JSON.stringify({ success: false }), { status: 200 })],
    ["a 403", refusal(403)],
  ])("%s reads as a wrong code", async (_name, reply) => {
    answer = reply;
    const outcome = await verifyTwoFactorCode("user-1", "000000");

    expect(outcome).toEqual({
      ok: false,
      message: "That code is not valid. Check that your device's clock is correct and try again.",
    });
  });

  test("a lockout is reported as one, not as a wrong code", async () => {
    answer = refusal(429);
    const outcome = await verifyTwoFactorCode("user-1", "000000");

    expect(outcome).toEqual({
      ok: false,
      message: "Too many failed attempts. The account is locked for a while; try again later.",
    });
  });
});
