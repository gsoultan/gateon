// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { afterAll, beforeEach, describe, expect, mock, test } from "bun:test";

// The calls go through the real apiFetch; only the network under it is
// replaced, so each test decides what the gateway answers and reads back what
// was asked.
let asked: string[] = [];
let answers: Record<string, () => Promise<Response>> = {};

// hooks/api builds the Connect client from window.location at import, and a
// 401 signs the store out, which reaches for the live-update socket; there is
// no window under bun:test.
mock.module("../services/client", () => ({ api: {} }));
mock.module("../store/useAuthStore", () => ({
  useAuthStore: { getState: () => ({ token: null, logout: () => {} }) },
}));

const realFetch = globalThis.fetch;
globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
  const path = new URL(String(input), "http://gateway.test").pathname;
  asked.push(`${init?.method ?? "GET"} ${path}`);
  const answer = answers[path];
  if (!answer) throw new Error(`nothing staged for ${path}`);
  return answer();
}) as typeof fetch;
afterAll(() => {
  globalThis.fetch = realFetch;
});

const { signOutEverywhere, OTHER_SESSIONS_MAY_REMAIN, SESSION_HAD_ENDED, NOT_SIGNED_OUT } = await import("./signOut");

const status = (code: number) => async () => new Response("{}", { status: code });
const unreachable = async (): Promise<Response> => {
  throw new TypeError("Failed to fetch");
};

beforeEach(() => {
  asked = [];
  answers = {};
});

describe("signOutEverywhere", () => {
  test("a success ended every session, and nothing more is asked", async () => {
    answers["/v1/logout"] = status(200);
    expect(await signOutEverywhere()).toEqual({ signedOut: true, warning: null });
    expect(asked).toEqual(["POST /v1/logout"]);
  });

  test("a 500 that signed this browser out says the other sessions may remain", async () => {
    // What the gateway does when it cannot end the account's sessions: it
    // clears this browser's cookie and answers 500.
    answers["/v1/logout"] = status(500);
    answers["/v1/me"] = status(401);
    expect(await signOutEverywhere()).toEqual({ signedOut: true, warning: OTHER_SESSIONS_MAY_REMAIN });
    expect(asked).toEqual(["POST /v1/logout", "GET /v1/me"]);
  });

  test("a refusal that left this browser signed in is not a sign-out", async () => {
    // A proxy in front of the gateway, say: the request never arrived.
    answers["/v1/logout"] = status(503);
    answers["/v1/me"] = status(200);
    expect(await signOutEverywhere()).toEqual({ signedOut: false, warning: NOT_SIGNED_OUT });
  });

  test("an unreachable gateway signed nothing out", async () => {
    answers["/v1/logout"] = unreachable;
    answers["/v1/me"] = unreachable;
    expect(await signOutEverywhere()).toEqual({ signedOut: false, warning: NOT_SIGNED_OUT });
  });

  test("an answer lost on its way back is checked, not assumed", async () => {
    answers["/v1/logout"] = unreachable;
    answers["/v1/me"] = status(401);
    expect(await signOutEverywhere()).toEqual({ signedOut: true, warning: OTHER_SESSIONS_MAY_REMAIN });
  });

  test("a session that had already ended says the others were not signed out", async () => {
    answers["/v1/logout"] = status(401);
    expect(await signOutEverywhere()).toEqual({ signedOut: true, warning: SESSION_HAD_ENDED });
    expect(asked).toEqual(["POST /v1/logout"]);
  });
});
