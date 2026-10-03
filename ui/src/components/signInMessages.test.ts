// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";

import {
  enrolmentRefusalMessage,
  isChallengeRefusal,
  signInCodeRefusalMessage,
  signInRefusalMessage,
} from "./signInMessages";

const LOCKED = "Too many attempts right now. Wait a few minutes and try again.";

describe("sign-in refusals", () => {
  test.each([
    [401, "Invalid username or password."],
    [429, "Too many sign-in attempts. Wait a minute and try again."],
    [503, "The gateway is not ready to sign you in yet. Try again shortly."],
    [500, "Sign-in failed. Please try again."],
    [403, "Sign-in failed. Please try again."],
  ])("a %i to the password step reads %p", (status, message) => {
    expect(signInRefusalMessage(status)).toBe(message);
  });

  test.each([
    [401, "That code is not valid. Check that your device's clock is correct and try again."],
    [429, LOCKED],
    [500, "The code could not be verified. Please try again."],
  ])("a %i to the code step reads %p", (status, message) => {
    expect(signInCodeRefusalMessage(status)).toBe(message);
  });

  test.each([
    [401, "Invalid username or password."],
    [403, "This account cannot sign in. Contact an administrator."],
    [429, LOCKED],
    [500, "Two-factor setup could not be started. Please try again."],
  ])("a %i to the required enrolment reads %p", (status, message) => {
    expect(enrolmentRefusalMessage(status)).toBe(message);
  });
});

// The page used to render the gateway's answer after "Access denied:" and
// "Could not start 2FA setup:". Nothing it shows may come from a response body.
test("the sign-in page shows none of the gateway's text", () => {
  const page = readFileSync(new URL("../routes/LoginPage.tsx", import.meta.url), "utf8");

  expect(page).not.toContain("res.text()");
  expect(page).not.toContain("res.statusText");
  expect(page).toContain("signInRefusalMessage(res.status)");
  expect(page).toContain("enrolmentRefusalMessage(res.status)");
  expect(page).toContain("signInCodeRefusalMessage(res.status)");
});

// The second step is refused for its challenge with 401 and a fixed code; the
// page keys on the code alone and sends the user back to the password.
describe("isChallengeRefusal", () => {
  const reply = (status: number, body: unknown) => new Response(JSON.stringify(body), { status });

  test.each([
    ["the challenge code on a 401", () => reply(401, { code: "two_factor_challenge_invalid" }), true],
    ["a wrong code's 401", () => reply(401, { error: "invalid two-factor authentication code" }), false],
    ["the challenge code on another status", () => reply(403, { code: "two_factor_challenge_invalid" }), false],
    ["a body that is not JSON", () => new Response("<html>", { status: 401 }), false],
  ])("%s", async (_name, res, want) => {
    expect(await isChallengeRefusal(res())).toBe(want);
  });
});

// ADR 0039: the code step carries the password step's challenge, which lives in
// component state and nowhere a script could find it later.
test("the sign-in page carries the challenge and keeps it out of storage", () => {
  const page = readFileSync(new URL("../routes/LoginPage.tsx", import.meta.url), "utf8");

  expect(page).toContain("code: tfaCode, challenge }");
  expect(page).toContain("setChallenge(data.twoFactorChallenge");
  expect(page).not.toMatch(/(localStorage|sessionStorage)[^\n]*challenge/i);
});
