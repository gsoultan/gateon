// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";

import { enrolmentRefusalMessage, signInCodeRefusalMessage, signInRefusalMessage } from "./signInMessages";

const LOCKED = "Too many failed attempts. The account is locked for a while; try again later.";

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
