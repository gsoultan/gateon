// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { passwordPolicyError } from "./passwordPolicy";

describe("passwordPolicyError", () => {
  test.each([
    ["a", "admin", "Use at least 12 characters"],
    ["elevenchars", "admin", "Use at least 12 characters"],
    ["x".repeat(73), "admin", "Use at most 72 bytes"],
    ["alice-in-the-garden", "Alice", "Do not include the username"],
  ])("refuses %p for %p", (password, username, message) => {
    expect(passwordPolicyError(password, username)).toBe(message);
  });

  test.each([
    ["correct horse battery", "admin"],
    // Length counts characters, as the gateway does: twelve runes, more bytes.
    ["ünïcödé-pässw", "admin"],
    // A two-letter username would refuse half the dictionary.
    ["my-ed-passphrase", "ed"],
  ])("accepts %p for %p", (password, username) => {
    expect(passwordPolicyError(password, username)).toBeNull();
  });
});
