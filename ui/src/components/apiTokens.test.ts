// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { Code, ConnectError } from "@connectrpc/connect";
import {
  formatTokenTime,
  isExpired,
  prometheusJob,
  tokenNameError,
  tokenRefusalMessage,
} from "./apiTokens";

describe("tokenNameError", () => {
  test.each([
    ["", "Give the token a name, such as the scraper that will use it"],
    ["   ", "Give the token a name, such as the scraper that will use it"],
    ["n".repeat(65), "Use at most 64 characters"],
  ])("refuses %p", (name, message) => {
    expect(tokenNameError(name)).toBe(message);
  });

  test("accepts a name up to the gateway's limit", () => {
    expect(tokenNameError("prometheus-eu-1")).toBeNull();
    expect(tokenNameError("n".repeat(64))).toBeNull();
  });
});

describe("isExpired", () => {
  const now = new Date("2026-10-03T12:00:00Z");
  test("a token with no expiry never expires", () => {
    expect(isExpired({ expiresAt: "" }, now)).toBe(false);
  });
  test("expires at its expiry, not after", () => {
    expect(isExpired({ expiresAt: "2026-10-03T12:00:00Z" }, now)).toBe(true);
    expect(isExpired({ expiresAt: "2026-10-03T12:00:01Z" }, now)).toBe(false);
  });
});

describe("formatTokenTime", () => {
  test("says the empty case in words", () => {
    expect(formatTokenTime("", "Never")).toBe("Never");
  });
});

describe("tokenRefusalMessage", () => {
  test.each([
    [Code.InvalidArgument, "at least one scope"],
    [Code.ResourceExhausted, "Revoke one"],
    [Code.PermissionDenied, "Only an administrator"],
    [Code.NotFound, "already have been revoked"],
    [Code.Unavailable, "until setup"],
    [Code.Internal, "Please try again"],
  ])("code %p is said in the dashboard's words, never the server's", (code, words) => {
    const msg = tokenRefusalMessage(new ConnectError("rpc error: sql: database is locked", code));
    expect(msg).toContain(words);
    expect(msg).not.toContain("sql:");
  });
});

describe("prometheusJob", () => {
  test("reads the token from a file, never inline", () => {
    const job = prometheusJob("gateway.internal:8080");
    expect(job).toContain("credentials_file: /etc/prometheus/gateon.token");
    expect(job).toContain('targets: ["gateway.internal:8080"]');
    expect(job).not.toContain("gateon_tok_");
  });
});
