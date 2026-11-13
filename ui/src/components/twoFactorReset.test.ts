// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { Code, ConnectError } from "@connectrpc/connect";
import { resetConfirmation, resetRefusalMessage, twoFactorAction, twoFactorActionable, twoFactorActionLabel } from "./twoFactorReset";

const enrolled = { id: "u-2", twoFactorEnabled: true, twoFactorPending: false };

describe("twoFactorAction", () => {
  test("an administrator can reset another account's enrolled second factor (MGMT-N5)", () => {
    expect(twoFactorAction(enrolled, "u-1", true)).toBe("reset");
    expect(twoFactorActionLabel("reset")).toBe("Reset this user's two-factor authentication");
  });

  test("one's own account is self-service, never a reset", () => {
    expect(twoFactorAction(enrolled, "u-2", true)).toBe("self");
  });

  // Every account enrols at its next sign-in (ADR 0087). The control used to
  // offer to require it, or to cancel the requirement -- a flag the sign-in no
  // longer reads -- so it offers nothing for an account that has not enrolled.
  test("an account that has not enrolled is waiting to, and nothing here changes that", () => {
    for (const pending of [false, true]) {
      const action = twoFactorAction({ ...enrolled, twoFactorEnabled: false, twoFactorPending: pending }, "u-1", true);
      expect(action).toBe("awaiting-enrolment");
      expect(twoFactorActionable(action)).toBe(false);
    }
    expect(twoFactorActionLabel("awaiting-enrolment")).toContain("next sign-in");
  });

  test("anyone else can do nothing to another account", () => {
    expect(twoFactorAction(enrolled, "u-1", false)).toBe("none");
  });
});

describe("resetConfirmation", () => {
  test("names the account and says what the reset does", () => {
    const c = resetConfirmation("alice");
    expect(c.question).toContain('"alice"');
    expect(c.question).toContain("every session they have ends");
    expect(c.question).toContain("set up a new authenticator");
    expect(c.confirm).toBe('Reset 2FA for "alice"');
  });
});

describe("resetRefusalMessage", () => {
  test.each([
    [Code.PermissionDenied, "not their own"],
    [Code.NotFound, "no longer exists"],
    [Code.Internal, "could not be reset"],
  ])("code %p is said in the dashboard's words", (code, words) => {
    const msg = resetRefusalMessage(new ConnectError("pq: internal detail", code));
    expect(msg).toContain(words);
    expect(msg).not.toContain("pq:");
  });
});
