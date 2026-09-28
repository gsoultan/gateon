// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import type { User } from "../types/gateon";
import { userUpdateBody } from "./userUpdate";

// Disabled, and required by an administrator to set up 2FA.
const held: User = {
  id: "user-1",
  username: "alice",
  role: "viewer",
  disabled: true,
  twoFactorPending: true,
  twoFactorEnabled: false,
};

describe("userUpdateBody", () => {
  test("an edit of the name and role keeps the account disabled and its 2FA required", () => {
    // What the Edit form submits: the name, an untouched password field, the role.
    expect(userUpdateBody(held, { username: "alice", password: "", role: "operator" })).toEqual({
      id: "user-1",
      username: "alice",
      password: "",
      role: "operator",
      disabled: true,
      twoFactorPending: true,
      twoFactorEnabled: false,
    });
  });

  test("a change wins over what the account has, and only that change", () => {
    expect(userUpdateBody(held, { disabled: false })).toEqual({ ...held, disabled: false });
  });

  test("an enrolled account says so, so the gateway leaves its pending flag alone", () => {
    const enrolled: User = { id: "user-2", username: "bob", role: "admin", twoFactorEnabled: true };
    expect(userUpdateBody(enrolled, { role: "viewer" })).toEqual({
      id: "user-2",
      username: "bob",
      role: "viewer",
      disabled: false,
      twoFactorPending: false,
      twoFactorEnabled: true,
    });
  });
});
