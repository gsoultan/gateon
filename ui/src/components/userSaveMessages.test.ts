// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { USERNAME_TAKEN, userSaveRefusalMessage } from "./userSaveMessages";

describe("userSaveRefusalMessage", () => {
  test("a taken username is said in the dashboard's own words", () => {
    expect(userSaveRefusalMessage(409)).toBe(USERNAME_TAKEN);
    expect(USERNAME_TAKEN).toBe(
      "That username is already taken by another account. Choose a different username.",
    );
  });

  test.each([400, 403, 500])("a %i has no fixed sentence and keeps today's handling", (status) => {
    expect(userSaveRefusalMessage(status)).toBeNull();
  });
});
