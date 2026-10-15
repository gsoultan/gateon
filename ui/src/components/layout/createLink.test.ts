// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { wantsCreateForm } from "./createLink";

describe("a link that opens a create form", () => {
  test("is recognised whether the router left the value a string or parsed it", () => {
    expect(wantsCreateForm({ new: "1" })).toBe(true);
    expect(wantsCreateForm({ new: 1 })).toBe(true);
  });

  test("is not assumed from an ordinary visit or another filter", () => {
    expect(wantsCreateForm({})).toBe(false);
    expect(wantsCreateForm({ q: "api" })).toBe(false);
    expect(wantsCreateForm({ new: "0" })).toBe(false);
  });
});
