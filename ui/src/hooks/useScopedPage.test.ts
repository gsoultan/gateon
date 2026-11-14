// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { pageInScope } from "./useScopedPage";

// Switching the Blocks tab from user to IP mitigations kept the page number, so
// page 3 of one list opened an empty page of the other.
describe("pageInScope", () => {
  test("keeps the page while the filters are the ones it was chosen under", () => {
    expect(pageInScope({ scope: "mitigated|user", page: 3 }, "mitigated|user")).toBe(3);
  });

  test("returns to the first page when any filter changes", () => {
    expect(pageInScope({ scope: "mitigated|user", page: 3 }, "mitigated|ip")).toBe(1);
  });
});
