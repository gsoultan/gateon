// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { hasUnsavedChanges } from "./configChanges";

const loaded = {
  log: { level: "info", format: "json" },
  tls: { enabled: true, certificates: [{ id: "a" }] },
  management: { allowedIps: ["10.0.0.0/8"] },
};

describe("the Settings save bar", () => {
  test("has nothing to save when nothing was edited", () => {
    expect(hasUnsavedChanges(structuredClone(loaded), loaded)).toBe(false);
  });

  test("has something to save after a field changes", () => {
    const edited = { ...loaded, log: { ...loaded.log, level: "debug" } };
    expect(hasUnsavedChanges(edited, loaded)).toBe(true);
  });

  test("notices a change deep in a list", () => {
    const edited = { ...loaded, management: { allowedIps: ["10.0.0.0/8", "192.168.0.0/16"] } };
    expect(hasUnsavedChanges(edited, loaded)).toBe(true);
  });

  test("has nothing to save once an edit is put back", () => {
    const edited = { ...loaded, log: { ...loaded.log, level: "debug" } };
    const reverted = { ...edited, log: { ...edited.log, level: "info" } };
    expect(hasUnsavedChanges(reverted, loaded)).toBe(false);
  });

  test("ignores key order and keys set to undefined", () => {
    const reordered = { management: loaded.management, tls: loaded.tls, log: { format: "json", level: "info", extra: undefined } };
    expect(hasUnsavedChanges(reordered, loaded)).toBe(false);
  });
});
