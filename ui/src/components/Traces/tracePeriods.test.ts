// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { archiveSpan, fromLocalInput, hourPeriod, periodProblem, presetPeriod, toLocalInput } from "./tracePeriods";

describe("trace periods", () => {
  test("a preset ends now and reaches back its length", () => {
    const now = new Date("2026-09-26T12:00:00Z");
    const p = presetPeriod("24h", now);
    expect(p.to).toEqual(now);
    expect(p.from.toISOString()).toBe("2026-09-25T12:00:00.000Z");
  });

  test("an archive file's hour is the hour after its start", () => {
    const p = hourPeriod("2026-09-26T14:00:00Z");
    expect(p?.from.toISOString()).toBe("2026-09-26T14:00:00.000Z");
    expect(p?.to.toISOString()).toBe("2026-09-26T15:00:00.000Z");
    expect(hourPeriod("not a time")).toBeNull();
  });

  // The status names the newest hour by its start; what the archive covers
  // runs to that hour's end. Shown as the start, it read an hour short.
  test("an archive covers from its oldest hour's start to its newest hour's end", () => {
    const span = archiveSpan("2026-09-25T00:00:00Z", "2026-09-26T01:00:00Z");
    expect(span?.from.toISOString()).toBe("2026-09-25T00:00:00.000Z");
    expect(span?.to.toISOString()).toBe("2026-09-26T02:00:00.000Z");
    expect(archiveSpan("", "")).toBeNull();
  });

  test("a local input round-trips to the minute", () => {
    const d = new Date(2026, 8, 26, 9, 5, 42);
    expect(toLocalInput(d)).toBe("2026-09-26T09:05");
    expect(fromLocalInput(toLocalInput(d))?.getTime()).toBe(new Date(2026, 8, 26, 9, 5).getTime());
  });

  test("an input that is not a local time is nothing, not a guess", () => {
    for (const v of ["", "2026-09-26", "2026-09-26T09:05Z", "yesterday", "2026-13-40T99:99"]) {
      expect(fromLocalInput(v)).toBeNull();
    }
  });

  test("a period that cannot be queried says why", () => {
    const a = new Date("2026-09-26T10:00:00Z");
    const b = new Date("2026-09-26T11:00:00Z");
    expect(periodProblem({ from: a, to: b })).toBeNull();
    expect(periodProblem({ from: null, to: b })).toContain("Choose");
    expect(periodProblem({ from: b, to: a })).toContain("start before");
    expect(periodProblem({ from: new Date("2024-01-01T00:00:00Z"), to: b })).toContain("400 days");
  });
});
