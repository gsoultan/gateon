// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { describeConfigImport, settleConfigImport } from "./configImportResult";

// The gateway's answer to an exported config with one Cloudflare IP filter
// that this gateway refuses: everything else was written.
const partial = {
  success: true,
  applied: { routes: 2, services: 2, entry_points: 1, middlewares: 6 },
  errors: ['middleware c9a8: middleware config "trust_cloudflare_headers": "true" is not valid'],
};

describe("config import result", () => {
  test("a partial import says what it imported as well as what it refused", () => {
    const out = describeConfigImport(partial);

    expect(out.tone).toBe("partial");
    expect(out.summary).toContain("2 routes");
    expect(out.summary).toContain("2 services");
    expect(out.summary).toContain("6 policies");
    expect(out.summary).toContain("1 item was not imported");
    expect(out.refused).toEqual(partial.errors);
  });

  test("an import that applied nothing says so", () => {
    const out = describeConfigImport({ success: false, applied: {}, errors: ["route r1: missing rule"] });

    expect(out.tone).toBe("failed");
    expect(out.summary).toStartWith("Nothing was imported.");
  });

  test("a clean import is a success", () => {
    expect(describeConfigImport({ success: true, applied: { routes: 1 } }).tone).toBe("success");
  });

  test("a partial import refreshes the cached lists, or they keep showing the old config", async () => {
    let invalidated = 0;
    const client = { invalidateQueries: async () => void invalidated++ };

    await settleConfigImport(partial, client);

    expect(invalidated).toBe(1);
  });
});
