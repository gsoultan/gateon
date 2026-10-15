// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { Glob } from "bun";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const SRC = join(import.meta.dir, "..");

// useMantineColorScheme().colorScheme is the operator's *setting*: "light",
// "dark" or "auto". The dashboard defaults to "auto", so on a system in dark
// mode `colorScheme === "dark"` is false, and the header, sidebar, health bar
// and topology nodes all drew their light-mode colours around a dark page.
// Whether the page is dark is useComputedColorScheme(), or a CSS selector on
// [data-mantine-color-scheme].
describe("dark mode", () => {
  test("is never decided by comparing the colour-scheme setting to a scheme", () => {
    const offenders: string[] = [];
    for (const file of new Glob("**/*.{ts,tsx}").scanSync(SRC)) {
      if (file.includes("services/gen") || file.endsWith(".test.ts") || file.endsWith(".test.tsx")) continue;
      const source = readFileSync(join(SRC, file), "utf8");
      if (/\bcolorScheme\s*[!=]==?\s*["'](dark|light)["']/.test(source)) offenders.push(file);
    }
    expect(offenders).toEqual([]);
  });
});
