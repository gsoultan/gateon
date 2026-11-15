// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, mock, test } from "bun:test";
import { MantineProvider } from "@mantine/core";
import { renderToString } from "react-dom/server";
import type { BuiltinWafRule } from "../../types/gateon";

type HookResult = {
  data?: { rules: BuiltinWafRule[]; total: number; categories: string[] };
  isPending: boolean;
  isError: boolean;
  refetch: () => void;
};

let result: HookResult = { isPending: true, isError: false, refetch: () => {} };
mock.module("../../hooks/useBuiltinWafRules", () => ({ useBuiltinWafRules: () => result }));

const { BuiltinWAFRules, detectionSource, onMatch } = await import("./BuiltinWAFRules");

const render = (next: Partial<HookResult>) => {
  result = { isPending: false, isError: false, refetch: () => {}, ...next };
  return renderToString(
    <MantineProvider>
      <BuiltinWAFRules />
    </MantineProvider>,
  );
};

const text4shell: BuiltinWafRule = {
  id: 1151006, name: "Text4Shell RCE attempt", category: "RCE", paranoiaLevel: 1,
  severity: "critical", confidence: "certain", phase: "request_body",
  tags: ["attack-rce", "cve-2022-42889"], action: "block", source: "gwaf", sourceRuleId: 100013,
};
const inboundKey: BuiltinWafRule = {
  id: 1131001, name: "AWS access key sent in a request", category: "DLP", paranoiaLevel: 2,
  severity: "warning", confidence: "high", phase: "request_body",
  action: "log", source: "gwaf", sourceRuleId: 111002,
};
const gambling: BuiltinWafRule = {
  id: 1210001, name: "Online gambling content detected", category: "ContentScanner", paranoiaLevel: 2,
  severity: "warning", confidence: "medium", phase: "request_body", action: "block", source: "gateon",
};

describe("the built-in WAF rules list", () => {
  test("says where each rule's detection comes from and what a match does", () => {
    const html = render({ data: { rules: [text4shell, inboundKey, gambling], total: 3, categories: ["DLP", "RCE"] } });
    expect(html).toContain("Text4Shell RCE attempt");
    expect(html).toContain("1151006");
    expect(html).toContain("gwaf 100013");
    expect(html).toContain("Records only");
    expect(html).toContain("Blocks");
    expect(detectionSource(gambling)).toBe("gateon");
    expect(onMatch(inboundKey).label).toBe("Records only");
    expect(onMatch(text4shell).label).toBe("Blocks");
  });

  // Read-only is the point: these are not rows, and a control that looked like
  // it changed one would do nothing.
  test("offers no way to edit or delete a rule", () => {
    const html = render({ data: { rules: [text4shell], total: 1, categories: ["RCE"] } });
    expect(html).not.toMatch(/Edit WAF rule|Delete WAF rule|Add Rule/);
    expect(html).toContain("cannot be edited or deleted");
  });

  test("has a loading, an empty and an error state, and the error is not the raw one", () => {
    expect(render({ isPending: true })).toContain("Loading built-in rules");
    expect(render({ data: { rules: [], total: 0, categories: [] } })).toContain("reports no built-in rules");

    const failed = render({ isError: true });
    expect(failed).toContain("could not be loaded");
    expect(failed).toContain("They are still running");
    expect(failed).toContain("Try again");
    expect(failed).not.toMatch(/HTTP \d/);
  });

  test("renders a rule name as text", () => {
    const html = render({
      data: { rules: [{ ...gambling, name: "<img src=x onerror=alert(1)>" }], total: 1, categories: [] },
    });
    expect(html).not.toContain("<img src=x");
    expect(html).toContain("&lt;img src=x");
  });
});
