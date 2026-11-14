// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, mock, test } from "bun:test";
import { MantineProvider } from "@mantine/core";
import { renderToString } from "react-dom/server";

// hooks/api builds the Connect client at module init from window.location;
// nothing here calls it.
mock.module("../../services/client", () => ({ api: {} }));

const { RuleStatus } = await import("./WAFRulesTab");

const render = (el: React.ReactElement) => renderToString(<MantineProvider>{el}</MantineProvider>);

// The status column read the switch alone: a rule above every WAF's paranoia
// level said "Enabled" and no request was ever checked against it.
describe("RuleStatus", () => {
  test("says a switched-on rule that no WAF compiles runs nowhere", () => {
    expect(render(<RuleStatus enabled runsIn={[]} paranoia={2} />)).toContain("runs nowhere");
  });

  test("says Enabled for a rule some WAF runs, and Disabled for one switched off", () => {
    const on = render(<RuleStatus enabled runsIn={["the gateway-wide WAF"]} paranoia={1} />);
    expect(on).toContain("Enabled");
    expect(on).not.toContain("runs nowhere");
    expect(render(<RuleStatus enabled={false} runsIn={[]} paranoia={2} />)).toContain("Disabled");
  });
});
