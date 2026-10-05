// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, mock, test } from "bun:test";
import { MantineProvider } from "@mantine/core";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToString } from "react-dom/server";
import type { MetricsSnapshot } from "../../types/metrics";

// OverviewTab reaches hooks/api, which builds the Connect client from
// window.location at import; there is no window under bun:test.
mock.module("../../services/client", () => ({ api: {} }));

const { OverviewTab } = await import("./OverviewTab");

const render = (metrics: MetricsSnapshot) =>
  renderToString(
    <QueryClientProvider client={new QueryClient()}>
      <MantineProvider>
        <OverviewTab metrics={metrics} threatTypeData={[]} totalThreats={0} />
      </MantineProvider>
    </QueryClientProvider>,
  );

// Truth T41: "Global Threat Score" showed the day's unscaled sum of every
// threat's score (3700 on the review host) and called it a "real-time estimate
// of system-wide risk level". It has no scale, no window an operator can read
// and no threshold, so it is not shown; the threat counts beside it are.
describe("the Security Hub overview", () => {
  test("does not show an unscaled threat-score sum as a risk level", () => {
    const html = render({ security: { globalThreatScore: 3700 } } as unknown as MetricsSnapshot);
    expect(html).toContain("Mitigated Today");
    expect(html).not.toContain("Global Threat Score");
    expect(html).not.toContain("system-wide risk level");
  });
});
