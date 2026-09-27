// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, mock, test } from "bun:test";
import { MantineProvider } from "@mantine/core";
import { renderToString } from "react-dom/server";

import type { Anomaly } from "../../types/gateon";

// The tab, and the two modals it mounts, read every hook they need from the
// useGateon barrel. Replacing the barrel keeps the render free of the network,
// the Connect client and the SSE stream, and lets each test decide what the
// threats query returns.
interface ThreatsQuery {
  data?: { threats: Anomaly[]; totalCount: number };
  isLoading: boolean;
  error: unknown;
  refetch: () => Promise<unknown>;
}

let threatsQuery: ThreatsQuery = {
  data: undefined,
  isLoading: false,
  error: null,
  refetch: async () => undefined,
};

const inertMutation = {
  mutate: () => undefined,
  mutateAsync: async () => ({}),
  isPending: false,
};

// TraceVisualizer reaches hooks/api, which builds the Connect client at module
// init from window.location. There is no window here; the client itself is
// never called by these renders. hooks/api stays real so QueryError's
// getApiErrorMessage — the thing under test — is the shipped one.
mock.module("../../services/client", () => ({ api: {} }));

// Role comes from a zustand store, and zustand reads the store's *initial*
// state as the server snapshot, so seeding it with setState is invisible to
// renderToString. Grant write access at the hook instead.
mock.module("../../hooks/usePermissions", () => ({
  usePermissions: () => ({
    canWrite: true,
    canManageUsers: true,
    canEditGlobal: true,
    canImportConfig: true,
    canExportConfig: true,
    canUploadCerts: true,
    isViewer: false,
  }),
}));

mock.module("../../hooks/useGateon", () => ({
  useSecurityThreats: () => threatsQuery,
  useSecurityThreat: () => ({ data: undefined }),
  useDiagnostics: () => ({ data: undefined }),
  useRemoveMitigation: () => inertMutation,
  useApplyRecommendation: () => inertMutation,
  useMitigateThreat: () => inertMutation,
}));

const { ThreatExplorerTab } = await import("./ThreatExplorerTab");

const render = () =>
  renderToString(
    <MantineProvider>
      <ThreatExplorerTab />
    </MantineProvider>,
  );

describe("ThreatExplorerTab error state", () => {
  test("shows the friendly message instead of the server's error body", () => {
    // What the management API writes on a 403, and what the query surfaces as
    // error.message. It used to be rendered verbatim after "Failed to load
    // threats:".
    threatsQuery = {
      data: undefined,
      isLoading: false,
      error: new Error('{"error":"insufficient permissions"}'),
      refetch: async () => undefined,
    };

    const html = render();

    // React escapes the quotes, so the raw envelope would appear as
    // {&quot;error&quot;:...}.
    expect(html).not.toContain("&quot;error&quot;");
    expect(html).toContain("Insufficient permissions. You do not have access to perform this action.");
    // The error state offers a way back; the old alert was a dead end.
    expect(html).toContain("Try again");
  });
});

describe("ThreatExplorerTab mitigated rows", () => {
  test("renders Allow for a mitigated threat without a pending confirmation", () => {
    const threat: Anomaly = {
      id: "t-1",
      type: "waf_block",
      severity: "high",
      description: "SQL injection attempt",
      timestamp: "2026-09-19T00:00:00Z",
      source: "203.0.113.9",
      recommendation: "",
      mitigated: true,
      ja4plus: "t13d1516h2_8daaf6152771_e5627efa2ab1",
    };
    threatsQuery = {
      data: { threats: [threat], totalCount: 1 },
      isLoading: false,
      error: null,
      refetch: async () => undefined,
    };

    const html = render();

    expect(html).toContain("203.0.113.9");
    expect(html).toContain(">Allow<");
    // Nothing is pending until the operator clicks Allow, so the dialog that
    // names the source is not on the page yet.
    expect(html).not.toContain("Allow this source again?");
  });

  // Kernel rate limits were listed nowhere, so an address could be held to a
  // few packets a second with nothing on this page to show it or release it.
  // The row says how hard, why and until when, where a threat shows its URL,
  // and is marked throttled rather than blocked.
  test("shows a kernel throttle's rate, reason and expiry, and offers Allow", () => {
    const throttle: Anomaly = {
      id: "kernel_throttle:10.60.0.3",
      type: "kernel_throttle",
      severity: "medium",
      description:
        "10.60.0.3 is rate-limited in the kernel to 100 packets a second, after a burst of 64. " +
        "Why: Neural Sentinel on repeated analysis passes. Lapses at 2026-09-27T14:05:00Z unless set again.",
      timestamp: "2026-09-27T14:00:00Z",
      source: "10.60.0.3",
      recommendation: "",
      mitigated: true,
      actionTaken: "throttled",
    };
    threatsQuery = {
      data: { threats: [throttle], totalCount: 1 },
      isLoading: false,
      error: null,
      refetch: async () => undefined,
    };

    const html = render();

    expect(html).toContain("100 packets a second");
    expect(html).toContain("Lapses at 2026-09-27T14:05:00Z");
    expect(html).toContain(">Throttled<");
    expect(html).not.toContain(">Mitigated<");
    expect(html).toContain(">Allow<");
  });

  // The expiry was only in the description, as a timestamp to read and
  // subtract. The row counts down to the structured expires_at instead.
  test("counts down to a kernel throttle's expiry", () => {
    const throttle: Anomaly = {
      id: "kernel_throttle:10.60.0.4",
      type: "kernel_throttle",
      severity: "medium",
      description: "10.60.0.4 is rate-limited in the kernel to 100 packets a second.",
      timestamp: new Date().toISOString(),
      source: "10.60.0.4",
      recommendation: "",
      mitigated: true,
      actionTaken: "throttled",
      expiresAt: new Date(Date.now() + 4 * 60_000 - 5_000).toISOString(),
    };
    const blocked: Anomaly = {
      id: "t-2",
      type: "ip_shunning",
      severity: "high",
      description: "blocked",
      timestamp: "2026-09-27T14:00:00Z",
      source: "10.60.0.5",
      recommendation: "",
      mitigated: true,
    };
    threatsQuery = {
      data: { threats: [throttle, blocked], totalCount: 2 },
      isLoading: false,
      error: null,
      refetch: async () => undefined,
    };

    const html = render();

    expect(html).toContain("lifts in 4m");
    // A block with no expiry of its own says nothing about lifting.
    expect(html.match(/data-testid="lifts-in"/g)?.length).toBe(1);
  });
});
