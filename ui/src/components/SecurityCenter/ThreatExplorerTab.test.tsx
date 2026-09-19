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
});
