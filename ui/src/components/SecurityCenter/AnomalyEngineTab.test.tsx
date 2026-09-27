// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, mock, test } from "bun:test";
import { MantineProvider } from "@mantine/core";
import { renderToString } from "react-dom/server";

import type { Anomaly } from "../../types/gateon";

// The tab's module reaches hooks/api, which builds the Connect client from
// window.location at import; there is no window under bun:test. The card
// rendered below makes no calls of its own.
mock.module("../../services/client", () => ({ api: {} }));

const { AnomalyCard } = await import("./AnomalyEngineTab");

const finding = (type: string, mitigated = false): Anomaly => ({
  type,
  severity: "medium",
  description: `a ${type} finding`,
  timestamp: "2026-09-27T00:00:00Z",
  source: "203.0.113.11",
  recommendation: "Do the thing.",
  requestUri: "/unlisted-path",
  entrypoint: "http-plain",
  mitigated,
});

const render = (anomaly: Anomaly, canWrite = true) =>
  renderToString(
    <MantineProvider>
      <AnomalyCard anomaly={anomaly} onApply={() => undefined} applying={false} onTrace={() => undefined} canWrite={canWrite} />
    </MantineProvider>,
  );

const APPLY = "Apply automatic fix";

describe("AnomalyCard's Apply automatic fix", () => {
  test("is offered for a finding the gateway can fix", () => {
    expect(render(finding("unlisted_route"))).toContain(APPLY);
  });

  // The nine types the AI analysis review found offered with no fix behind
  // them: the click could only answer that nothing was done.
  test.each([
    "honeypot_triggered",
    "neural_sentinel",
    "graph_coordinated_fp",
    "reputation_hit",
    "suspicious_activity",
    "coordinated_attack",
    "system_integrity_violation",
    "configuration_recommendation",
    "honeypot_hit",
  ])("is not offered for %s, which has no fix", (type) => {
    const html = render(finding(type));

    expect(html).toContain(`a ${type} finding`);
    expect(html).not.toContain(APPLY);
  });

  test("is not offered once a finding is mitigated", () => {
    expect(render(finding("unlisted_route", true))).not.toContain(APPLY);
  });

  test("is not offered to a role that cannot change anything", () => {
    expect(render(finding("unlisted_route"), false)).not.toContain(APPLY);
  });
});

describe("AnomalyCard's count of folded requests", () => {
  test("says how many requests and clients a folded finding stands for", () => {
    const html = render({ ...finding("unlisted_route"), occurrences: 3, sourceIps: ["10.0.0.1", "10.0.0.2"] });

    expect(html).toContain("· seen 3 times from 2 clients");
  });

  test("says when it lists only some of the clients", () => {
    const many = Array.from({ length: 10 }, (_, i) => `10.0.0.${i}`);
    const html = render({ ...finding("unlisted_route"), occurrences: 50, sourceIps: many });

    expect(html).toContain("· seen 50 times from 10 or more clients");
  });

  test("says nothing for a single request", () => {
    expect(render({ ...finding("unlisted_route"), occurrences: 1 })).not.toContain("seen");
  });
});
