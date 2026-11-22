// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test, mock } from "bun:test";
import { isValidElement, type ReactElement, type ReactNode } from "react";

// The component imports the API client, which reads window.location on import.
mock.module("../../services/client", () => ({ api: {} }));

const { AdvisoryReviewFields, AdvisoryStatusView, advisoryCountsSummary, advisoryModeSummary } =
  await import("./AdvisoryReviewFields");
import type { AdvisoryStatus } from "./AdvisoryReviewFields";

type Props = Record<string, unknown>;

const find = (node: ReactNode, label: string): ReactElement<Props> | null => {
  if (Array.isArray(node)) return node.map((n) => find(n, label)).find(Boolean) ?? null;
  if (!isValidElement<Props>(node)) return null;
  if (node.props.label === label) return node;
  return find(node.props.children as ReactNode, label);
};

const text = (node: ReactNode) => JSON.stringify(node);

const idle: AdvisoryStatus = {
  configured: true,
  worker: "https://worker.example:8443",
  mode: "record",
  queueCapacity: 256,
  queued: 0,
  offered: 0,
  dropped: 0,
  sent: 0,
  failed: 0,
  flagged: 0,
  lastContact: 0,
  lastError: "",
};

// The switch sends requests to another host, so the form says what is sent
// and what never is, and writes the keys the gateway reads (advisory_review,
// advisory_sample_rate; waf_advisory_test.go).
describe("route WAF editor, advisory review", () => {
  test("the switch says what is sent, what never is, and that nothing is refused", () => {
    const written: Record<string, string> = {};
    const view = AdvisoryReviewFields({
      config: {},
      updateConfig: (key, value) => {
        written[key] = value;
      },
    });
    const toggle = find(view, "Ask the advisory worker about forwarded requests");
    const description = String(toggle?.props.description);
    expect(description).toContain("Never sent: bodies, client addresses and credentials");
    expect(description).toContain("never slows or refuses one");
    expect(toggle?.props.checked).toBe(false);
    (toggle?.props.onChange as (e: unknown) => void)({ currentTarget: { checked: true } });
    expect(written.advisory_review).toBe("true");
    // The rate and the status belong to a switch that is on.
    expect(find(view, "Also Ask About Ordinary Requests")).toBeNull();
  });

  test("a rate is written under the key the gateway reads, and clearing it writes off", () => {
    const written: Record<string, string> = {};
    const field = find(
      AdvisoryReviewFields({
        config: { advisory_review: "true", advisory_sample_rate: "100" },
        updateConfig: (key, value) => {
          written[key] = value;
        },
      }),
      "Also Ask About Ordinary Requests",
    );
    expect(field?.props.value).toBe(100);
    const onChange = field?.props.onChange as (v: number | string) => void;
    onChange(20);
    expect(written.advisory_sample_rate).toBe("20");
    onChange("");
    expect(written.advisory_sample_rate).toBe("0");
  });
});

// A switch that is on and does nothing is the defect: with no worker the form
// says so, and says how to get one.
describe("advisory worker status", () => {
  test("a gateway with no worker says the switch does nothing and names the setting", () => {
    const view = text(AdvisoryStatusView({ status: { ...idle, configured: false, worker: "" } }));
    expect(view).toContain("this switch does nothing yet");
    expect(view).toContain("GATEON_WAF_ADVISORY_URL");
    expect(view).toContain("gateon advisory-worker");
  });

  test("a worker that has been sent nothing is an empty state that says what to do", () => {
    expect(advisoryCountsSummary(idle)).toContain("No request has been sent yet");
    expect(text(AdvisoryStatusView({ status: idle }))).toContain("The worker is https://worker.example:8443.");
  });

  test("the mode says whether a verdict counts against the client", () => {
    expect(advisoryModeSummary("record")).toContain("held against nobody");
    expect(advisoryModeSummary("reputation")).toContain("counts against the client's reputation");
  });

  test("what was judged, flagged, left out and lost are each counted", () => {
    expect(advisoryCountsSummary({ ...idle, offered: 50, sent: 40, flagged: 3 })).toBe(
      "40 requests judged across all routes, 3 flagged.",
    );
    const lossy = advisoryCountsSummary({ ...idle, offered: 50, sent: 40, flagged: 3, dropped: 6, failed: 4 });
    expect(lossy).toContain("6 were left out because the queue of 256 was full");
    expect(lossy).toContain("4 were lost because the worker did not answer");
  });

  test("a worker that is not answering is said, with why", () => {
    const view = text(AdvisoryStatusView({ status: { ...idle, offered: 9, lastError: "the worker answered 502" } }));
    expect(view).toContain("The worker is not answering");
    expect(view).toContain("the worker answered 502");
  });
});
