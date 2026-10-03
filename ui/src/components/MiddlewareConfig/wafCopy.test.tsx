// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test, mock } from "bun:test";
import { isValidElement, type ReactElement, type ReactNode } from "react";

// The editors import the API client, which reads window.location on import.
mock.module("../../services/client", () => ({ api: {} }));

const { WAFConfigFields } = await import("./SecurityConfigEditors");

type Props = Record<string, unknown>;

function byLabel(node: ReactNode, label: string): ReactElement<Props> | null {
  if (Array.isArray(node)) {
    for (const child of node) {
      const found = byLabel(child, label);
      if (found) return found;
    }
    return null;
  }
  if (!isValidElement<Props>(node)) return null;
  if (node.props.label === label) return node;
  return byLabel(node.props.children as ReactNode, label);
}

// An audit-only WAF and a DLP finding in a response used to lower the client's
// reputation until it was refused on every route, while the editor said
// "block nothing" (TRUTH-NEW-2, NEW-3). The gateway no longer does that (ADR
// 0055); these pin the editor saying so.
describe("route WAF editor", () => {
  const tree = WAFConfigFields({
    config: { dlp: "true" },
    updateConfig: () => {},
    global: undefined,
    globalUnreadable: false,
  });

  test("audit-only says its matches never count against the client", () => {
    const description = String(byLabel(tree, "Audit Only")?.props.description);
    expect(description).toContain("block nothing");
    expect(description).toContain("never count against the client");
    expect(description).toContain("no reputation penalty");
  });

  test("the DLP action says a leak is the backend's, never the reader's", () => {
    const description = String(byLabel(tree, "When a leak is found")?.props.description);
    expect(description).toContain("recorded on the route");
    expect(description).toContain("never counts against the client that received the page");
  });
});
