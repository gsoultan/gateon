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

function byType(node: ReactNode, type: unknown): ReactElement<Props> | null {
  if (Array.isArray(node)) {
    for (const child of node) {
      const found = byType(child, type);
      if (found) return found;
    }
    return null;
  }
  if (!isValidElement<Props>(node)) return null;
  if (node.type === type) return node;
  return byType(node.props.children as ReactNode, type);
}

// The gateway records by default, forwards a path the document does not
// describe, and holds a schema refusal against nobody (waf_openapi_test.go).
// These pin the form saying the same three things.
describe("route WAF editor, OpenAPI document", async () => {
  const { OpenApiSpecFields, openApiSpecProblem } = await import("./OpenApiSpecFields");
  const { OPENAPI_MODE_HELP, OPENAPI_SPEC_HELP, OPENAPI_MAX_BYTES, DLP_ACTION_HELP } = await import("./wafCopy");

  test("the route form carries the section and tells it when the route is audit-only", () => {
    const tree = WAFConfigFields({
      config: { audit_only: "true" },
      updateConfig: () => {},
      global: undefined,
      globalUnreadable: false,
    });
    expect(byType(tree, OpenApiSpecFields)?.props.auditOnly).toBe(true);
  });

  test("the copy says what is checked, what is not, and what a refusal costs the client", () => {
    expect(OPENAPI_SPEC_HELP).toContain("A path it does not describe is not checked");
    expect(OPENAPI_MODE_HELP).toContain("Recorded requests are forwarded");
    expect(OPENAPI_MODE_HELP).toContain("not held against the client");
  });

  test("a document over the gateway's limit is refused in the form, in bytes", () => {
    expect(openApiSpecProblem("openapi: 3.0.3")).toBe("");
    expect(openApiSpecProblem("x".repeat(OPENAPI_MAX_BYTES + 1))).toContain("larger than 1024 KiB");
    // Three bytes each in UTF-8: under the limit in characters, over it in bytes.
    expect(openApiSpecProblem("€".repeat(OPENAPI_MAX_BYTES / 2))).toContain("larger than");
  });

  test("the DLP action says an exploit's result is refused under Redact", () => {
    expect(DLP_ACTION_HELP).toContain("refused whole under Redact too");
  });
});

// The gateway closes the connection on a refused message, closes it on one
// past the limit, stops offering compression, and on an audit-only route
// forwards both (waf_websocket_test.go). These pin the form saying so before
// an operator turns it on, because each of them changes a working route.
describe("route WAF editor, WebSocket inspection", () => {
  const editor = (config: Record<string, string>) =>
    WAFConfigFields({ config, updateConfig: () => {}, global: undefined, globalUnreadable: false });

  test("the switch says what turning it on changes", () => {
    const description = String(byLabel(editor({}), "Inspect WebSocket messages")?.props.description);
    expect(description).toContain("closes the connection (code 1008)");
    expect(description).toContain("compression (permessage-deflate) is not offered");
    expect(description).toContain("any other upgraded protocol is closed");
    expect(description).toContain("Messages the backend sends are not inspected");
  });

  test("the limit appears only with inspection on, and says a larger message closes the connection", () => {
    expect(byLabel(editor({}), "WebSocket Message Limit")).toBeNull();
    const limit = byLabel(editor({ websocket_inspection: "true" }), "WebSocket Message Limit");
    expect(String(limit?.props.description)).toContain("closes the connection (code 1009)");
  });

  test("an audit-only route is told its messages are forwarded", () => {
    const text = (config: Record<string, string>) => JSON.stringify(editor(config));
    expect(text({ websocket_inspection: "true", audit_only: "true" })).toContain("recorded and forwarded");
    expect(text({ websocket_inspection: "true" })).not.toContain("recorded and forwarded");
    expect(text({ audit_only: "true" })).not.toContain("is forwarded unread");
  });
});
