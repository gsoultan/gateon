// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test, mock } from "bun:test";
import { isValidElement, type ReactElement, type ReactNode } from "react";

// The component imports the API client, which reads window.location on import.
mock.module("../../services/client", () => ({ api: {} }));

const { LearnedDraftList, draftSummary } =
  await import("./LearnedSchemaDrafts");
const { SchemaLearningFields, showsModeSelect } =
  await import("./OpenApiSpecFields");
import type { LearnedDraft } from "./LearnedSchemaDrafts";

type Props = Record<string, unknown>;

function buttons(
  node: ReactNode,
  out: ReactElement<Props>[] = [],
): ReactElement<Props>[] {
  if (Array.isArray(node)) {
    node.forEach((child) => buttons(child, out));
    return out;
  }
  if (!isValidElement<Props>(node)) return out;
  if (typeof node.props.onClick === "function") out.push(node);
  buttons(node.props.children as ReactNode, out);
  return out;
}

const text = (node: ReactNode) => JSON.stringify(node);

const drafted: LearnedDraft = {
  route: "orders",
  observed: 412,
  operations: 3,
  droppedOperations: 0,
  droppedParameters: 0,
  minSamples: 20,
  document: '{"openapi":"3.0.3"}',
};
const quiet: LearnedDraft = {
  ...drafted,
  route: "quiet",
  observed: 4,
  operations: 0,
  document: "",
};

const list = (over: Partial<Parameters<typeof LearnedDraftList>[0]>) =>
  LearnedDraftList({
    drafts: [drafted, quiet],
    routesRejected: 0,
    maxRoutes: 64,
    hasDocument: false,
    enforcing: false,
    onUse: () => {},
    ...over,
  });

// What the gateway learned is shown as it is (schemalearn.Draft), and a draft
// is only ever put in the form by the operator, never over a document they
// already have and never into a form set to refuse.
describe("learned schema drafts", () => {
  test("a route says how much it has seen, and a quiet one says why it has no draft", () => {
    expect(draftSummary(drafted)).toBe(
      "3 operations drafted from 412 requests.",
    );
    expect(draftSummary(quiet)).toContain("Nothing has been seen 20 times yet");
    expect(
      draftSummary({ ...drafted, droppedOperations: 2, droppedParameters: 5 }),
    ).toContain("2 requests and 5 parameters were left out");
  });

  test("only a route with a draft offers one, and using it hands over that route's document", () => {
    const used: string[] = [];
    const offered = buttons(list({ onUse: (doc) => used.push(doc) }));
    expect(offered).toHaveLength(1);
    (offered[0].props.onClick as () => void)();
    expect(used).toEqual(['{"openapi":"3.0.3"}']);
  });

  test("a draft is not offered over a document the form already has", () => {
    const view = list({ hasDocument: true });
    expect(buttons(view)[0].props.disabled).toBe(true);
    expect(text(view)).toContain("Remove it first");
  });

  test("a draft is not offered into a form set to refuse", () => {
    const view = list({ enforcing: true });
    expect(buttons(view)[0].props.disabled).toBe(true);
    expect(text(view)).toContain("Set that to Recorded first");
  });

  test("no learning route is an empty state that says what to do", () => {
    expect(text(list({ drafts: [] }))).toContain("No route is learning yet");
  });

  test("routes turned away by the limit are named as a count against the limit", () => {
    expect(text(list({ routesRejected: 3 }))).toContain(
      "3 routes are not being learned: at most 64 routes learn at once.",
    );
  });
});

describe("route WAF editor, schema learning", () => {
  const find = (node: ReactNode, label: string): ReactElement<Props> | null => {
    if (Array.isArray(node))
      return node.map((n) => find(n, label)).find(Boolean) ?? null;
    if (!isValidElement<Props>(node)) return null;
    if (node.props.label === label) return node;
    return find(node.props.children as ReactNode, label);
  };

  test("the switch says what is kept and that nothing is enforced, and writes the key the gateway reads", () => {
    const written: Record<string, string> = {};
    const view = SchemaLearningFields({
      config: {},
      updateConfig: (key, value) => {
        written[key] = value;
      },
      onUse: () => {},
    });
    const toggle = find(view, "Learn this route's API from traffic");
    const help = String(toggle?.props.description);
    expect(help).toContain("No value is kept");
    expect(help).toContain(
      "enforces nothing until you put it in the document field and save",
    );
    expect(help).toContain("lost on restart");
    expect(toggle?.props.checked).toBe(false);
    (toggle?.props.onChange as (e: unknown) => void)({
      currentTarget: { checked: true },
    });
    expect(written.schema_learning).toBe("true");
  });

  test("the drafts are told whether the form has a document and whether it refuses", () => {
    const drafts = (config: Record<string, string>) => {
      const view = SchemaLearningFields({
        config,
        updateConfig: () => {},
        onUse: () => {},
      });
      const children = (view.props as { children: ReactElement<Props>[] })
        .children;
      return children[1].props;
    };
    expect(drafts({})).toMatchObject({ hasDocument: false, enforcing: false });
    expect(
      drafts({ openapi_spec: "openapi: 3.0.3", openapi_mode: "enforce" }),
    ).toMatchObject({
      hasDocument: true,
      enforcing: true,
    });
  });

  test("a leftover Refused with no document is shown, so it can be changed before a draft is used", () => {
    expect(showsModeSelect("", "enforce")).toBe(true);
    expect(showsModeSelect("", "record")).toBe(false);
    expect(showsModeSelect("openapi: 3.0.3", "record")).toBe(true);
  });
});
