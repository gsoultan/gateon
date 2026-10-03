// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, mock, test } from "bun:test";
import { isValidElement, type ReactElement, type ReactNode } from "react";

// MiddlewareConfigEditor pulls in the API client, which reads window.location
// on import; there is no window under bun:test.
mock.module("../../services/client", () => ({ api: {} }));
const { CircuitBreakerConfigEditor, InFlightReqConfigEditor } = await import("./TrafficConfigEditors");
const { MiddlewareConfigEditor } = await import("./MiddlewareConfigEditor");

type Props = Record<string, unknown>;
type Element = ReactElement<Props>;

function findElement(node: ReactNode, matches: (el: Element) => boolean): Element | null {
  if (Array.isArray(node)) {
    for (const child of node) {
      const found = findElement(child, matches);
      if (found) return found;
    }
    return null;
  }
  if (!isValidElement<Props>(node)) return null;
  if (matches(node)) return node;
  return findElement(node.props.children as ReactNode, matches);
}

const labelled = (text: string) => (el: Element) => String(el.props.label ?? "").startsWith(text);

describe("in-flight requests editor", () => {
  // The label said "Max Concurrent Requests" and the gateway counted per client
  // address, so an operator protecting a backend got amount x clients.
  test("the cap's label says what it counts", () => {
    const perAddress = InFlightReqConfigEditor({ config: { amount: "5" }, updateConfig: () => {} });
    expect(findElement(perAddress, labelled("Max Concurrent Requests"))?.props.label)
      .toBe("Max Concurrent Requests per Client Address");
    const total = InFlightReqConfigEditor({ config: { amount: "5", per_ip: "false" }, updateConfig: () => {} });
    expect(findElement(total, labelled("Max Concurrent Requests"))?.props.label)
      .toBe("Max Concurrent Requests (total)");
  });

  test("choosing a total writes per_ip=false, the key the gateway reads", () => {
    const written: string[] = [];
    const tree = InFlightReqConfigEditor({ config: {}, updateConfig: (k, v) => { written.push(k, v); } });
    const scope = findElement(tree, labelled("Count Concurrent Requests"));
    (scope!.props.onChange as (v: string) => void)("false");
    expect(written).toEqual(["per_ip", "false"]);
  });

  // An untouched form showed 100 and saved nothing, and the gateway refused the
  // save for a value the form appeared to have.
  test("an unset cap shows no value rather than one it would not save", () => {
    const tree = InFlightReqConfigEditor({ config: {}, updateConfig: () => {} });
    expect(findElement(tree, labelled("Max Concurrent Requests"))?.props.value).toBe("");
  });
});

describe("circuit breaker editor", () => {
  // There was no editor: the type could not be created from the dashboard.
  test("the middleware editor has one for circuit_breaker", () => {
    const tree = MiddlewareConfigEditor({ type: "circuit_breaker", config: {}, onChange: () => {} });
    expect(isValidElement(tree) && tree.type).toBe(CircuitBreakerConfigEditor);
  });

  test("each field writes the key the gateway reads", () => {
    const written: Record<string, string> = {};
    const tree = CircuitBreakerConfigEditor({ config: {}, updateConfig: (k, v) => { written[k] = v; } });
    const set = (label: string, value: unknown) =>
      (findElement(tree, (el) => el.props.label === label)!.props.onChange as (v: unknown) => void)(value);
    set("Error Threshold", 0.25);
    set("Minimum Requests", 10);
    set("Window", { currentTarget: { value: "20s" } });
    set("Sleep Window", { currentTarget: { value: "1m" } });
    expect(written).toEqual({ error_threshold: "0.25", min_requests: "10", window_size: "20s", sleep_window: "1m" });
  });
});
