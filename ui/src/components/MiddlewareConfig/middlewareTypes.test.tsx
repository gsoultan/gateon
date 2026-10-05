// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, mock, test } from "bun:test";
import { MantineProvider } from "@mantine/core";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToString } from "react-dom/server";

// The security editors import the API client, which reads window.location at
// import; there is no window under bun:test.
mock.module("../../services/client", () => ({ api: {} }));

const { MIDDLEWARE_TYPES } = await import("./middlewareTypes");
const { MiddlewareConfigEditor } = await import("./MiddlewareConfigEditor");
const { middlewareConfigProblem } = await import("./middlewareConfigProblems");

const render = (type: string) =>
  renderToString(
    <QueryClientProvider client={new QueryClient()}>
      <MantineProvider>
        <MiddlewareConfigEditor type={type} config={{}} onChange={() => {}} />
      </MantineProvider>
    </QueryClientProvider>,
  );

// Truth T36 / NEW-8: the type picker could not create bot_management,
// file_security, honeypot, oidc, xfcc, tls_binding, security_headers, policy,
// pow or tarpit -- while the dashboard, the advisory and the posture pointed
// operators at them, so the only way to follow the advice was the API.
// scripts/checkconfig holds this list to every type the factory builds.
describe("the middleware type picker", () => {
  const offered = MIDDLEWARE_TYPES.map((t) => t.value);

  test.each([
    "bot_management", "file_security", "honeypot", "oidc", "xfcc",
    "tls_binding", "security_headers", "policy", "pow", "tarpit",
  ])("offers %s", (type) => {
    expect(offered).toContain(type);
  });

  test("offers each type once", () => {
    expect(new Set(offered).size).toBe(offered.length);
  });

  test.each(MIDDLEWARE_TYPES.map((t) => t.value))("%s has an editor", (type) => {
    expect(render(type)).not.toContain("Unknown middleware type");
  });
});

// A tarpit saved without a threshold delays every client: the factory reads
// it as 0, which a clean client's threat score of 0 meets.
describe("a tarpit config", () => {
  test("cannot be saved without a threshold above 0 and a maximum delay", () => {
    expect(middlewareConfigProblem("tarpit", {})).toContain("threshold above 0");
    expect(middlewareConfigProblem("tarpit", { threshold: "0", max_delay: "5s" })).toContain("threshold above 0");
    expect(middlewareConfigProblem("tarpit", { threshold: "50" })).toContain("maximum delay");
    expect(middlewareConfigProblem("tarpit", { threshold: "50", max_delay: "5s" })).toBeUndefined();
  });
});

// Review-3 F5: the Body Entropy editor showed 7.5 while the gateway read an
// empty threshold as 0, so every request body was recorded as a threat. Empty
// now means 7.5 in the gateway, the editor says so, and a threshold no body
// can be usefully measured against is refused, as the gateway refuses it.
describe("a body entropy config", () => {
  test("refuses a threshold at or below 0 or above 8", () => {
    for (const threshold of ["0", "-1", "8.5", "Infinity"]) {
      expect(middlewareConfigProblem("entropy", { threshold })).toContain("above 0 and at most 8");
    }
  });

  test("saves empty, which is 7.5, and any value in range", () => {
    for (const threshold of ["", "7.5", "8", "0.5"]) {
      expect(middlewareConfigProblem("entropy", { threshold })).toBeUndefined();
    }
    expect(middlewareConfigProblem("entropy", {})).toBeUndefined();
  });

  test("the editor says what empty means", () => {
    expect(render("entropy")).toContain("Empty: 7.5.");
  });
});
