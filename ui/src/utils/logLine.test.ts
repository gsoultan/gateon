// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { clientMatches, logFields, parseLogfmt, routeOf, statusMatches } from "./logLine";

// A line exactly as the gateway's text handler writes one (standard.go's
// access log), trailing newline included.
const ACCESS =
  'time=2026-09-27T14:16:30+07:00 level=INFO msg="access log" host=localhost:8081 method=GET ' +
  'path="/ratelimit/<img src=x onerror=alert(1)>" remote_addr=127.0.0.1:54201 client=198.51.100.201 ' +
  'status=403 latency=2.976791ms route="Rate Limit Route"\n';

describe("parseLogfmt", () => {
  test("reads bare and quoted values", () => {
    const f = parseLogfmt(ACCESS);
    expect(f?.msg).toBe("access log");
    expect(f?.path).toBe("/ratelimit/<img src=x onerror=alert(1)>");
    expect(f?.status).toBe("403");
    expect(f?.client).toBe("198.51.100.201");
    expect(f?.route).toBe("Rate Limit Route");
  });

  test("unescapes what Go's quoting escapes", () => {
    const f = parseLogfmt(String.raw`msg="said \"hi\"\n" dir="C:\\x"`);
    expect(f?.msg).toBe('said "hi"\n');
    expect(f?.dir).toBe("C:\\x");
  });

  test("is null for a line that is not key=value pairs", () => {
    expect(parseLogfmt("panic: runtime error: invalid memory address")).toBeNull();
    expect(parseLogfmt('msg="never closed')).toBeNull();
    expect(parseLogfmt("")).toBeNull();
  });
});

describe("filters over a text-format line", () => {
  const f = logFields(ACCESS, null)!;

  test("status matches the code, a prefix and a class", () => {
    expect(statusMatches(f, "403")).toBe(true);
    expect(statusMatches(f, "4")).toBe(true);
    expect(statusMatches(f, "4xx")).toBe(true);
    expect(statusMatches(f, "4XX")).toBe(true);
    expect(statusMatches(f, "5xx")).toBe(false);
    expect(statusMatches(f, "200")).toBe(false);
  });

  test("client matches the resolved client and the TCP peer", () => {
    expect(clientMatches(f, "198.51.100.201")).toBe(true);
    expect(clientMatches(f, "127.0.0.1")).toBe(true);
    expect(clientMatches(f, "203.0.113.9")).toBe(false);
  });

  test("route is the route field", () => {
    expect(routeOf(f)).toBe("Rate Limit Route");
  });
});

describe("filters over a JSON line", () => {
  const json = { level: "INFO", msg: "access log", status: 503, client: "203.0.113.4", route: "Test Route" };
  const f = logFields(JSON.stringify(json), json)!;

  test("a numeric status is matched as its digits", () => {
    expect(statusMatches(f, "5xx")).toBe(true);
    expect(statusMatches(f, "503")).toBe(true);
    expect(statusMatches(f, "2xx")).toBe(false);
  });

  test("client and route read the names the access log writes", () => {
    expect(clientMatches(f, "203.0.113.4")).toBe(true);
    expect(routeOf(f)).toBe("Test Route");
  });
});
