// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { afterAll, beforeEach, describe, expect, mock, test } from "bun:test";

// The gateway refuses a management write whose body is text/plain, form or
// multipart outside the upload endpoints (ADR 0041): those are the types a page
// on another site can send without a CORS preflight. fetch labels a string body
// text/plain unless told otherwise, and several callers of apiFetch send a
// JSON string without saying so, so apiFetch has to say it for them.

mock.module("../services/client", () => ({ api: {} }));
mock.module("../store/useAuthStore", () => ({
  useAuthStore: { getState: () => ({ token: "__cookie__", logout: () => {} }) },
}));

let sent: Headers | null = null;
const realFetch = globalThis.fetch;
globalThis.fetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
  sent = new Headers(init?.headers);
  return new Response("{}", { status: 200 });
}) as typeof fetch;
afterAll(() => {
  globalThis.fetch = realFetch;
});

const { apiFetch } = await import("./api");

beforeEach(() => {
  sent = null;
});

describe("apiFetch content type", () => {
  test("a JSON string body is sent as application/json", async () => {
    await apiFetch("/v1/waf/rules", { method: "POST", body: JSON.stringify({ id: "r" }) });
    expect(sent?.get("Content-Type")).toBe("application/json");
  });

  test("a caller's own Content-Type is kept, whatever its casing", async () => {
    await apiFetch("/v1/x", { method: "POST", body: "a", headers: { "content-type": "application/proto" } });
    expect(sent?.get("Content-Type")).toBe("application/proto");
  });

  test("a FormData upload keeps the multipart type fetch gives it", async () => {
    const form = new FormData();
    form.append("file", new Blob(["x"]), "x.pem");
    await apiFetch("/v1/certs/upload", { method: "POST", body: form });
    expect(sent?.get("Content-Type")).toBeNull();
  });

  test("a request without a body is given no type", async () => {
    await apiFetch("/v1/security/clamav/scan", { method: "POST" });
    expect(sent?.get("Content-Type")).toBeNull();
  });
});
