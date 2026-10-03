// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, mock, test } from "bun:test";
import { MantineProvider } from "@mantine/core";
import { renderToString } from "react-dom/server";
import type { ReactElement } from "react";

// renderToString reads a zustand store's initial state, not one set in the
// test, so the signed-in role is supplied through a stand-in store.
let role: string | null = null;
mock.module("../../../store/useAuthStore", () => ({
  COOKIE_SESSION: "__cookie__",
  useAuthStore: (select: (s: { user: { role: string } | null }) => unknown) => select({ user: role ? { role } : null }),
}));
mock.module("../../../services/client", () => ({ api: {} }));

const { ADMIN_ONLY_REASON } = await import("../../../hooks/usePermissions");
const { ManagementApiSection } = await import("../gateway/ManagementApiSection");
const { AuthSection } = await import("../gateway/AuthSection");
const { RedisSection } = await import("../gateway/RedisSection");
const { AuditSettingsCard } = await import("../AuditSettingsCard");

// The gateway refuses an operator's change to these settings (ADR 0040), so an
// operator sees them read-only with the reason, and an administrator edits them.
const as = (signedIn: string, ui: ReactElement) => {
  role = signedIn;
  return renderToString(<MantineProvider>{ui}</MantineProvider>);
};

const reason = ADMIN_ONLY_REASON;

const inputTag = (html: string, label: string): string => {
  const at = html.indexOf(label);
  expect(at).toBeGreaterThan(-1);
  const input = html.indexOf("<input", at);
  return html.slice(input, html.indexOf(">", input));
};

// A Mantine Switch renders its input before its label.
const switchTag = (html: string, label: string): string => {
  const at = html.indexOf(label);
  expect(at).toBeGreaterThan(-1);
  const input = html.lastIndexOf("<input", at);
  return html.slice(input, html.indexOf(">", input));
};

describe("administrator-only global settings", () => {
  const management = () => (
    <ManagementApiSection management={{ bind: "127.0.0.1", allowedIps: ["10.0.0.0/8"] }} onChange={() => undefined} disabled={false} />
  );

  test("an operator sees the management API read-only, with the reason", () => {
    const html = as("operator", management());
    expect(html).toContain(reason);
    expect(inputTag(html, "Bind Address")).toContain("disabled");
    expect(inputTag(html, "Allowed IPs")).toContain("disabled");
  });

  test("an administrator edits it, and is told nothing", () => {
    const html = as("admin", management());
    expect(html).not.toContain(reason);
    expect(inputTag(html, "Bind Address")).not.toContain("disabled");
  });

  test("authentication and audit are read-only for an operator", () => {
    const auth = as("operator", <AuthSection auth={{ enabled: true }} onChange={() => undefined} disabled={false} />);
    expect(auth).toContain(reason);
    expect(switchTag(auth, "Enable Role-Based Access Control")).toContain("disabled");

    const audit = as("operator", <AuditSettingsCard config={{ audit: { enabled: true, signEntries: false } }} onChange={() => undefined} />);
    expect(audit).toContain(reason);
    expect(inputTag(audit, "Forensic Audit Logging")).toContain("disabled");
  });

  test("an operator may switch Redis on or off but not choose the server", () => {
    const html = as("operator", <RedisSection redis={{ enabled: true, addr: "redis:6379" }} onChange={() => undefined} disabled={false} />);
    expect(html).toContain(reason);
    expect(switchTag(html, "Enable Redis")).not.toContain("disabled");
    expect(inputTag(html, "Address")).toContain("disabled");
  });
});
