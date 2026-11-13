// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, mock, test } from "bun:test";
import { MantineProvider } from "@mantine/core";
import { renderToString } from "react-dom/server";

// renderToString reads a zustand store's initial state, not one set in the
// test, so the signed-in role is supplied through a stand-in store.
let role = "admin";
let disabledByEnv = false;
mock.module("../../../store/useAuthStore", () => ({
  COOKIE_SESSION: "__cookie__",
  useAuthStore: (select: (s: { user: { role: string } }) => unknown) => select({ user: { role } }),
}));
mock.module("../../../services/client", () => ({ api: {} }));
mock.module("../../../hooks/useUpdateStatus", () => ({
  useUpdateStatus: () => ({ data: { disabledByEnv } }),
  // The whole module is replaced for every test file in the run, so the
  // stand-in carries each hook another file's component imports.
  useCheckForUpdate: () => ({}),
  useInstallUpdate: () => ({}),
}));

const { ADMIN_ONLY_REASON } = await import("../../../hooks/usePermissions");
const { UpdateSettingsCard, DEFAULT_RELEASE_SOURCE } = await import("./UpdateSettingsCard");

const render = (signedIn: string, update: { checkDisabled?: boolean; sourceUrl?: string }, pinnedOff = false) => {
  role = signedIn;
  disabledByEnv = pinnedOff;
  return renderToString(
    <MantineProvider>
      <UpdateSettingsCard config={{ update }} onChange={() => undefined} />
    </MantineProvider>,
  );
};

const ON = 'data-checked="true"';
const OFF = 'data-checked="false"';

// A Mantine Switch renders its input before its label.
const switchTag = (html: string): string => {
  const at = html.indexOf('aria-label="Check for new versions every day"');
  expect(at).toBeGreaterThan(-1);
  const input = html.lastIndexOf("<input", at);
  return html.slice(input, html.indexOf(">", input));
};

const sourceTag = (html: string): string => {
  const at = html.indexOf("Release source");
  const input = html.indexOf("<input", at);
  return html.slice(input, html.indexOf(">", input));
};

describe("the update check settings", () => {
  test("the check is on until it is switched off", () => {
    expect(switchTag(render("admin", {}))).toContain(ON);
    expect(switchTag(render("admin", { checkDisabled: true }))).toContain(OFF);
  });

  test("an administrator edits both settings", () => {
    const html = render("admin", { sourceUrl: "https://mirror.example.com/releases" });
    expect(html).not.toContain(ADMIN_ONLY_REASON);
    expect(switchTag(html)).not.toContain("disabled");
    expect(sourceTag(html)).not.toContain("disabled");
    expect(sourceTag(html)).toContain("https://mirror.example.com/releases");
  });

  // The gateway refuses an operator's change to the update section (ADR 0040,
  // ADR 0085), so the dashboard does not offer one that would fail on save.
  test("an operator sees them read-only, with the reason", () => {
    const html = render("operator", {});
    expect(html).toContain(ADMIN_ONLY_REASON);
    expect(switchTag(html)).toContain("disabled");
    expect(sourceTag(html)).toContain("disabled");
  });

  test("a check switched off by the environment shows off, cannot be switched, and says why", () => {
    const html = render("admin", {}, true);
    expect(switchTag(html)).toContain(OFF);
    expect(switchTag(html)).toContain("disabled");
    expect(html).toContain("GATEON_UPDATE_CHECK turns the check off on this host");
    // The source still applies once the variable is removed, so it stays editable.
    expect(sourceTag(html)).not.toContain("disabled");
  });

  test("an empty source shows where the gateway asks by default", () => {
    expect(sourceTag(render("admin", {}))).toContain(DEFAULT_RELEASE_SOURCE);
  });
});
