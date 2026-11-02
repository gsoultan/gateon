// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, mock, test } from "bun:test";
import { MantineProvider } from "@mantine/core";
import { renderToString } from "react-dom/server";
import type { ReactElement } from "react";
import type { GlobalConfig } from "../../types/gateon";

// renderToString reads a zustand store's initial state, not one set in the
// test, so the signed-in role is supplied through a stand-in store.
let role: string | null = null;
mock.module("../../store/useAuthStore", () => ({
  COOKIE_SESSION: "__cookie__",
  useAuthStore: (select: (s: { user: { role: string } | null }) => unknown) => select({ user: role ? { role } : null }),
}));
mock.module("../../services/client", () => ({ api: {} }));

const { ADMIN_ONLY_REASON } = await import("../../hooks/usePermissions");
const { ArchiveOnRetentionCard, withArchiveOnRetention } = await import("./ArchiveOnRetentionCard");
const { ThreatArchiveSettingsCard } = await import("./ThreatArchiveSettingsCard");
const { TraceArchiveSettingsCard } = await import("../Traces/TraceArchiveSettingsCard");
const { AuditSettingsCard } = await import("./AuditSettingsCard");

const as = (signedIn: string, ui: ReactElement) => {
  role = signedIn;
  return renderToString(<MantineProvider>{ui}</MantineProvider>);
};

// A Mantine Switch renders its input before its label.
const switchTag = (html: string, label: string): string => {
  const at = html.indexOf(`aria-label="${label}"`);
  expect(at).toBeGreaterThan(-1);
  const input = html.lastIndexOf("<input", at);
  return html.slice(input, html.indexOf(">", at));
};

const noop = () => undefined;
const on: GlobalConfig = { log: { archiveOnRetention: true }, audit: { enabled: true, signEntries: false, retentionDays: 30 } };
const off: GlobalConfig = { log: {}, audit: { enabled: true, signEntries: false, retentionDays: 30 } };

describe("archive everything on retention", () => {
  test("the switch writes log.archiveOnRetention and keeps the rest of the config", () => {
    const before: GlobalConfig = { log: { level: "warn", traceArchiveEnabled: false }, profile: "minimal" };
    const after = withArchiveOnRetention(before, true);
    expect(after.log).toEqual({ level: "warn", traceArchiveEnabled: false, archiveOnRetention: true });
    expect(after.profile).toBe("minimal");
    expect(withArchiveOnRetention(after, false).log?.archiveOnRetention).toBe(false);
    expect(withArchiveOnRetention({}, true).log).toEqual({ archiveOnRetention: true });
  });

  test("it shows the stored state, and is off when nothing is stored", () => {
    expect(switchTag(as("admin", <ArchiveOnRetentionCard config={on} onChange={noop} />), "Archive everything on retention")).toContain('data-checked="true"');
    expect(switchTag(as("admin", <ArchiveOnRetentionCard config={{}} onChange={noop} />), "Archive everything on retention")).not.toContain('data-checked="true"');
  });

  test("an administrator edits it; an operator sees it read-only with the reason", () => {
    const admin = as("admin", <ArchiveOnRetentionCard config={off} onChange={noop} />);
    expect(admin).not.toContain(ADMIN_ONLY_REASON);
    expect(switchTag(admin, "Archive everything on retention")).not.toContain('disabled=""');

    const operator = as("operator", <ArchiveOnRetentionCard config={off} onChange={noop} />);
    expect(operator).toContain(ADMIN_ONLY_REASON);
    expect(switchTag(operator, "Archive everything on retention")).toContain('disabled=""');
  });

  test("while it is on, each archive reads on and cannot be switched off on its own card", () => {
    const cards: Array<[string, (c: GlobalConfig) => ReactElement]> = [
      ["Archive traces", (c) => <TraceArchiveSettingsCard config={c} onChange={noop} />],
      ["Archive security threats", (c) => <ThreatArchiveSettingsCard config={c} onChange={noop} />],
      ["Archive on retention", (c) => <AuditSettingsCard config={c} onChange={noop} />],
    ];
    for (const [label, card] of cards) {
      const withAll = as("admin", card(on));
      expect(switchTag(withAll, label)).toContain('data-checked="true"');
      expect(switchTag(withAll, label)).toContain('disabled=""');
      expect(withAll).toContain("Archive everything on retention is on");

      const without = as("admin", card(off));
      expect(switchTag(without, label)).not.toContain('data-checked="true"');
      expect(switchTag(without, label)).not.toContain('disabled=""');
    }
  });
});
