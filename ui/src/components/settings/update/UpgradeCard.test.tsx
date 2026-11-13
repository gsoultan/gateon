// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, mock, test } from "bun:test";
import { MantineProvider } from "@mantine/core";
import { renderToString } from "react-dom/server";
import { UpdateSignature, UpgradeBlocker, UpgradePhase, UpgradeReason } from "../../../services/gen/gateon/v1/status_pb";

// renderToString reads a zustand store's initial state, not one set in the
// test, so the signed-in role and the gateway's answer are stand-ins.
let role = "admin";
let query: Record<string, unknown> = {};
mock.module("../../../store/useAuthStore", () => ({
  COOKIE_SESSION: "__cookie__",
  useAuthStore: (select: (s: { user: { role: string } }) => unknown) => select({ user: { role } }),
}));
mock.module("../../../services/client", () => ({ api: {} }));
mock.module("../../../hooks/useUpdateStatus", () => ({
  useUpdateStatus: () => query,
  useCheckForUpdate: () => ({}),
  useInstallUpdate: () => ({ mutate: () => undefined, reset: () => undefined, isPending: false, isError: false }),
}));

const { UpgradeCard } = await import("./UpgradeCard");
const { AutoInstallCard } = await import("./AutoInstallCard");

const record = (over: Record<string, unknown>) => ({
  phase: UpgradePhase.UNSPECIFIED,
  reason: UpgradeReason.UNSPECIFIED,
  targetVersion: "1.8.3",
  previousVersion: "1.8.2",
  startedAt: 1_800_000_000n,
  finishedAt: 1_800_000_060n,
  requestedBy: "ada",
  automatic: false,
  databaseRestored: false,
  ...over,
});

const status = (upgrade: Record<string, unknown>, over: Record<string, unknown> = {}) => ({
  currentVersion: "1.8.2",
  latestVersion: "1.8.3",
  updateAvailable: true,
  signature: UpdateSignature.VERIFIED,
  upgrade: { blocker: UpgradeBlocker.UNSPECIFIED, history: [], windowStart: "02:00", windowEnd: "04:00", ...upgrade },
  ...over,
});

const card = (signedIn: string, data: unknown, rest: Record<string, unknown> = {}) => {
  role = signedIn;
  query = { data, isPending: false, isError: false, refetch: () => undefined, ...rest };
  return renderToString(
    <MantineProvider>
      <UpgradeCard />
    </MantineProvider>,
  );
};

// The opening tag of the button whose text is label.
const button = (html: string, label: string): string => {
  const at = html.indexOf(label);
  expect(at).toBeGreaterThan(-1);
  return html.slice(html.lastIndexOf("<button", at), at);
};

describe("the Install card", () => {
  test("offers an administrator the exact version", () => {
    const html = card("admin", status({}));
    expect(button(html, "Upgrade to v<!-- -->1.8.3")).not.toContain("disabled");
    expect(html).toContain("You will be asked to confirm.");
  });

  test("shows an operator the button they may not press, and says who may", () => {
    const html = card("operator", status({}));
    expect(button(html, "Upgrade to v<!-- -->1.8.3")).toContain("disabled");
    expect(html).toContain("Only an administrator can install an upgrade.");
  });

  test("offers nothing when the release could not be verified", () => {
    const html = card("admin", status({}, { signature: UpdateSignature.NO_KEY }));
    expect(html).not.toContain("<button");
    expect(html).toContain("could not be verified, so it is not offered for install");
  });

  test("offers nothing when there is nothing newer", () => {
    const html = card("admin", status({}, { updateAvailable: false }));
    expect(html).not.toContain("Upgrade to v");
    expect(html).toContain("There is nothing to install");
  });

  test("gives the command that enables the helper instead of a button that cannot work", () => {
    const html = card("admin", status({ blocker: UpgradeBlocker.NO_HELPER }));
    expect(html).not.toContain("Upgrade to v");
    expect(html).toContain("sudo systemctl enable --now gateon-upgrade.path");
  });

  test("shows the steps and no button while an install runs", () => {
    const html = card("admin", status({ current: record({ phase: UpgradePhase.RESTARTING, finishedAt: 0n }) }));
    expect(html).toContain('data-testid="upgrade-progress"');
    expect(html).toContain("The gateway is restarting on v1.8.3.");
    expect(html).not.toContain("Upgrade to v");
    expect(html).not.toContain('data-testid="upgrade-outcome"');
  });

  test("keeps the progress on screen while the restarting gateway does not answer", () => {
    const data = status({ current: record({ phase: UpgradePhase.RESTARTING, finishedAt: 0n }) });
    const html = card("admin", data, { isError: true });
    expect(html).toContain("is not answering yet. This page keeps trying.");
    expect(html).not.toContain("could not be loaded");
  });

  test("says how the last install ended, and offers the next one", () => {
    const html = card("admin", status({ current: record({ phase: UpgradePhase.ROLLED_BACK, reason: UpgradeReason.NOT_READY }) }));
    expect(html).toContain('data-testid="upgrade-outcome"');
    expect(html).toContain("v1.8.3 was rolled back");
    expect(html).toContain("Upgrade to v");
  });

  test("has an empty state for the history, and rows when there are any", () => {
    expect(card("admin", status({}))).toContain("No release has been installed from this gateway yet.");
    const html = card("admin", status({ history: [record({ phase: UpgradePhase.SUCCEEDED }), record({ phase: UpgradePhase.REFUSED, automatic: true, requestedBy: "" })] }));
    expect(html).toContain("Installed");
    expect(html).toContain("Not installed");
    expect(html).toContain("Automatic");
  });

  test("renders the name of who asked as text, whatever it holds", () => {
    const html = card("admin", status({ history: [record({ phase: UpgradePhase.SUCCEEDED, requestedBy: '<img src=x onerror="alert(1)">' })] }));
    expect(html).not.toContain("<img");
    expect(html).toContain("&lt;img");
  });

  test("has a loading state and an error state with a retry", () => {
    expect(card("admin", undefined, { isPending: true })).toContain("mantine-Skeleton-root");
    const html = card("admin", undefined, { isError: true });
    expect(html).toContain("The upgrade status could not be loaded");
    expect(html).toContain("Retry");
  });
});

describe("the Automatic install card", () => {
  const auto = (signedIn: string, update: Record<string, unknown>, upgrade: Record<string, unknown> = {}) => {
    role = signedIn;
    query = { data: status(upgrade) };
    return renderToString(
      <MantineProvider>
        <AutoInstallCard config={{ update }} onChange={() => undefined} />
      </MantineProvider>,
    );
  };
  const switchTag = (html: string): string => {
    const at = html.indexOf('aria-label="Install new versions automatically"');
    expect(at).toBeGreaterThan(-1);
    const input = html.lastIndexOf("<input", at);
    return html.slice(input, html.indexOf(">", input));
  };
  const ON = 'data-checked="true"';
  const OFF = 'data-checked="false"';

  test("is off until switched on", () => {
    expect(switchTag(auto("admin", {}))).toContain(OFF);
    expect(switchTag(auto("admin", { autoInstall: true }))).toContain(ON);
  });

  test("shows what the environment decided and does not let the switch pretend otherwise", () => {
    const html = auto("admin", { autoInstall: true }, { autoInstall: false, autoInstallByEnv: true });
    expect(switchTag(html)).toContain(OFF);
    expect(switchTag(html)).toContain("disabled");
    expect(html).toContain("GATEON_UPDATE_AUTO_INSTALL turns this off on this host.");
  });

  test("is an administrator's to change", () => {
    expect(switchTag(auto("operator", {}))).toContain("disabled");
    expect(switchTag(auto("admin", {}))).not.toContain("disabled");
  });

  test("says so when this gateway cannot install at all", () => {
    expect(auto("admin", {}, { blocker: UpgradeBlocker.ORCHESTRATED })).toContain("so this setting has no effect here");
  });

  test("names what is wrong with half a window", () => {
    expect(auto("admin", { autoInstallWindowStart: "02:00" })).toContain("Give both a start and an end, or leave both empty.");
  });

  test("shows the window in force", () => {
    expect(auto("admin", {}, { windowStart: "22:00", windowEnd: "23:30" })).toContain("22:00 to 23:30");
  });
});
