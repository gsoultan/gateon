// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, mock, test } from "bun:test";
import { MantineProvider } from "@mantine/core";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToString } from "react-dom/server";

// The card reaches hooks/api, which builds the Connect client from
// window.location at import; there is no window under bun:test.
mock.module("../../../services/client", () => ({ api: {} }));
// Other test files replace the auth store module; supply one here so this
// file renders the same alone and in the full suite.
mock.module("../../../store/useAuthStore", () => ({
  COOKIE_SESSION: "__cookie__",
  useAuthStore: (select: (s: { user: { role: string } | null }) => unknown) => select({ user: { role: "admin" } }),
}));

const { WafSettingsCard } = await import("./WafSettingsCard");

const render = () =>
  renderToString(
    <QueryClientProvider client={new QueryClient()}>
      <MantineProvider>
        <WafSettingsCard
          waf={{ enabled: true, paranoiaLevel: 1, categories: { sqli: false } }}
          onChange={() => {}}
          disabled={false}
          canEdit
          saving={false}
          onSave={() => {}}
          status={undefined}
          installing={false}
          uninstalling={false}
          onInstall={() => {}}
          onUninstall={() => {}}
        />
      </MantineProvider>
    </QueryClientProvider>,
  );

// Truth NEW-13: "Update WAF Rules Now" was offered and always failed -- rule
// downloads are retired; the rules are built in, and custom rules load from
// disk. A control that can only fail is not offered.
describe("the global WAF card", () => {
  test("does not offer the retired rule update", () => {
    const html = render();
    expect(html).toContain("Global WAF Settings");
    expect(html).not.toContain("Update WAF Rules Now");
  });

  // ADR 0064: the families are switches now, and one switched off is named.
  test("offers the attack-family switches and names the ones switched off", () => {
    const html = render();
    expect(html).toContain("Cross-Site Scripting");
    expect(html).toContain("Switched off gateway-wide");
    expect(html).toContain("requests carrying these attacks reach the backends");
  });
});
