// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { MantineProvider } from "@mantine/core";
import { renderToString } from "react-dom/server";
import { SettingsSaveBar } from "./SettingsSaveBar";

const noop = () => undefined;
const render = (props: Partial<Parameters<typeof SettingsSaveBar>[0]>) =>
  renderToString(
    <MantineProvider>
      <SettingsSaveBar
        hasChanges={false}
        saving={false}
        canSave
        error={null}
        savedOk={false}
        onSave={noop}
        onDiscard={noop}
        {...props}
      />
    </MantineProvider>,
  );

describe("the Settings save bar", () => {
  test("does not claim unsaved changes when nothing has been edited", () => {
    // It used to claim unsaved changes the moment the page opened.
    const html = render({}).toLowerCase();
    expect(html).not.toContain(">unsaved changes<");
    expect(html).not.toContain("you have modified");
    expect(html).not.toContain("discard");
    expect(html).toContain("no unsaved changes");
  });

  test("still lets the stored configuration be saved, and not before it has loaded", () => {
    expect(render({})).toContain("Save Global Configuration");
    expect(render({ canSave: false })).toMatch(/<button[^>]*disabled[^>]*>(?:(?!<\/button>).)*Save Global Configuration/s);
  });

  test("offers save and discard once something has been edited", () => {
    const html = render({ hasChanges: true });
    expect(html).toContain("Unsaved changes");
    expect(html).toContain("Save Global Configuration");
    expect(html).toContain("Discard");
  });

  test("confirms a save without offering to discard", () => {
    const html = render({ savedOk: true });
    expect(html).toContain("All changes saved");
    expect(html).not.toContain("Discard");
  });

  test("reports a refused save", () => {
    const html = render({ hasChanges: true, error: "TLS needs a certificate" });
    expect(html).toContain("TLS needs a certificate");
  });
});
