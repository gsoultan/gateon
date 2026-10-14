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
  test("is not shown when nothing has been edited", () => {
    // It used to claim unsaved changes the moment the page opened.
    const html = render({});
    expect(html).not.toContain('role="region"');
  });

  test("offers save and discard once something has been edited", () => {
    const html = render({ hasChanges: true });
    expect(html).toContain("Unsaved changes");
    expect(html).toContain("Save changes");
    expect(html).toContain("Discard");
  });

  test("confirms a save without offering to save again", () => {
    const html = render({ savedOk: true });
    expect(html).toContain("All changes saved");
    expect(html).not.toContain("Save changes");
  });

  test("reports a refused save", () => {
    const html = render({ hasChanges: true, error: "TLS needs a certificate" });
    expect(html).toContain("TLS needs a certificate");
  });
});
