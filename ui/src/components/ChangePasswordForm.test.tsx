// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, mock, test } from "bun:test";
import { MantineProvider } from "@mantine/core";
import { renderToString } from "react-dom/server";

// The form's module reaches hooks/api, which builds the Connect client from
// window.location at import; there is no window under bun:test.
mock.module("../services/client", () => ({ api: {} }));

const { ChangePasswordForm } = await import("./ChangePasswordForm");

const render = (own: boolean) =>
  renderToString(
    <MantineProvider>
      <ChangePasswordForm userId="user-1" own={own} onChanged={() => undefined} />
    </MantineProvider>,
  );

describe("ChangePasswordForm", () => {
  test("asks for your current password when the password is your own", () => {
    const html = render(true);

    expect(html).toContain("Current password");
    expect(html.toLowerCase()).toContain('autocomplete="current-password"');
    expect(html).toContain("New password");
  });

  test("asks for none when an administrator resets another account", () => {
    const html = render(false);

    expect(html).not.toContain("Current password");
    expect(html).toContain("New password");
  });
});
