// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, mock, test } from "bun:test";
import { MantineProvider } from "@mantine/core";
import { renderToString } from "react-dom/server";

// The step is presentational. The module it lives in reaches hooks/api, which
// builds the Connect client from window.location at import; there is no
// window under bun:test.
mock.module("../services/client", () => ({ api: {} }));

const { TwoFactorPasswordStep } = await import("./TwoFactorModal");

const render = (props: { password?: string; error?: string | null; loading?: boolean } = {}) =>
  renderToString(
    <MantineProvider>
      <TwoFactorPasswordStep
        password={props.password ?? ""}
        onPasswordChange={() => undefined}
        onSubmit={() => undefined}
        loading={props.loading ?? false}
        error={props.error ?? null}
      />
    </MantineProvider>,
  );

describe("TwoFactorPasswordStep", () => {
  test("asks for the current password before anything else", () => {
    const html = render();

    expect(html).toContain('type="password"');
    // So a password manager fills it, and fills the right one.
    expect(html.toLowerCase()).toContain('autocomplete="current-password"');
    expect(html).toContain("Current password");
  });

  test("cannot be submitted empty", () => {
    const html = render({ password: "" });

    // Mantine renders a disabled button with the disabled attribute.
    expect(html).toMatch(/<button[^>]*type="submit"[^>]*disabled=""/);
  });

  test("shows a refusal as an alert", () => {
    const html = render({ password: "x", error: "That password is not correct." });

    expect(html).toContain('role="alert"');
    expect(html).toContain("That password is not correct.");
  });
});
