// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, mock, test } from "bun:test";
import { MantineProvider } from "@mantine/core";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToString } from "react-dom/server";

// The form reaches hooks/api, which builds the Connect client from
// window.location at import; there is no window under bun:test.
mock.module("../services/client", () => ({ api: {} }));

const { EntryPointForm, maxConnectionsDescription } = await import("./EntryPointForm");

const render = () =>
  renderToString(
    <MantineProvider>
      <QueryClientProvider client={new QueryClient()}>
        <EntryPointForm />
      </QueryClientProvider>
    </MantineProvider>,
  );

// max_connections was kept in the form's state and sent on every save, but no
// input showed it: an operator could neither see nor set the limit, which the
// gateway now applies to every entrypoint (ADR 0032).
describe("EntryPointForm max connections", () => {
  test("is an input on the form, which says what 0 means and what that is", () => {
    const html = render();

    expect(html).toContain("Max Connections");
    expect(html).toContain("0 uses the resource profile");
    expect(html).toContain("1,000 on the minimal profile, 10,000 on standard, 50,000 on enterprise");
  });

  test("says that idle keep-alive connections count, and a multiplexed connection once", () => {
    const text = maxConnectionsDescription(false);

    expect(text).toContain("Idle keep-alive connections count");
    expect(text).toContain("counts once however many requests it carries");
  });

  test("tells a raw UDP entrypoint it has no connections to limit, rather than offering a limit nothing reads", () => {
    const text = maxConnectionsDescription(true);

    expect(text).toContain("has no connections to limit");
    expect(text).not.toContain("resource profile");
  });
});
