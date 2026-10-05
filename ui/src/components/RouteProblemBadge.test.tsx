// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { MantineProvider } from "@mantine/core";
import { renderToString } from "react-dom/server";
import { RouteProblemBadge } from "./RouteProblemBadge";

const render = (node: React.ReactNode) => renderToString(<MantineProvider>{node}</MantineProvider>);

// OPS-N4: a route an upgrade left answering 503, or matching nothing, looked
// like every other route in the list until a request reached it.
describe("the route list's problem marker", () => {
  test("marks a route that refuses every request, with the reason", () => {
    const html = render(
      <RouteProblemBadge problem={{ routeId: "r", route: "api", kind: "refuses", reason: 'middleware "gone" does not exist' }} />,
    );
    expect(html).toContain("REFUSES REQUESTS");
    expect(html).toContain("middleware &quot;gone&quot; does not exist");
  });

  test("marks a route whose rule matches nothing", () => {
    const html = render(
      <RouteProblemBadge problem={{ routeId: "r", route: "api", kind: "matches_nothing", reason: "rule does not parse: <b>x" }} />,
    );
    expect(html).toContain("MATCHES NOTHING");
    // The reason is text, never markup.
    expect(html).not.toContain("<b>x");
  });

  // A middleware stored with a config the gateway now refuses (a tarpit with
  // no threshold above 0) is built switched off: the route serves, without it.
  // It must not be marked as refusing requests, which it does not.
  test("marks a route serving without a middleware that is off", () => {
    const html = render(
      <RouteProblemBadge
        problem={{ routeId: "r", route: "api", kind: "middleware_off", reason: 'tarpit middleware "slow" is off until fixed' }}
      />,
    );
    expect(html).toContain("MIDDLEWARE OFF");
    expect(html).not.toContain("REFUSES REQUESTS");
  });

  test("shows nothing for a route that serves", () => {
    expect(render(<RouteProblemBadge problem={undefined} />)).not.toContain("REQUESTS");
  });
});
