import React from "react";
import { describe, expect, test } from "bun:test";
import { MantineProvider } from "@mantine/core";
import { renderToString } from "react-dom/server";

import { TopologyGraph } from "./TopologyGraph";

describe("TopologyGraph", () => {
  test("renders without crashing for empty topology data", () => {
    expect(() =>
      renderToString(
        <MantineProvider>
          <TopologyGraph entrypoints={[]} routes={[]} middlewares={[]} services={[]} />,
        </MantineProvider>,
      ),
    ).not.toThrow();
  });
});