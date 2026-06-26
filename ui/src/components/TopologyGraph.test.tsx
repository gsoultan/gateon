import { describe, expect, test } from "bun:test";
import { MantineProvider } from "@mantine/core";
import { renderToString } from "react-dom/server";

import { TopologyGraph } from "./TopologyGraph";
import {
  type Route,
  type Service,
  type EntryPoint,
  type Middleware,
  EntryPointType,
} from "../types/gateon";

describe("TopologyGraph", () => {
  test("renders without crashing for empty topology data", () => {
    expect(() =>
      renderToString(
        <MantineProvider>
          <TopologyGraph entrypoints={[]} routes={[]} middlewares={[]} services={[]} />
        </MantineProvider>,
      ),
    ).not.toThrow();
  });

  test("renders a populated topology with a service shared by two routes", () => {
    // Two routes pointing at the same service must not produce duplicate node
    // ids for the service or its backend targets (regression guard).
    const entrypoints: EntryPoint[] = [
      { id: "web", name: "web", address: ":443", type: EntryPointType.HTTP },
    ];
    const services: Service[] = [
      {
        id: "svc-1",
        name: "api",
        weighted_targets: [
          { url: "http://10.0.0.1:8080", weight: 1 },
          { url: "http://10.0.0.2:8080", weight: 1 },
        ],
        load_balancer_policy: "round_robin",
        health_check_path: "/healthz",
      },
    ];
    const middlewares: Middleware[] = [
      { id: "mw-auth", name: "auth", type: "jwt", config: {} },
    ];
    const routes: Route[] = [
      {
        id: "r1",
        name: "route-a",
        type: "http",
        entrypoints: ["web"],
        rule: "Host(`a.example.com`)",
        priority: 1,
        middlewares: ["mw-auth"],
        service_id: "svc-1",
      },
      {
        id: "r2",
        name: "route-b",
        type: "http",
        entrypoints: ["web"],
        rule: "Host(`b.example.com`)",
        priority: 1,
        middlewares: [],
        service_id: "svc-1",
      },
    ];

    expect(() =>
      renderToString(
        <MantineProvider>
          <TopologyGraph
            entrypoints={entrypoints}
            routes={routes}
            middlewares={middlewares}
            services={services}
          />
        </MantineProvider>,
      ),
    ).not.toThrow();
  });
});
