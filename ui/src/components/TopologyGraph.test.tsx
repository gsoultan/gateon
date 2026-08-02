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
          <TopologyGraph entryPoints={[]} routes={[]} middlewares={[]} services={[]} />
        </MantineProvider>,
      ),
    ).not.toThrow();
  });

  test("renders a populated topology with a service shared by two routes", () => {
    // Two routes pointing at the same service must not produce duplicate node
    // ids for the service or its backend targets (regression guard).
    const entryPoints: EntryPoint[] = [
      { id: "web", name: "web", address: ":443", type: EntryPointType.HTTP },
    ];
    const services: Service[] = [
      {
        id: "svc-1",
        name: "api",
        weightedTargets: [
          { url: "http://10.0.0.1:8080", weight: 1 },
          { url: "http://10.0.0.2:8080", weight: 1 },
        ],
        loadBalancerPolicy: "round_robin",
        healthCheckPath: "/healthz",
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
        entryPoints: ["web"],
        rule: "Host(`a.example.com`)",
        priority: 1,
        middlewares: ["mw-auth"],
        serviceId: "svc-1",
      },
      {
        id: "r2",
        name: "route-b",
        type: "http",
        entryPoints: ["web"],
        rule: "Host(`b.example.com`)",
        priority: 1,
        middlewares: [],
        serviceId: "svc-1",
      },
    ];

    expect(() =>
      renderToString(
        <MantineProvider>
          <TopologyGraph
            entryPoints={entryPoints}
            routes={routes}
            middlewares={middlewares}
            services={services}
          />
        </MantineProvider>,
      ),
    ).not.toThrow();
  });
});
