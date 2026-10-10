// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { expect, test } from "bun:test";
import { create, fromJson, toJson, type JsonValue } from "@bufbuild/protobuf";

import { RouteSchema, Route_StreamMode } from "../../services/gen/gateon/v1/route_pb";
import type { Route } from "../../types/gateon";
import { formValuesToRoute, routeToFormValues } from "./routePayload";

// The gateway sends routes as protojson and decodes PUT /v1/routes with
// protojson and DiscardUnknown. These two helpers are those halves, taken from
// the generated schema, so a field the form spells differently from the proto
// vanishes here exactly as it does on the wire: silently.
// enumAsInteger: the gateway marshals with UseEnumNumbers (handlers/response.go).
const fromGateway = (msg: ReturnType<typeof stored>): Route =>
  toJson(RouteSchema, msg, { alwaysEmitImplicit: true, enumAsInteger: true }) as unknown as Route;
const onTheWire = (route: Route): JsonValue => JSON.parse(JSON.stringify(route));

const stored = () =>
  create(RouteSchema, {
    id: "internal-admin",
    name: "internal-admin",
    type: "http",
    rule: "PathPrefix(`/admin`)",
    entrypoints: ["internal"],
    serviceId: "svc-1",
  });

// A route restricted to one entrypoint, opened in the dashboard's edit form and
// saved unchanged. The form called the field entryPoints; the proto field is
// entrypoints. The form therefore loaded the restriction as empty and saved a
// key the gateway discards, and an empty list means "every entrypoint": an
// admin path meant for an internal listener was republished on all of them.
test("editing and saving a route keeps its entrypoint restriction", () => {
  const values = routeToFormValues(fromGateway(stored()));
  const saved = fromJson(RouteSchema, onTheWire(formValuesToRoute(values)), { ignoreUnknownFields: true });

  expect(saved.entrypoints).toEqual(["internal"]);
});

test("the route the form saves has no field the gateway would discard", () => {
  const body = onTheWire(formValuesToRoute(routeToFormValues(fromGateway(stored()))));

  expect(() => fromJson(RouteSchema, body)).not.toThrow();
});

// The gateway reads any tls section on a route as "HTTPS only": a plain-HTTP
// request to it is refused with 403 "HTTPS required" (internal/server/proxy.go).
// The form keeps an empty one so its fields have values, and used to send it,
// so a route created in the dashboard -- or an HTTP route merely renamed there
// -- stopped serving plain HTTP.
test("a route with no TLS settings is saved without a tls section", () => {
  const values = routeToFormValues(fromGateway(stored()));
  const saved = fromJson(RouteSchema, onTheWire(formValuesToRoute(values)));

  expect(values.tls).toEqual({ certificateIds: [], optionId: "" });
  expect(saved.tls).toBeUndefined();
});

test("a route with a TLS option or a certificate keeps its tls section", () => {
  const values = routeToFormValues(fromGateway(stored()));
  const option = formValuesToRoute({ ...values, tls: { certificateIds: [], optionId: "modern" } });
  const cert = formValuesToRoute({ ...values, tls: { certificateIds: ["c1"], optionId: "" } });

  expect(fromJson(RouteSchema, onTheWire(option)).tls?.optionId).toBe("modern");
  expect(fromJson(RouteSchema, onTheWire(cert)).tls?.certificateIds).toEqual(["c1"]);
});

// A route's stream mode (ADR 0064) survives the edit form: a route set to
// always or never stream, opened and saved unchanged, keeps that setting, and
// one that never had it saves auto.
test("editing and saving a route keeps its stream mode", () => {
  for (const mode of [Route_StreamMode.ALWAYS, Route_StreamMode.NEVER]) {
    const msg = stored();
    msg.streamMode = mode;
    const values = routeToFormValues(fromGateway(msg));
    const saved = fromJson(RouteSchema, onTheWire(formValuesToRoute(values)));
    expect(saved.streamMode).toBe(mode);
  }
  const plain = fromJson(RouteSchema, onTheWire(formValuesToRoute(routeToFormValues(fromGateway(stored())))));
  expect(plain.streamMode).toBe(Route_StreamMode.AUTO);
});

test("a stream mode the dashboard does not know is shown and saved as auto", () => {
  const values = routeToFormValues({ ...fromGateway(stored()), streamMode: 7 as never });
  expect(values.streamMode).toBe(0);
});
