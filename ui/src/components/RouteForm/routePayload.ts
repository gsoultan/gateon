// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { ROUTE_STREAM_MODE, type Route, type RouteStreamMode } from "../../types/gateon";

const isL4 = (type: Route["type"]) => type === "tcp" || type === "udp";

/** The route form's values for a route the gateway returned. */
export function routeToFormValues(route: Route): Route {
  const type = route.type || "http";
  return {
    id: route.id,
    name: route.name || "",
    type,
    rule: isL4(type) ? "L4()" : route.rule || "",
    priority: route.priority || 0,
    entrypoints: route.entrypoints || [],
    middlewares: route.middlewares || [],
    serviceId: route.serviceId || "",
    tls: route.tls || { certificateIds: [], optionId: "" },
    disabled: route.disabled ?? false,
    streamMode: knownStreamMode(route.streamMode),
  };
}

/** A stream mode the gateway knows, or auto: what the router reads any other value as. */
function knownStreamMode(mode: number | undefined): RouteStreamMode {
  return (Object.values(ROUTE_STREAM_MODE) as number[]).includes(mode ?? -1)
    ? (mode as RouteStreamMode)
    : ROUTE_STREAM_MODE.AUTO;
}

/**
 * Whether a route's tls section asks for anything: a TLS option, a
 * certificate, or ACME.
 */
function hasTlsSettings(tls: Route["tls"]): boolean {
  if (!tls) return false;
  return Boolean(tls.optionId) || (tls.certificateIds?.length ?? 0) > 0 || tls.acmeEnabled === true;
}

/**
 * The body PUT /v1/routes is sent for the form's values.
 *
 * The gateway reads the presence of a tls section as "this route is HTTPS
 * only" and refuses plain HTTP to it with 403 "HTTPS required". The form's
 * values always carry one, empty, so its fields have something to bind to;
 * sending that made every route created here, and every HTTP route merely
 * edited here, stop serving plain HTTP. An empty section is left out.
 */
export function formValuesToRoute(values: Route): Route {
  const route = isL4(values.type) ? { ...values, rule: "L4()" } : { ...values };
  if (!hasTlsSettings(route.tls)) delete route.tls;
  return route;
}
