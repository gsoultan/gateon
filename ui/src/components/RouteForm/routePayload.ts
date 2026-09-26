// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import type { Route } from "../../types/gateon";

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
  };
}

/** The body PUT /v1/routes is sent for the form's values. */
export function formValuesToRoute(values: Route): Route {
  return isL4(values.type) ? { ...values, rule: "L4()" } : { ...values };
}
