// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import type { QueryClient } from "@tanstack/react-query";

/** What POST /v1/config/import answers once it has applied a file. */
export interface ConfigImportResponse {
  success?: boolean;
  applied?: {
    routes?: number;
    services?: number;
    entry_points?: number;
    middlewares?: number;
  };
  errors?: string[];
}

export type ConfigImportTone = "success" | "partial" | "failed";

export interface ConfigImportOutcome {
  tone: ConfigImportTone;
  /** One sentence saying what the import changed. */
  summary: string;
  /** Each item the gateway refused, with its reason. */
  refused: string[];
}

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

/**
 * describeConfigImport turns the gateway's answer into what the card shows.
 *
 * An import is applied item by item, so a refusal says nothing about the rest
 * of the file. The card used to show only the refusals, which read as an
 * import that had added nothing while everything else in the file was live.
 */
export function describeConfigImport(data: ConfigImportResponse): ConfigImportOutcome {
  const a = data.applied ?? {};
  const counts = [
    plural(a.routes ?? 0, "route", "routes"),
    plural(a.services ?? 0, "service", "services"),
    plural(a.entry_points ?? 0, "listener", "listeners"),
    plural(a.middlewares ?? 0, "policy", "policies"),
  ];
  const applied = (a.routes ?? 0) + (a.services ?? 0) + (a.entry_points ?? 0) + (a.middlewares ?? 0);
  const refused = data.errors ?? [];
  const what = `Imported ${counts.join(", ")}.`;
  if (refused.length === 0) return { tone: "success", summary: what, refused };
  const notApplied = `${plural(refused.length, "item was", "items were")} not imported:`;
  if (applied === 0) return { tone: "failed", summary: `Nothing was imported. ${notApplied}`, refused };
  return { tone: "partial", summary: `${what} ${notApplied}`, refused };
}

/**
 * settleConfigImport refreshes every cached list once an import has been
 * applied, then describes the result. The dashboard caches lists for 30
 * seconds without refetching on focus, so without this the Routes, Services,
 * Listeners and Policies pages kept showing the configuration from before the
 * import -- empty, on a new gateway.
 */
export async function settleConfigImport(
  data: ConfigImportResponse,
  client: Pick<QueryClient, "invalidateQueries">,
): Promise<ConfigImportOutcome> {
  await client.invalidateQueries();
  return describeConfigImport(data);
}
