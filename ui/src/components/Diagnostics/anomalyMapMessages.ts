// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

/**
 * mapEmptyMessage explains an empty map. Locations come only from a local
 * MaxMind database: client addresses are never sent to a third-party lookup
 * service, so without one there are findings but nothing to place on the map.
 */
export function mapEmptyMessage(findings: number): string {
  if (findings === 0) return "No anomalies detected";
  const noun = findings === 1 ? "finding has" : "findings have";
  return `${findings} ${noun} no location. Locations need a local MaxMind GeoLite2 database (Settings → GeoIP).`;
}
