// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { format } from "date-fns";

export function formatCompact(num: number | undefined | null): string {
  if (num === undefined || num === null || isNaN(num as number)) return "0";
  const n = num as number;
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1000) return `${(n / 1000).toFixed(1)}K`;
  return n.toLocaleString();
}

export function formatBytes(num: number | undefined | null): string {
  if (num === undefined || num === null || isNaN(num as number)) return "0 B";
  const n = num as number;
  if (n >= 1024 * 1024 * 1024) return `${(n / (1024 * 1024 * 1024)).toFixed(1)} GB`;
  if (n >= 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${Math.round(n)} B`;
}

/**
 * formatUptime renders a gateway uptime. Whole seconds: the live metrics
 * snapshot reports uptime as float seconds, and the fraction used to be printed
 * as it came ("50.395464208s").
 */
export function formatUptime(seconds: number) {
  const s = Math.floor(seconds)
  if (s < 60) return `${s}s`
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`
  const hours = Math.floor(s / 3600)
  const minutes = Math.floor((s % 3600) / 60)
  return `${hours}h ${minutes}m`
}

export function safeToFixed(val: number | undefined | null, decimals = 1): string {
  if (val === undefined || val === null || isNaN(Number(val))) return "0";
  return Number(val).toFixed(decimals);
}

export function safeToLocaleString(val: number | undefined | null): string {
  if (val === undefined || val === null || isNaN(Number(val))) return "0";
  return Number(val).toLocaleString();
}

export function safeFormatDate(dateVal: any, formatStr: string, fallback = 'N/A'): string {
  if (!dateVal) return fallback;
  try {
    const d = new Date(dateVal);
    if (isNaN(d.getTime())) return fallback;
    return format(d, formatStr);
  } catch {
    return fallback;
  }
}

export function safeToDateLocaleString(dateVal: any, fallback = 'N/A'): string {
  if (!dateVal) return fallback;
  try {
    const d = new Date(dateVal);
    if (isNaN(d.getTime())) return fallback;
    return d.toLocaleString();
  } catch {
    return fallback;
  }
}

export function formatHourLabel(ts: number): string {
  const date = new Date(ts);
  const month = `${date.getMonth() + 1}`.padStart(2, "0");
  const day = `${date.getDate()}`.padStart(2, "0");
  const hour = `${date.getHours()}`.padStart(2, "0");
  return `${month}/${day} ${hour}:00`;
}

const SECOND_MS = 1000;
const MINUTE_MS = 60 * SECOND_MS;

// msUntilExpiry is how long until an RFC 3339 expiry, or null when there is
// none or it cannot be read.
function msUntilExpiry(expiresAt: string | undefined, nowMs: number): number | null {
  if (!expiresAt) return null;
  const at = Date.parse(expiresAt);
  return Number.isNaN(at) ? null : at - nowMs;
}

/**
 * When a mitigation lifts, as the mitigation list says it: "lifts in 4m",
 * "lifts in 45s", "lifts in 1h 5m". Minutes and seconds round up, so it never
 * says a limit lifts sooner than it does. "lifting now" once the moment has
 * passed: the gateway sweeps expired kernel limits every 30 seconds, and one
 * that was set again shows its new expiry on the next refresh. "" when there is
 * no expiry.
 */
export function formatLiftsIn(expiresAt: string | undefined, nowMs: number): string {
  const rem = msUntilExpiry(expiresAt, nowMs);
  if (rem === null) return "";
  if (rem <= 0) return "lifting now";
  if (rem <= MINUTE_MS) return `lifts in ${Math.ceil(rem / SECOND_MS)}s`;
  const minutes = Math.ceil(rem / MINUTE_MS);
  if (minutes < 60) return `lifts in ${minutes}m`;
  const h = Math.floor(minutes / 60);
  const m = minutes % 60;
  return `lifts in ${h}h${m ? ` ${m}m` : ""}`;
}

/**
 * How long until formatLiftsIn's text for this expiry next changes, or null
 * when it never will. A countdown sleeps exactly that long instead of polling
 * on an interval: once a minute while minutes are shown, once a second for the
 * last minute, and not at all after "lifting now".
 */
export function msUntilLiftsInChanges(expiresAt: string | undefined, nowMs: number): number | null {
  const rem = msUntilExpiry(expiresAt, nowMs);
  if (rem === null || rem <= 0) return null;
  const unit = rem <= MINUTE_MS ? SECOND_MS : MINUTE_MS;
  return rem % unit || unit;
}

export function getCountryFlag(countryCode: string): string {
  if (!countryCode || countryCode.length !== 2 || countryCode === "XX") {
    return "🌐";
  }
  const codePoints = countryCode
    .toUpperCase()
    .split("")
    .map((char) => 127397 + char.charCodeAt(0));
  return String.fromCodePoint(...codePoints);
}
