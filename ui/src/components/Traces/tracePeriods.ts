// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Periods for the History tab. The gateway takes RFC 3339 instants; people
// pick times in their own zone, so the inputs are local and converted here.

export type PeriodPreset = "1h" | "24h" | "7d" | "30d" | "custom";

export const PERIOD_PRESETS: { value: PeriodPreset; label: string }[] = [
  { value: "1h", label: "Last hour" },
  { value: "24h", label: "24 hours" },
  { value: "7d", label: "7 days" },
  { value: "30d", label: "30 days" },
  { value: "custom", label: "Custom" },
];

const HOUR_MS = 3_600_000;
const PRESET_MS: Record<Exclude<PeriodPreset, "custom">, number> = {
  "1h": HOUR_MS,
  "24h": 24 * HOUR_MS,
  "7d": 7 * 24 * HOUR_MS,
  "30d": 30 * 24 * HOUR_MS,
};

export interface Period {
  from: Date;
  to: Date;
}

/** The period a preset names, ending now. */
export function presetPeriod(preset: Exclude<PeriodPreset, "custom">, now: Date = new Date()): Period {
  return { from: new Date(now.getTime() - PRESET_MS[preset]), to: now };
}

/** The hour an archive file holds, from its period_start. */
export function hourPeriod(periodStart: string): Period | null {
  const from = new Date(periodStart);
  if (Number.isNaN(from.getTime())) return null;
  return { from, to: new Date(from.getTime() + HOUR_MS) };
}

/**
 * archiveSpan is the time an archive covers, given its oldest and newest
 * hours as the gateway names them -- by their starts: from the start of the
 * oldest hour to the end of the newest.
 */
export function archiveSpan(oldestPeriod: string, newestPeriod: string): Period | null {
  const oldest = hourPeriod(oldestPeriod);
  const newest = hourPeriod(newestPeriod);
  return oldest && newest ? { from: oldest.from, to: newest.to } : null;
}

const pad = (n: number) => String(n).padStart(2, "0");

/** A date as a datetime-local input shows it: local time, to the minute. */
export function toLocalInput(d: Date): string {
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/** A datetime-local input's value as a date, or null if it holds none. */
export function fromLocalInput(value: string): Date | null {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?$/.test(value)) return null;
  const d = new Date(value); // no zone in the string: read as local time
  return Number.isNaN(d.getTime()) ? null : d;
}

/** Why a period cannot be queried, in words, or null if it can. */
export function periodProblem(p: { from: Date | null; to: Date | null }): string | null {
  if (!p.from || !p.to) return "Choose when the period starts and ends.";
  if (p.from.getTime() >= p.to.getTime()) return "The period has to start before it ends.";
  if (p.to.getTime() - p.from.getTime() > 400 * 24 * HOUR_MS) return "A period can span at most 400 days.";
  return null;
}
