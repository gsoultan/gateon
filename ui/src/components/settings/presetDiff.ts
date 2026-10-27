// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

/** One field a preset would change: its dotted path, and both values as text. */
export interface PresetChange {
  path: string;
  from: string;
  to: string;
}

const show = (v: unknown): string => {
  if (v === undefined) return "unset";
  if (v === null) return "null";
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
};

/**
 * Every leaf that differs between the configuration as it is and as a preset
 * would leave it, in path order. A preset used to replace sections silently;
 * this is the list shown before one is applied, so what it changes is read
 * rather than discovered after a save.
 */
export function presetChanges(current: unknown, proposed: unknown, prefix = ""): PresetChange[] {
  // A section one side lacks is compared field by field, so a preset that
  // adds a section lists the fields it sets rather than one JSON blob.
  if ((isRecord(current) || current === undefined) && (isRecord(proposed) || proposed === undefined) && (isRecord(current) || isRecord(proposed))) {
    const before: Record<string, unknown> = current ?? {};
    const after: Record<string, unknown> = proposed ?? {};
    const keys = [...new Set([...Object.keys(before), ...Object.keys(after)])].sort();
    return keys.flatMap((k) => presetChanges(before[k], after[k], prefix ? `${prefix}.${k}` : k));
  }
  if (Object.is(current, proposed) || JSON.stringify(current) === JSON.stringify(proposed)) return [];
  return [{ path: prefix || "(root)", from: show(current), to: show(proposed) }];
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
