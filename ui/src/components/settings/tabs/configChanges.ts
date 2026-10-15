// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// A value as JSON.stringify would write it, with object keys sorted so two
// configurations that differ only in key order compare equal. An absent key
// and one set to undefined are the same thing on the wire, and both are left
// out.
function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value).sort()) {
      const v = (value as Record<string, unknown>)[key];
      if (v !== undefined) out[key] = canonical(v);
    }
    return out;
  }
  return value;
}

/**
 * Whether the configuration being edited differs from the one the gateway
 * last confirmed, as the body a save would send. The Settings save bar said
 * "You have modified the global configuration" from the moment the page
 * opened, whether or not anything had been touched, so it told an operator
 * nothing — and a bar that is always there is a bar nobody reads.
 */
export function hasUnsavedChanges(edited: unknown, saved: unknown): boolean {
  return JSON.stringify(canonical(edited)) !== JSON.stringify(canonical(saved));
}
