// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

/**
 * What GET /v1/global returns in place of a stored secret, and what a save
 * sends back to keep it. The gateway never returns a stored secret's value, to
 * anyone (ADR 0028): a field holding this string means "a secret is stored",
 * and sending it back keeps that secret. Sending a new value replaces it.
 *
 * Must equal storedsecret.Sentinel in
 * internal/config/storedsecret/storedsecret.go. A Go test reads this file and
 * fails if the two differ.
 */
export const STORED_SECRET_SENTINEL = "__gateon_redacted__";

/** Whether a secret field's value stands for a secret stored on the gateway. */
export function isStoredSecret(value: string | null | undefined): boolean {
  return value === STORED_SECRET_SENTINEL;
}

/**
 * Whether a connection URL carries a stored password: the gateway shows
 * "postgres://user:__gateon_redacted__@host/db" so the rest stays readable.
 */
export function hasStoredSecret(value: string | null | undefined): boolean {
  return typeof value === "string" && value.includes(STORED_SECRET_SENTINEL);
}

/** Whether a value names a secret held elsewhere ($env:, $vault:, $aws-sm:). */
export function isSecretReference(value: string | null | undefined): boolean {
  return typeof value === "string" && /^\$(env|vault|aws-sm):/.test(value);
}

/**
 * The value to save for a replacement being typed over a stored secret. An
 * empty draft keeps the stored secret: replacing never clears by accident,
 * only the explicit Clear does.
 */
export function replacementValue(draft: string): string {
  return draft === "" ? STORED_SECRET_SENTINEL : draft;
}
