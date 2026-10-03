// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

/**
 * The password policy the gateway enforces (ADR 0050), checked in the form so
 * a refusal is explained before anything is sent. The gateway is the authority:
 * it also refuses commonly used passwords, which the dashboard does not ship a
 * list of.
 */

export const PASSWORD_MIN_LENGTH = 12;
/** bcrypt's input limit; the gateway refuses anything longer. */
export const PASSWORD_MAX_BYTES = 72;

/** The rule in one sentence, for a field's description. */
export const PASSWORD_RULE =
  "At least 12 characters. Not the username, and not a commonly used password.";

/** Said when the gateway refuses a password the form let through. */
export const PASSWORD_REFUSED =
  "That password was refused: use at least 12 characters, not containing the username, and not a commonly used password.";

/** What is wrong with password for the account username, or null. */
export function passwordPolicyError(password: string, username = ""): string | null {
  if ([...password].length < PASSWORD_MIN_LENGTH) {
    return `Use at least ${PASSWORD_MIN_LENGTH} characters`;
  }
  if (new TextEncoder().encode(password).length > PASSWORD_MAX_BYTES) {
    return `Use at most ${PASSWORD_MAX_BYTES} bytes`;
  }
  const name = username.trim().toLowerCase();
  if (name.length >= 3 && password.toLowerCase().includes(name)) {
    return "Do not include the username";
  }
  return null;
}
