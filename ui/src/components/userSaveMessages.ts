// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { PASSWORD_REFUSED } from "./passwordPolicy";

/**
 * What the Users page says when the gateway refuses to save an account because
 * its username belongs to another one -- an Add User under a name that exists,
 * or an edit that renames onto one. The gateway answers 409 and writes nothing.
 *
 * Adding a user under a taken name used to replace that account's password and
 * role and report the save as a success. The refusal is the dashboard's own
 * sentence, never the server's text.
 */
export const USERNAME_TAKEN = "That username is already taken by another account. Choose a different username.";

/**
 * The fixed sentence for a refused save, or null when the status has none. A
 * 400 for a save that set a password is the password policy (ADR 0050).
 */
export function userSaveRefusalMessage(status: number, setsPassword = false): string | null {
  if (status === 409) return USERNAME_TAKEN;
  if (status === 400 && setsPassword) return PASSWORD_REFUSED;
  return null;
}
