// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { apiFetch } from "../hooks/api";

/**
 * The two ways the dashboard changes a password, and what it says when one is
 * refused.
 *
 * Changing your own password needs the one you have now: the session alone is
 * a cookie that script in the page can ride, and a password that script chose
 * would outlive the session. A wrong current password counts towards the same
 * lockout as a failed sign-in. An administrator resetting someone else's
 * password has no current password to give and sends none.
 *
 * Every refusal becomes one of the fixed sentences below, keyed on the status;
 * the server's own text is never shown.
 */

export type ChangeOutcome = { ok: true } | { ok: false; message: string };

const UNREACHABLE = "The gateway could not be reached. Check your connection and try again.";

/** What the form says when a change is refused with this status. */
export function passwordChangeRefusalMessage(status: number, own: boolean): string {
  switch (status) {
    case 400:
      return own ? "Enter your current password to change it." : "Enter a new password.";
    case 403:
      return own ? "Your current password is not correct." : "You do not have permission to change this password.";
    case 429:
      return "Too many failed attempts. The account is locked for a while; try again later.";
    default:
      return "The password could not be changed. Please try again.";
  }
}

async function post(body: Record<string, string>, own: boolean): Promise<ChangeOutcome> {
  let res: Response;
  try {
    res = await apiFetch("/v1/users/password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  } catch {
    return { ok: false, message: UNREACHABLE };
  }
  return res.ok ? { ok: true } : { ok: false, message: passwordChangeRefusalMessage(res.status, own) };
}

/** Changes the signed-in user's own password, proving it with the current one. */
export function changeOwnPassword(userId: string, currentPassword: string, password: string): Promise<ChangeOutcome> {
  return post({ id: userId, password, currentPassword }, true);
}

/** An administrator setting another account's password. */
export function resetPassword(userId: string, password: string): Promise<ChangeOutcome> {
  return post({ id: userId, password }, false);
}
