// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { apiFetch } from "../hooks/api";

/**
 * What signing out does, said wherever the dashboard offers it: the header's
 * profile menu, the Profile page and the command palette.
 *
 * The gateway ends every session of the account, not only this browser's. A
 * session is a bearer token, and the only way to end a copy of one -- which is
 * why someone signs out of a device they no longer trust -- is to end them
 * all, so the other devices signed in to the account are signed out too.
 */
export const SIGN_OUT_SCOPE = "Ends every session of this account, on every device";

export const OTHER_SESSIONS_MAY_REMAIN =
  "You are signed out on this device, but the gateway did not confirm that this account's other " +
  "sessions ended, so they may keep working until they expire. To end them, sign in and sign out " +
  "again, or change your password.";

export const SESSION_HAD_ENDED =
  "Your session here had already ended, so this account's other sessions were not signed out. " +
  "To end them, sign in and sign out again.";

export const NOT_SIGNED_OUT = "The gateway did not confirm the sign-out, so you may still be signed in. Try again.";

export type SignOutOutcome =
  /** This browser is signed out; `warning` says what may not be, or is null when every session ended. */
  | { signedOut: true; warning: string | null }
  /** Nothing is known to have ended, this browser's session included. */
  | { signedOut: false; warning: string };

async function statusOf(path: string, init?: RequestInit): Promise<number | null> {
  try {
    return (await apiFetch(path, init)).status;
  } catch {
    return null;
  }
}

/**
 * Signs every session of the account out, and says what actually ended.
 *
 * Every sign-out control used to throw the gateway's answer away and go to the
 * sign-in page as though every session had ended. The gateway clears this
 * browser's cookie whether or not it can end the others -- ending them is a
 * database write -- and answers 500 when it cannot. So anything but a success
 * is checked against /v1/me: a 401 there means this browser is signed out,
 * whatever became of the others, and anything else means it may not be.
 */
export async function signOutEverywhere(): Promise<SignOutOutcome> {
  const status = await statusOf("/v1/logout", { method: "POST" });
  if (status !== null && status >= 200 && status < 300) return { signedOut: true, warning: null };
  // The session was already over, so there was nothing here to end; the
  // account's sessions elsewhere were not touched.
  if (status === 401) return { signedOut: true, warning: SESSION_HAD_ENDED };
  if ((await statusOf("/v1/me")) === 401) return { signedOut: true, warning: OTHER_SESSIONS_MAY_REMAIN };
  return { signedOut: false, warning: NOT_SIGNED_OUT };
}
