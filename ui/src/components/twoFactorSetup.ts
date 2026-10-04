// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { apiFetch } from "../hooks/api";
import { getApiBaseUrl } from "../store/useApiConfigStore";
import type { Setup2FARequest, Setup2FAResponse, Verify2FARequest } from "../types/gateon";
import { isChallengeRefusal } from "./signInMessages";

/**
 * The two self-service 2FA calls the enrolment dialog makes, and what it shows
 * when one is refused.
 *
 * Setup needs the account's current password: the session alone is a cookie
 * that script in the page can ride, and setup hands back a TOTP secret. The
 * gateway counts a wrong password towards the same lockout as a failed sign-in.
 *
 * Verifying the first code needs the challenge setup answered with: it proves
 * the password was given, and the gateway refuses the step without it (ADR
 * 0039). It lasts five minutes.
 *
 * Every refusal becomes one of the fixed sentences below. The server's own text
 * is never shown -- an unexpected failure can carry a database error -- and a
 * refusal is keyed on the status alone.
 */

export type Outcome<T> = { ok: true; data: T } | { ok: false; message: string };

const UNREACHABLE = "The gateway could not be reached. Check your connection and try again.";
// A 429 here is the account's lockout, this client's sign-in budget, or a
// full password-hashing gate (ADR 0053); the status alone cannot say which,
// so the sentence claims none of them -- it used to say the account was
// locked when it was not.
const LOCKED = "Too many attempts right now. Wait a few minutes and try again.";
const EXPIRED = "Setup took too long and has expired. Close this window and start again.";

/** What the dialog says when setup is refused with this status. */
export function setupRefusalMessage(status: number): string {
  switch (status) {
    case 400:
      return "Enter your current password to continue.";
    case 403:
      return "That password is not correct.";
    case 429:
      return LOCKED;
    default:
      return "Two-factor setup could not be started. Please try again.";
  }
}

/** What the dialog says when a code is refused with this status. */
export function verifyRefusalMessage(status: number): string {
  switch (status) {
    case 400:
    case 401:
    case 403:
      return "That code is not valid. Check that your device's clock is correct and try again.";
    case 429:
      return LOCKED;
    default:
      return "The code could not be verified. Please try again.";
  }
}

async function postJSON(path: string, body: unknown): Promise<Response | null> {
  try {
    return await apiFetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  } catch {
    return null;
  }
}

/** Starts enrolment for the signed-in account, proving it with its password. */
export async function startTwoFactorSetup(userId: string, password: string): Promise<Outcome<Setup2FAResponse>> {
  const req: Setup2FARequest = { id: userId, password };
  const res = await postJSON("/v1/auth/2fa/setup", req);
  if (!res) return { ok: false, message: UNREACHABLE };
  if (!res.ok) return { ok: false, message: setupRefusalMessage(res.status) };
  try {
    return { ok: true, data: (await res.json()) as Setup2FAResponse };
  } catch {
    return { ok: false, message: setupRefusalMessage(0) };
  }
}

/**
 * Completes enrolment with a code from the new authenticator and the challenge
 * setup answered with.
 *
 * Not through apiFetch: the endpoint is served before authentication, so its
 * 401 is about the code or the challenge, never the session -- and apiFetch
 * reads every 401 as "signed out" and ends the session the user was adding a
 * factor to.
 */
export async function verifyTwoFactorCode(userId: string, code: string, challenge: string): Promise<Outcome<null>> {
  const req: Verify2FARequest = { id: userId, code, challenge };
  let res: Response;
  try {
    res = await fetch(`${getApiBaseUrl()}/v1/auth/2fa/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(req),
      credentials: "include",
    });
  } catch {
    return { ok: false, message: UNREACHABLE };
  }
  if (!res.ok) {
    if (await isChallengeRefusal(res)) return { ok: false, message: EXPIRED };
    return { ok: false, message: verifyRefusalMessage(res.status) };
  }
  try {
    const data = (await res.json()) as { success?: boolean };
    return data.success ? { ok: true, data: null } : { ok: false, message: verifyRefusalMessage(403) };
  } catch {
    return { ok: false, message: verifyRefusalMessage(0) };
  }
}
