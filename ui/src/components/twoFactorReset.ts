// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Code, ConnectError } from "@connectrpc/connect";
import type { User } from "../types/gateon";

/**
 * What the two-factor control on a user row does (ADR 0057).
 *
 * An administrator could require another account to enrol, but once it had
 * enrolled the control was disabled: an account whose authenticator was lost
 * could only be deleted (MGMT-N5). It now resets that account's second factor.
 * The caller's own account is self-service, from the enrolment modal, which
 * asks for the password -- the gateway refuses a reset of one's own account.
 *
 * Every account must have a second factor (ADR 0087), so one that has not
 * enrolled sets one up at its next sign-in whatever anyone does here. The
 * "require" and "cancel requirement" controls it used to offer toggled a flag
 * the sign-in no longer reads: cancelling did not let the account sign in
 * with its password alone, so the control said something untrue.
 */
export type TwoFactorAction = "self" | "reset" | "awaiting-enrolment" | "none";

export function twoFactorAction(user: Pick<User, "id" | "twoFactorEnabled" | "twoFactorPending">, currentUserId: string | undefined, isAdmin: boolean): TwoFactorAction {
  if (currentUserId === user.id) return "self";
  if (!user.twoFactorEnabled) return "awaiting-enrolment";
  return isAdmin ? "reset" : "none";
}

/** Whether the control does anything when pressed. */
export function twoFactorActionable(action: TwoFactorAction): boolean {
  return action === "self" || action === "reset";
}

/** The control's label, for its tooltip. */
export function twoFactorActionLabel(action: TwoFactorAction): string {
  switch (action) {
    case "self":
      return "Manage your two-factor authentication";
    case "reset":
      return "Reset this user's two-factor authentication";
    case "awaiting-enrolment":
      return "Sets up 2FA at their next sign-in: every account must have it";
    default:
      return "Only an administrator can change another user's two-factor authentication";
  }
}

/** The confirmation's words, naming the account. */
export function resetConfirmation(username: string): { title: string; question: string; confirm: string } {
  return {
    title: "Reset two-factor authentication",
    question:
      `Reset two-factor authentication for "${username}"? Their authenticator and recovery codes stop working, ` +
      "every session they have ends, and they must set up a new authenticator the next time they sign in.",
    confirm: `Reset 2FA for "${username}"`,
  };
}

/** A refused reset, in the dashboard's words. */
export function resetRefusalMessage(err: unknown): string {
  const code = err instanceof ConnectError ? err.code : undefined;
  switch (code) {
    case Code.PermissionDenied:
      return "Only an administrator can reset another user's two-factor authentication, and not their own: set yours up again from your profile.";
    case Code.NotFound:
      return "That user no longer exists.";
    default:
      return "Two-factor authentication could not be reset. Please try again.";
  }
}
