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
 */
export type TwoFactorAction = "self" | "reset" | "require" | "cancel-requirement" | "none";

export function twoFactorAction(user: Pick<User, "id" | "twoFactorEnabled" | "twoFactorPending">, currentUserId: string | undefined, isAdmin: boolean): TwoFactorAction {
  if (currentUserId === user.id) return "self";
  if (!isAdmin) return "none";
  if (user.twoFactorEnabled) return "reset";
  return user.twoFactorPending ? "cancel-requirement" : "require";
}

/** The control's label, for its tooltip. */
export function twoFactorActionLabel(action: TwoFactorAction): string {
  switch (action) {
    case "self":
      return "Manage your two-factor authentication";
    case "reset":
      return "Reset this user's two-factor authentication";
    case "cancel-requirement":
      return "2FA required — click to cancel requirement";
    case "require":
      return "Require this user to set up 2FA";
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
