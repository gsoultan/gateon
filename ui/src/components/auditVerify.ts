// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Code, ConnectError } from "@connectrpc/connect";

/**
 * What the audit page says about a verification of the audit log's HMAC chain
 * (ADR 0050). The gateway checks a window of entries at a time and says where
 * to continue; the page sums the windows it has checked.
 */

/** The fields of a VerifyAuditChainResponse this reads. */
export interface VerifyAnswer {
  intact: boolean;
  checked: number;
  firstBreak?: { id: string; timestamp: string; reason: string };
  nextAfterId: string;
  complete: boolean;
  lastTimestamp: string;
}

export interface VerifyOutcome {
  color: "green" | "blue" | "red";
  title: string;
  message: string;
  /** Whether there is more of the log to check. */
  canContinue: boolean;
}

/** The outcome after the windows checked so far, `checked` entries in all. */
export function describeVerification(answer: VerifyAnswer, checked: number): VerifyOutcome {
  if (!answer.intact && answer.firstBreak) {
    const b = answer.firstBreak;
    return {
      color: "red",
      title: "The audit log does not verify",
      message:
        `${checked} entries are intact, then the chain breaks at entry ${b.id} (${b.timestamp}): ${b.reason}. ` +
        "That entry was edited, inserted, removed or reordered -- or written while signing was off.",
      canContinue: false,
    };
  }
  if (!answer.complete) {
    return {
      color: "blue",
      title: "Intact so far",
      message: `${checked} entries checked, up to ${answer.lastTimestamp || "the start"}. Continue to check the rest.`,
      canContinue: true,
    };
  }
  return {
    color: "green",
    title: "The audit log verifies",
    message:
      checked === 0
        ? "There are no entries to check yet."
        : `All ${checked} entries are signed and each follows the one before.`,
    canContinue: false,
  };
}

/** A refused verification, in the dashboard's words. */
export function verifyRefusalMessage(err: unknown): string {
  const code = err instanceof ConnectError ? err.code : undefined;
  switch (code) {
    case Code.FailedPrecondition:
      return "Audit signing is off, so there is no chain to verify. Turn on signing under Settings, Audit.";
    case Code.PermissionDenied:
      return "Only an administrator can verify the audit log.";
    case Code.InvalidArgument:
      return "The place to continue from is no longer in the log (retention may have removed it). Start again.";
    default:
      return "The audit log could not be verified. Please try again.";
  }
}
