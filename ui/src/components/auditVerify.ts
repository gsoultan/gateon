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
  /** The newest entry this gateway has written, checked when the range ran to now (ADR 0057). */
  tailAnchorTimestamp?: string;
  /** That entry is no longer in the log: entries were removed from its end. */
  tailMissing?: boolean;
}

/**
 * What a chain cannot show, said wherever the log is called verified: what is
 * left of a log cut from its end still verifies. TRUTH-NEW-11 -- the page said
 * "The audit log verifies" over a log whose newest entries had been deleted.
 */
export function tailSentence(answer: VerifyAnswer): string {
  if (answer.tailAnchorTimestamp) {
    return (
      ` The newest entry this gateway has written since it started (${answer.tailAnchorTimestamp}) is still there, ` +
      "so none were removed from the end since then. Entries removed from the end while the gateway was stopped " +
      "cannot be detected."
    );
  }
  return (
    " Whether entries were removed from the end cannot be shown: what is left of a log cut from its end still " +
    "verifies, and this gateway has no newer entry of its own to look for."
  );
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
  if (answer.tailMissing) {
    return {
      color: "red",
      title: "The newest audit entries were removed",
      message:
        `${checked} entries are signed and each follows the one before, but the newest entry this gateway wrote ` +
        `(${answer.tailAnchorTimestamp || "since it started"}) is no longer in the log: entries were deleted from its end.`,
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
        : `All ${checked} entries are signed and each follows the one before.` + tailSentence(answer),
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
