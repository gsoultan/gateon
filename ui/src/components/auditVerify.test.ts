// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { Code, ConnectError } from "@connectrpc/connect";
import { describeVerification, verifyRefusalMessage } from "./auditVerify";

const done = { intact: true, checked: 3, nextAfterId: "", complete: true, lastTimestamp: "2026-10-03T01:00:00Z" };

describe("describeVerification", () => {
  test("a complete, intact chain says so with the total checked, and what it cannot show", () => {
    const o = describeVerification(done, 1203);
    expect(o).toMatchObject({ color: "green", title: "The audit log verifies", canContinue: false });
    expect(o.message).toStartWith("All 1203 entries are signed and each follows the one before.");
    // TRUTH-NEW-11: never "verifies" without the limit beside it.
    expect(o.message).toContain("Whether entries were removed from the end cannot be shown");
  });

  test("a checked tail says how far, and what it still cannot see", () => {
    const o = describeVerification({ ...done, tailAnchorTimestamp: "2026-10-04T09:30:00Z" }, 3);
    expect(o.color).toBe("green");
    expect(o.message).toContain("(2026-10-04T09:30:00Z) is still there, so none were removed from the end since then");
    expect(o.message).toContain("while the gateway was stopped cannot be detected");
  });

  test("a log cut from its end is not called verified (TRUTH-NEW-11)", () => {
    const o = describeVerification(
      { ...done, intact: false, tailMissing: true, tailAnchorTimestamp: "2026-10-04T09:30:00Z" },
      7,
    );
    expect(o.color).toBe("red");
    expect(o.title).toBe("The newest audit entries were removed");
    expect(o.message).toContain("the newest entry this gateway wrote (2026-10-04T09:30:00Z) is no longer in the log");
    expect(o.canContinue).toBe(false);
  });

  test("an empty log is not called verified by count", () => {
    expect(describeVerification({ ...done, checked: 0 }, 0).message).toBe("There are no entries to check yet.");
  });

  test("a window with more after it offers to continue", () => {
    const o = describeVerification({ ...done, complete: false, nextAfterId: "e-1000" }, 1000);
    expect(o.color).toBe("blue");
    expect(o.canContinue).toBe(true);
    expect(o.message).toContain("1000 entries checked, up to 2026-10-03T01:00:00Z");
  });

  test("a break names the entry, when, and why, and stops", () => {
    const o = describeVerification(
      {
        ...done,
        intact: false,
        complete: false,
        firstBreak: { id: "e-42", timestamp: "2026-10-03T00:00:42Z", reason: "entry is unsigned" },
      },
      41,
    );
    expect(o.color).toBe("red");
    expect(o.canContinue).toBe(false);
    expect(o.message).toContain("41 entries are intact, then the chain breaks at entry e-42 (2026-10-03T00:00:42Z): entry is unsigned.");
  });
});

describe("verifyRefusalMessage", () => {
  test.each([
    [Code.FailedPrecondition, "Audit signing is off"],
    [Code.PermissionDenied, "Only an administrator"],
    [Code.InvalidArgument, "Start again"],
    [Code.Internal, "could not be verified"],
  ])("code %p is said in the dashboard's words", (code, words) => {
    const msg = verifyRefusalMessage(new ConnectError("rpc error: pq: something internal", code));
    expect(msg).toContain(words);
    expect(msg).not.toContain("pq:");
  });
});
