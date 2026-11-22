// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { UpgradeBlocker, UpgradePhase, UpgradeReason } from "../../../services/gen/gateon/v1/status_pb";
import {
  activeStep,
  blockerNote,
  isRollback,
  landedOn,
  ROLLBACK_STEPS,
  stepsOf,
  versionChange,
  outcomeLabel,
  outcomeView,
  progressNote,
  startedBy,
  UPGRADE_STEPS,
  type UpgradeFacts,
  upgradeInProgress,
  windowError,
} from "./upgradeView";

const record = (over: Partial<UpgradeFacts>): UpgradeFacts => ({
  phase: UpgradePhase.UNSPECIFIED,
  reason: UpgradeReason.UNSPECIFIED,
  targetVersion: "1.8.3",
  previousVersion: "1.8.2",
  automatic: false,
  requestedBy: "ada",
  databaseRestored: false,
  databaseKept: false,
  ...over,
});

const numeric = (e: Record<string, unknown>): number[] => Object.values(e).filter((v): v is number => typeof v === "number");

describe("an install in progress", () => {
  test("is every phase before an outcome, and none after", () => {
    const running = [UpgradePhase.DOWNLOADING, UpgradePhase.REQUESTED, UpgradePhase.INSTALLING, UpgradePhase.RESTARTING, UpgradePhase.ROLLING_BACK];
    for (const phase of numeric(UpgradePhase) as UpgradePhase[]) {
      expect(upgradeInProgress(phase)).toBe(running.includes(phase));
    }
    expect(upgradeInProgress(undefined)).toBe(false);
  });

  test("has a sentence for every running phase, naming the version", () => {
    for (const phase of numeric(UpgradePhase) as UpgradePhase[]) {
      const note = progressNote(record({ phase }));
      expect(note !== "").toBe(upgradeInProgress(phase));
      if (note) expect(note).toContain("v1.8.3");
    }
  });

  test("moves through the steps in order and finishes them all on success", () => {
    const order = [UpgradePhase.DOWNLOADING, UpgradePhase.REQUESTED, UpgradePhase.INSTALLING, UpgradePhase.RESTARTING];
    expect(order.map((phase) => activeStep(record({ phase })))).toEqual([0, 1, 2, 3]);
    expect(activeStep(record({ phase: UpgradePhase.SUCCEEDED }))).toBe(UPGRADE_STEPS.length);
  });

  test("says a rollback is under way rather than that the restart is", () => {
    expect(progressNote(record({ phase: UpgradePhase.ROLLING_BACK }))).toContain("Putting v1.8.2 back");
  });
});

describe("a finished install", () => {
  test("has no outcome while it runs or before there is one", () => {
    for (const phase of numeric(UpgradePhase) as UpgradePhase[]) {
      const finished = [UpgradePhase.SUCCEEDED, UpgradePhase.ROLLED_BACK, UpgradePhase.REFUSED, UpgradePhase.FAILED].includes(phase);
      expect(outcomeView(record({ phase })) !== null).toBe(finished);
    }
  });

  test("a success names both versions and says the old one is kept", () => {
    const v = outcomeView(record({ phase: UpgradePhase.SUCCEEDED }));
    expect(v?.tone).toBe("green");
    expect(v?.detail).toContain("v1.8.2 is kept");
  });

  test("a rollback says the old version runs again, and says so about the database only when it was put back", () => {
    const plain = outcomeView(record({ phase: UpgradePhase.ROLLED_BACK, reason: UpgradeReason.NOT_READY }));
    expect(plain?.tone).toBe("yellow");
    expect(plain?.detail).toContain("v1.8.2 is running again");
    expect(plain?.detail).not.toContain("database");
    const restored = outcomeView(record({ phase: UpgradePhase.ROLLED_BACK, databaseRestored: true }));
    expect(restored?.detail).toContain("the database was put back");
  });

  test("a rollback that left a migrated database in place says so, and does not say nothing was changed", () => {
    const kept = outcomeView(record({ phase: UpgradePhase.ROLLED_BACK, reason: UpgradeReason.NOT_READY, databaseKept: true }));
    expect(kept?.tone).toBe("yellow");
    expect(kept?.detail).toContain("v1.8.2 is running again");
    expect(kept?.detail).toContain("had already updated the database");
    expect(kept?.detail).not.toContain("Nothing else was changed");
    expect(kept?.detail).not.toContain("put back");
  });

  test("every refusal has its own words and says nothing was changed", () => {
    const seen = new Set<string>();
    for (const reason of numeric(UpgradeReason) as UpgradeReason[]) {
      // REQUESTED and PREVIOUS_NOT_READY are never a refusal: see "a rollback on request".
      const notRefusals = [UpgradeReason.UNSPECIFIED, UpgradeReason.NOT_READY, UpgradeReason.MIGRATED, UpgradeReason.REQUESTED, UpgradeReason.PREVIOUS_NOT_READY];
      if (notRefusals.includes(reason)) continue;
      const v = outcomeView(record({ phase: UpgradePhase.REFUSED, reason }));
      expect(v?.detail).toContain("Nothing on this host was changed.");
      expect(v?.detail).not.toContain("The release was refused.");
      seen.add(v?.detail ?? "");
    }
    expect(seen.size).toBe(10);
  });

  test("a migrated database that blocks the rollback is not reported as rolled back", () => {
    const v = outcomeView(record({ phase: UpgradePhase.FAILED, reason: UpgradeReason.MIGRATED }));
    expect(v?.tone).toBe("red");
    expect(v?.title).toBe("v1.8.3 is installed and is not ready");
    expect(v?.detail).toContain("v1.8.2 was not put back");
  });

  test("the history has a label for every outcome", () => {
    expect(outcomeLabel(record({ phase: UpgradePhase.SUCCEEDED }))).toBe("Installed");
    expect(outcomeLabel(record({ phase: UpgradePhase.ROLLED_BACK }))).toBe("Rolled back");
    expect(outcomeLabel(record({ phase: UpgradePhase.REFUSED }))).toBe("Not installed");
    expect(outcomeLabel(record({ phase: UpgradePhase.FAILED }))).toBe("Failed, not rolled back");
  });

  test("an automatic install is not attributed to a person", () => {
    expect(startedBy(record({ automatic: true, requestedBy: "" }))).toBe("Automatic");
    expect(startedBy(record({}))).toBe("ada");
    expect(startedBy(record({ requestedBy: "" }))).toBe("Unknown");
  });
});

describe("a gateway that cannot install", () => {
  test("offers the command that enables the helper", () => {
    expect(blockerNote(UpgradeBlocker.NO_HELPER)?.command).toBe("sudo systemctl enable --now gateon-upgrade.path");
  });

  test("says why for a build that cannot verify or compare", () => {
    expect(blockerNote(UpgradeBlocker.NO_KEY)?.text).toContain("no release key");
    expect(blockerNote(UpgradeBlocker.DEVELOPMENT_BUILD)?.text).toContain("development build");
  });

  test("adds nothing where there is a button, or where the orchestrator's steps are already shown", () => {
    expect(blockerNote(UpgradeBlocker.UNSPECIFIED)).toBeNull();
    expect(blockerNote(UpgradeBlocker.ORCHESTRATED)).toBeNull();
  });
});

describe("a maintenance window", () => {
  test("is both ends or neither", () => {
    expect(windowError("", "")).toBeNull();
    expect(windowError("02:00", "04:00")).toBeNull();
    expect(windowError("23:30", "01:00")).toBeNull();
    expect(windowError("02:00", "")).toContain("both");
    expect(windowError("", "04:00")).toContain("both");
  });

  test("is written HH:MM", () => {
    for (const bad of ["2:00", "24:00", "02:60", "0200", "two"]) {
      expect(windowError(bad, "04:00")).toContain("HH:MM");
      expect(windowError("02:00", bad)).toContain("HH:MM");
    }
  });
});

// A rollback somebody asked for (ADR 0105) is recorded with the phases of an
// install and told apart by its reason. Here 1.8.3 is running and 1.8.2 is
// the version it replaced.
describe("a rollback on request", () => {
  const asked = (over: Partial<UpgradeFacts>) => record({ reason: UpgradeReason.REQUESTED, ...over });

  test("is told apart from an upgrade that rolled itself back", () => {
    expect(isRollback(asked({ phase: UpgradePhase.ROLLED_BACK }))).toBe(true);
    expect(isRollback(record({ phase: UpgradePhase.ROLLED_BACK, reason: UpgradeReason.NOT_READY }))).toBe(false);
    expect(isRollback(record({ phase: UpgradePhase.FAILED, reason: UpgradeReason.MIGRATED }))).toBe(false);
  });

  test("has its own steps, with nothing to download", () => {
    expect(stepsOf(asked({}))).toBe(ROLLBACK_STEPS);
    expect(stepsOf(record({}))).toBe(UPGRADE_STEPS);
    expect(ROLLBACK_STEPS.map((s) => s.label)).not.toContain("Download");
    expect(activeStep(asked({ phase: UpgradePhase.REQUESTED }))).toBe(0);
    expect(activeStep(asked({ phase: UpgradePhase.ROLLING_BACK }))).toBe(2);
  });

  test("says which version is coming back, not that one failed", () => {
    const waiting = progressNote(asked({ phase: UpgradePhase.REQUESTED }));
    expect(waiting).toContain("put v1.8.2 back");
    const restarting = progressNote(asked({ phase: UpgradePhase.ROLLING_BACK }));
    expect(restarting).toContain("restarting on v1.8.2");
    expect(restarting).not.toContain("did not become ready");
  });

  test("says so when the previous version did not come up and the newer one is going back", () => {
    expect(progressNote(asked({ phase: UpgradePhase.RESTARTING }))).toBe("v1.8.2 did not become ready. Putting v1.8.3 back.");
  });

  test("reports success as what was asked for, and what became of the database", () => {
    const kept = outcomeView(asked({ phase: UpgradePhase.ROLLED_BACK }));
    expect(kept?.tone).toBe("green");
    expect(kept?.title).toBe("Rolled back to v1.8.2");
    expect(kept?.detail).toContain("The database was left as it is.");
    expect(kept?.detail).toContain("v1.8.3 will not be installed automatically again");
    const restored = outcomeView(asked({ phase: UpgradePhase.ROLLED_BACK, databaseRestored: true }));
    expect(restored?.detail).toContain("put back to the copy taken before the upgrade");
  });

  test("a refusal says nothing changed and what to do", () => {
    const none = outcomeView(record({ phase: UpgradePhase.REFUSED, reason: UpgradeReason.NO_PREVIOUS }));
    expect(none?.title).toBe("Not rolled back");
    expect(none?.detail).toContain("Nothing on this host was changed.");
    const restore = outcomeView(record({ phase: UpgradePhase.REFUSED, reason: UpgradeReason.NEEDS_RESTORE }));
    expect(restore?.detail).toContain("sudo gateon upgrade --rollback --restore-database");
    expect(restore?.detail).toContain("Nothing on this host was changed.");
    expect(restore?.title).not.toContain("was not installed");
  });

  test("a previous version that did not come up is not reported as running", () => {
    const v = outcomeView(record({ phase: UpgradePhase.FAILED, reason: UpgradeReason.PREVIOUS_NOT_READY }));
    expect(v?.tone).toBe("red");
    expect(v?.title).toBe("v1.8.2 did not become ready");
    expect(v?.detail).toContain("v1.8.3 was put back and is running");
  });

  test("reads backwards in the history, with its own labels", () => {
    expect(versionChange(asked({ phase: UpgradePhase.ROLLED_BACK }))).toBe("v1.8.3 back to v1.8.2");
    expect(versionChange(record({ phase: UpgradePhase.SUCCEEDED }))).toBe("v1.8.2 to v1.8.3");
    expect(outcomeLabel(asked({ phase: UpgradePhase.ROLLED_BACK }))).toBe("Rolled back on request");
    expect(outcomeLabel(record({ phase: UpgradePhase.REFUSED, reason: UpgradeReason.NEEDS_RESTORE }))).toBe("Rollback refused");
    expect(outcomeLabel(record({ phase: UpgradePhase.FAILED, reason: UpgradeReason.PREVIOUS_NOT_READY }))).toBe("Rollback failed");
  });

  test("knows which version a finished record left running", () => {
    expect(landedOn(record({ phase: UpgradePhase.SUCCEEDED }))).toBe("1.8.3");
    expect(landedOn(asked({ phase: UpgradePhase.ROLLED_BACK }))).toBe("1.8.2");
    expect(landedOn(record({ phase: UpgradePhase.ROLLED_BACK, reason: UpgradeReason.NOT_READY }))).toBeNull();
    expect(landedOn(record({ phase: UpgradePhase.FAILED, reason: UpgradeReason.PREVIOUS_NOT_READY }))).toBeNull();
  });
});
