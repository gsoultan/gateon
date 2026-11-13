// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { UpgradeBlocker, UpgradePhase, UpgradeReason } from "../../../services/gen/gateon/v1/status_pb";
import {
  activeStep,
  blockerNote,
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
    expect(order.map(activeStep)).toEqual([0, 1, 2, 3]);
    expect(activeStep(UpgradePhase.SUCCEEDED)).toBe(UPGRADE_STEPS.length);
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

  test("every refusal has its own words and says nothing was changed", () => {
    const seen = new Set<string>();
    for (const reason of numeric(UpgradeReason) as UpgradeReason[]) {
      if ([UpgradeReason.UNSPECIFIED, UpgradeReason.NOT_READY, UpgradeReason.MIGRATED].includes(reason)) continue;
      const v = outcomeView(record({ phase: UpgradePhase.REFUSED, reason }));
      expect(v?.detail).toContain("Nothing on this host was changed.");
      expect(v?.detail).not.toContain("The release was refused.");
      seen.add(v?.detail ?? "");
    }
    expect(seen.size).toBe(8);
  });

  test("a migrated database that blocks the rollback is not reported as rolled back", () => {
    const v = outcomeView(record({ phase: UpgradePhase.FAILED, reason: UpgradeReason.MIGRATED }));
    expect(v?.tone).toBe("red");
    expect(v?.title).toBe("v1.8.3 is installed and is not ready");
    expect(v?.detail).toContain("v1.8.2 was not put back");
  });

  test("the history has a label for every outcome", () => {
    expect(outcomeLabel(UpgradePhase.SUCCEEDED)).toBe("Installed");
    expect(outcomeLabel(UpgradePhase.ROLLED_BACK)).toBe("Rolled back");
    expect(outcomeLabel(UpgradePhase.REFUSED)).toBe("Not installed");
    expect(outcomeLabel(UpgradePhase.FAILED)).toBe("Failed, not rolled back");
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
