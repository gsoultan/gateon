// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from "bun:test";
import { InstallKind, UpdateCheckState, UpdateFailure, UpdateSignature } from "../../../services/gen/gateon/v1/status_pb";
import { checkedAgo, installKindLabel, staleNote, updateView, upgradeSteps, type UpdateFacts } from "./updateView";

const facts = (over: Partial<UpdateFacts>): UpdateFacts => ({
  currentVersion: "v1.8.2",
  latestVersion: "",
  updateAvailable: false,
  signature: UpdateSignature.UNSPECIFIED,
  state: UpdateCheckState.PENDING,
  failure: UpdateFailure.UNSPECIFIED,
  disabledByEnv: false,
  releaseBuild: true,
  ...over,
});

const found = (over: Partial<UpdateFacts> = {}) =>
  facts({ latestVersion: "1.8.3", updateAvailable: true, signature: UpdateSignature.VERIFIED, state: UpdateCheckState.OK, ...over });

describe("what the Software update card says", () => {
  test("a newer signed release is announced by its version", () => {
    const v = updateView(found());
    expect(v.tone).toBe("blue");
    expect(v.title).toBe("Gateon v1.8.3 is available");
    expect(v.detail).toContain("signed by a Gateon release key");
  });

  test("a build with no release key says the list was not verified, never that it was", () => {
    const v = updateView(found({ signature: UpdateSignature.NO_KEY }));
    expect(v.title).toBe("Gateon v1.8.3 is available");
    expect(v.detail).toContain("could not be verified");
    expect(v.detail).not.toContain("is signed");
  });

  test("the running version being the newest reads as up to date", () => {
    const v = updateView(found({ updateAvailable: false }));
    expect(v.tone).toBe("green");
    expect(v.title).toBe("You're up to date");
  });

  test("a development build is not called up to date or out of date", () => {
    const v = updateView(found({ updateAvailable: false, releaseBuild: false, currentVersion: "dev" }));
    expect(v.title).toBe("The newest release is v1.8.3");
    expect(v.detail).toContain("development build (dev)");
  });

  test("nothing checked yet says so, and is not an error", () => {
    const v = updateView(facts({}));
    expect(v.tone).toBe("gray");
    expect(v.title).toBe("Not checked yet");
  });

  test("each failure has its own words, and none shows a code", () => {
    const titles = new Set<string>();
    for (const failure of [UpdateFailure.UNREACHABLE, UpdateFailure.SIGNATURE, UpdateFailure.MALFORMED, UpdateFailure.SOURCE]) {
      const v = updateView(facts({ state: UpdateCheckState.FAILED, failure }));
      titles.add(v.title);
      expect(`${v.title} ${v.detail}`).not.toMatch(/UPDATE_FAILURE|\b[45]\d\d\b|undefined/);
    }
    expect(titles.size).toBe(4);
    expect(updateView(facts({ state: UpdateCheckState.FAILED, failure: UpdateFailure.SIGNATURE })).tone).toBe("red");
  });

  test("a failed check keeps showing what an earlier one found, and says it is earlier", () => {
    const s = found({ state: UpdateCheckState.FAILED, failure: UpdateFailure.UNREACHABLE });
    expect(updateView(s).title).toBe("Gateon v1.8.3 is available");
    expect(staleNote(s)).toContain("earlier check");
    expect(staleNote(found())).toBeNull();
    expect(staleNote(facts({ state: UpdateCheckState.FAILED, failure: UpdateFailure.UNREACHABLE }))).toBeNull();
  });

  test("switched off names what switched it off", () => {
    const setting = updateView(facts({ state: UpdateCheckState.DISABLED }));
    expect(setting.title).toBe("Update checks are off");
    expect(setting.detail).toContain("Turn the daily check on below");
    const env = updateView(facts({ state: UpdateCheckState.DISABLED, disabledByEnv: true }));
    expect(env.detail).toContain("GATEON_UPDATE_CHECK");
    expect(env.detail).not.toContain("below");
  });
});

describe("how each kind of install takes a new version", () => {
  test("a container is told to pull the image, by the release's tag", () => {
    expect(upgradeSteps(InstallKind.CONTAINER, "1.8.3").command).toBe("docker pull ghcr.io/gsoultan/gateon:1.8.3");
    expect(upgradeSteps(InstallKind.KUBERNETES, "1.8.3").command).toContain("image.tag=1.8.3");
  });

  test("a host install is sent to the release page, with no command to paste", () => {
    for (const kind of [InstallKind.SYSTEMD, InstallKind.OTHER, InstallKind.UNSPECIFIED]) {
      const steps = upgradeSteps(kind, "1.8.3");
      expect(steps.command).toBeUndefined();
      expect(steps.text).toContain("release page");
    }
  });

  test("every kind has a name", () => {
    expect(installKindLabel(InstallKind.SYSTEMD)).toBe("systemd service");
    expect(installKindLabel(InstallKind.KUBERNETES)).toBe("Kubernetes");
    expect(installKindLabel(InstallKind.UNSPECIFIED)).toBe("standalone binary");
  });
});

describe("when the last check ran", () => {
  const now = Date.UTC(2026, 10, 13, 8, 0, 0);
  const ago = (seconds: number) => checkedAgo(BigInt(Math.floor(now / 1000) - seconds), now);

  test("reads as a distance, in the unit that fits", () => {
    expect(ago(10)).toBe("a moment ago");
    expect(ago(60)).toBe("1 minute ago");
    expect(ago(45 * 60)).toBe("45 minutes ago");
    expect(ago(2 * 3600)).toBe("2 hours ago");
    expect(ago(72 * 3600)).toBe("3 days ago");
  });

  test("is empty when no check has finished, and never negative", () => {
    expect(checkedAgo(0n, now)).toBe("");
    expect(ago(-300)).toBe("a moment ago");
  });
});
