// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import {
  UpdateScope,
  UpgradeBlocker,
  UpgradePhase,
  UpgradeReason,
  type UpgradeRecord,
} from "../../../services/gen/gateon/v1/status_pb";

/** The fields the views read, so a test builds one without a protobuf message. */
export type UpgradeFacts = Pick<
  UpgradeRecord,
  "phase" | "reason" | "targetVersion" | "previousVersion" | "automatic" | "requestedBy" | "databaseRestored" | "databaseKept"
>;

/** How an outcome reads: its colour and what it says. */
export interface OutcomeView {
  tone: "green" | "yellow" | "red";
  title: string;
  detail: string;
}

const IN_PROGRESS = new Set<UpgradePhase>([
  UpgradePhase.DOWNLOADING,
  UpgradePhase.REQUESTED,
  UpgradePhase.INSTALLING,
  UpgradePhase.RESTARTING,
  UpgradePhase.ROLLING_BACK,
]);

const ROLLBACK_REASONS = new Set<UpgradeReason>([
  UpgradeReason.REQUESTED,
  UpgradeReason.NO_PREVIOUS,
  UpgradeReason.NEEDS_RESTORE,
  UpgradeReason.PREVIOUS_NOT_READY,
]);

/** The record is of a rollback somebody asked for (ADR 0104), not of an install. */
export const isRollback = (r: Pick<UpgradeFacts, "reason">): boolean => ROLLBACK_REASONS.has(r.reason);

/** An install is running: the page asks again every couple of seconds. */
export const upgradeInProgress = (phase: UpgradePhase | undefined): boolean => phase !== undefined && IN_PROGRESS.has(phase);

/** The steps of an install, in order. The helper is the root-owned unit. */
export const UPGRADE_STEPS = [
  { label: "Download", description: "Fetch the release and check its signature and checksum" },
  { label: "Hand over", description: "The root-owned helper checks both again" },
  { label: "Install", description: "Replace the binary; the old one is kept" },
  { label: "Restart", description: "Start the new version and wait until it is ready" },
] as const;

const ACTIVE_STEP: Partial<Record<UpgradePhase, number>> = {
  [UpgradePhase.DOWNLOADING]: 0,
  [UpgradePhase.REQUESTED]: 1,
  [UpgradePhase.INSTALLING]: 2,
  [UpgradePhase.RESTARTING]: 3,
  [UpgradePhase.ROLLING_BACK]: 3,
  [UpgradePhase.SUCCEEDED]: UPGRADE_STEPS.length,
};

/** The steps of a rollback. Nothing is downloaded: the previous version is already on the host. */
export const ROLLBACK_STEPS = [
  { label: "Hand over", description: "The root-owned helper checks which version it kept" },
  { label: "Put back", description: "Replace the binary with the previous version" },
  { label: "Restart", description: "Start the previous version and wait until it is ready" },
] as const;

const ROLLBACK_STEP: Partial<Record<UpgradePhase, number>> = {
  [UpgradePhase.REQUESTED]: 0,
  [UpgradePhase.ROLLING_BACK]: 2,
  [UpgradePhase.RESTARTING]: 2,
  [UpgradePhase.ROLLED_BACK]: ROLLBACK_STEPS.length,
};

/** The steps the record is going through. */
export const stepsOf = (r: Pick<UpgradeFacts, "reason">) => (isRollback(r) ? ROLLBACK_STEPS : UPGRADE_STEPS);

/** Which step is under way; every step before it is done. */
export const activeStep = (r: Pick<UpgradeFacts, "phase" | "reason">): number =>
  (isRollback(r) ? ROLLBACK_STEP[r.phase] : ACTIVE_STEP[r.phase]) ?? 0;

/** What a rollback somebody asked for is doing right now. */
function rollbackNote(r: UpgradeFacts): string {
  const previous = `v${r.previousVersion}`;
  switch (r.phase) {
    case UpgradePhase.REQUESTED:
      return `Waiting for the upgrade helper to put ${previous} back.`;
    case UpgradePhase.ROLLING_BACK:
      return `The gateway is restarting on ${previous}. This page reconnects by itself.`;
    case UpgradePhase.RESTARTING:
      return `${previous} did not become ready. Putting v${r.targetVersion} back.`;
    default:
      return "";
  }
}

/** What the gateway is doing right now, in one sentence. */
export function progressNote(r: UpgradeFacts): string {
  if (isRollback(r)) return rollbackNote(r);
  const target = `v${r.targetVersion}`;
  switch (r.phase) {
    case UpgradePhase.DOWNLOADING:
      return `Downloading ${target} and checking its signature.`;
    case UpgradePhase.REQUESTED:
      return `${target} is verified. Waiting for the upgrade helper to pick it up.`;
    case UpgradePhase.INSTALLING:
      return `The helper is checking ${target} again and replacing the binary.`;
    case UpgradePhase.RESTARTING:
      return `The gateway is restarting on ${target}. This page reconnects by itself; connections are refused for a few seconds.`;
    case UpgradePhase.ROLLING_BACK:
      return `${target} did not become ready. Putting v${r.previousVersion} back.`;
    default:
      return "";
  }
}

const REFUSALS: Partial<Record<UpgradeReason, string>> = {
  [UpgradeReason.SIGNATURE]:
    "The release list is not signed by a Gateon release key. If you use a mirror, check that it copies checksums.txt and checksums.txt.sig unmodified.",
  [UpgradeReason.CHECKSUM]: "The downloaded archive is not the file the signed release list names. Try again; if it repeats, the release source is serving a different file.",
  [UpgradeReason.MALFORMED]: "The release source sent something that is not a Gateon release for this machine.",
  [UpgradeReason.NOT_NEWER]: "That release is not newer than the installed one. A downgrade is only done at a root shell: sudo gateon upgrade --version <version> --allow-downgrade.",
  [UpgradeReason.NO_KEY]: "This build has no release key, so it cannot verify a release and will not install one.",
  [UpgradeReason.INSTALL]: "The helper could not write the new binary. The system journal has the reason: journalctl -u gateon-upgrade.",
  [UpgradeReason.DOWNLOAD]: "The release could not be downloaded. Check that this host can reach the release source, then try again.",
  [UpgradeReason.HELPER]: "The upgrade helper did not pick the request up. Enable it with: sudo systemctl enable --now gateon-upgrade.path",
};

/** A rollback says what became of the database, because that is the part an administrator cannot see. */
function rolledBackDetail(r: UpgradeFacts, target: string, previous: string): string {
  const again = `${target} did not become ready, so ${previous} is running again`;
  if (r.databaseKept) {
    return `${again}. ${target} had already updated the database, and that was left as it is: ${target} only adds to what ${previous} reads, so ${previous} runs on it. It will not be installed automatically again.`;
  }
  if (r.databaseRestored) {
    return `${again} and the database was put back to the copy taken before the upgrade. What ${target} wrote is kept beside it.`;
  }
  return `${again}. Nothing else was changed. It will not be installed automatically again.`;
}

/** How a rollback somebody asked for ended. Null while it is running. */
function rollbackOutcome(r: UpgradeFacts, target: string, previous: string): OutcomeView | null {
  if (upgradeInProgress(r.phase)) return null;
  switch (r.reason) {
    case UpgradeReason.REQUESTED:
      return {
        tone: "green",
        title: `Rolled back to ${previous}`,
        detail: `The gateway restarted on ${previous} and reported ready. ${
          r.databaseRestored
            ? `The database was put back to the copy taken before the upgrade, and what was written since is kept beside it.`
            : `The database was left as it is.`
        } ${target} will not be installed automatically again; you can still install it from here.`,
      };
    case UpgradeReason.NO_PREVIOUS:
      return {
        tone: "red",
        title: "Not rolled back",
        detail:
          "There is no previous version on this host to go back to. The helper keeps the version the last upgrade replaced, until it is rolled back. Nothing on this host was changed.",
      };
    case UpgradeReason.NEEDS_RESTORE:
      return {
        tone: "red",
        title: "Not rolled back",
        detail: `${target} changed the database in a way ${previous} was never tested on, so going back means putting the database copy back as well. That discards what was written since the upgrade and is only done on the host: sudo gateon upgrade --rollback --restore-database. Nothing on this host was changed.`,
      };
    default:
      return {
        tone: "red",
        title: `${previous} did not become ready`,
        detail: `So ${target} was put back and is running, as it was before. The reason is in the system journal on the host: journalctl -u gateon.`,
      };
  }
}

/** What the card says about a finished install. Null while one is running, or when there has been none. */
export function outcomeView(r: UpgradeFacts): OutcomeView | null {
  const target = `v${r.targetVersion}`;
  const previous = `v${r.previousVersion}`;
  if (isRollback(r)) return rollbackOutcome(r, target, previous);
  switch (r.phase) {
    case UpgradePhase.SUCCEEDED:
      return {
        tone: "green",
        title: `Upgraded to ${target}`,
        detail: `The gateway restarted on ${target} and reported ready. ${previous} is kept on this host in case you need it.`,
      };
    case UpgradePhase.ROLLED_BACK:
      return {
        tone: "yellow",
        title: `${target} was rolled back`,
        detail: rolledBackDetail(r, target, previous),
      };
    case UpgradePhase.REFUSED:
      return {
        tone: "red",
        title: `${target} was not installed`,
        detail: `${REFUSALS[r.reason] ?? "The release was refused."} Nothing on this host was changed.`,
      };
    case UpgradePhase.FAILED:
      return {
        tone: "red",
        title: `${target} is installed and is not ready`,
        detail:
          r.reason === UpgradeReason.MIGRATED
            ? `${target} changed the database before it failed, and that cannot be undone automatically, so ${previous} was not put back. See doc/self-upgrade.md for restoring by hand.`
            : `${target} did not become ready and ${previous} could not be put back. Run sudo gateon upgrade --version ${r.previousVersion} --allow-downgrade on the host.`,
      };
    default:
      return null;
  }
}

const OUTCOMES: Partial<Record<UpgradePhase, string>> = {
  [UpgradePhase.SUCCEEDED]: "Installed",
  [UpgradePhase.ROLLED_BACK]: "Rolled back",
  [UpgradePhase.REFUSED]: "Not installed",
  [UpgradePhase.FAILED]: "Failed, not rolled back",
};

const ROLLBACK_OUTCOMES: Partial<Record<UpgradeReason, string>> = {
  [UpgradeReason.REQUESTED]: "Rolled back on request",
  [UpgradeReason.NO_PREVIOUS]: "Rollback refused",
  [UpgradeReason.NEEDS_RESTORE]: "Rollback refused",
  [UpgradeReason.PREVIOUS_NOT_READY]: "Rollback failed",
};

/** A few words for the history table. */
export const outcomeLabel = (r: Pick<UpgradeFacts, "phase" | "reason">): string =>
  (isRollback(r) ? ROLLBACK_OUTCOMES[r.reason] : OUTCOMES[r.phase]) ?? "In progress";

/** Which way the versions went, for the history table: a rollback reads backwards. */
export const versionChange = (r: UpgradeFacts): string =>
  isRollback(r) ? `v${r.targetVersion} back to v${r.previousVersion}` : `v${r.previousVersion} to v${r.targetVersion}`;

/** The version a finished record left running, or null when it left things as they were or is not finished. */
export function landedOn(r: UpgradeFacts): string | null {
  if (r.phase === UpgradePhase.SUCCEEDED) return r.targetVersion;
  if (r.phase === UpgradePhase.ROLLED_BACK && r.reason === UpgradeReason.REQUESTED) return r.previousVersion;
  return null;
}

/** The command that rolls back together with the database copy. It is only run on the host. */
export const ROLLBACK_RESTORE_COMMAND = "sudo gateon upgrade --rollback --restore-database";

/** Who started an install, for the history table. */
export const startedBy = (r: UpgradeFacts): string => (r.automatic ? "Automatic" : r.requestedBy || "Unknown");

/** Why this gateway has no Upgrade button, and what to do instead. Null when it has one. */
export function blockerNote(blocker: UpgradeBlocker): { text: string; command?: string } | null {
  switch (blocker) {
    case UpgradeBlocker.UNSPECIFIED:
      return null;
    case UpgradeBlocker.NO_HELPER:
      return {
        text: "This gateway can install the release itself once its upgrade helper is enabled. Run this on the host once, then use Upgrade now here:",
        command: "sudo systemctl enable --now gateon-upgrade.path",
      };
    case UpgradeBlocker.NO_KEY:
      return { text: "This build has no release key, so it cannot verify a release and will not install one. Install a release build to upgrade from here." };
    case UpgradeBlocker.DEVELOPMENT_BUILD:
      return { text: "This is a development build, which cannot be compared with a release, so it is not upgraded from here." };
    default:
      // Orchestrated: the status card already says how that install takes a version.
      return null;
  }
}

/** The scopes an automatic install can be held to, narrowest first. */
export const SCOPE_OPTIONS = [
  { value: String(UpdateScope.PATCH), label: "Patch releases only (1.8.2 to 1.8.3)" },
  { value: String(UpdateScope.MINOR), label: "Minor releases too (1.8 to 1.9)" },
  { value: String(UpdateScope.MAJOR), label: "Any newer release (1.x to 2.0)" },
];

const HHMM = /^([01]\d|2[0-3]):[0-5]\d$/;

/** What is wrong with a maintenance window as typed, or null. Both ends or neither. */
export function windowError(start: string, end: string): string | null {
  if (!start && !end) return null;
  if (!start || !end) return "Give both a start and an end, or leave both empty.";
  if (!HHMM.test(start) || !HHMM.test(end)) return "Write each time as HH:MM, such as 02:00.";
  return null;
}

/** Why this rollback has no button, said before the command for the host. */
export const rollbackOnHostNote = (current: string, previous: string): string =>
  `v${previous}, the version before the last upgrade, is kept on this host. v${current} changed the database in a way v${previous} was never tested on, so going back also puts back the database copy taken before the upgrade and sets aside what was written since. That is only done on the host:`;
