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
  "phase" | "reason" | "targetVersion" | "previousVersion" | "automatic" | "requestedBy" | "databaseRestored"
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

/** Which step is under way; every step before it is done. */
export const activeStep = (phase: UpgradePhase): number => ACTIVE_STEP[phase] ?? 0;

/** What the gateway is doing right now, in one sentence. */
export function progressNote(r: UpgradeFacts): string {
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

/** What the card says about a finished install. Null while one is running, or when there has been none. */
export function outcomeView(r: UpgradeFacts): OutcomeView | null {
  const target = `v${r.targetVersion}`;
  const previous = `v${r.previousVersion}`;
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
        detail: r.databaseRestored
          ? `${target} did not become ready, so ${previous} is running again and the database was put back to the copy taken before the upgrade. What ${target} wrote is kept beside it.`
          : `${target} did not become ready, so ${previous} is running again. Nothing else was changed. It will not be installed automatically again.`,
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

/** One word or two for the history table. */
export const outcomeLabel = (phase: UpgradePhase): string => OUTCOMES[phase] ?? "In progress";

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
