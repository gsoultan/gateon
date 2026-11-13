// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import {
  InstallKind,
  UpdateCheckState,
  UpdateFailure,
  UpdateSignature,
  type UpdateStatus,
} from "../../../services/gen/gateon/v1/status_pb";

/** How the status card reads: its colour and what it says. */
export interface UpdateView {
  tone: "blue" | "green" | "yellow" | "red" | "gray";
  title: string;
  detail: string;
}

/** The fields the view reads, so a test builds one without a protobuf message. */
export type UpdateFacts = Pick<
  UpdateStatus,
  "currentVersion" | "latestVersion" | "updateAvailable" | "signature" | "state" | "failure" | "disabledByEnv" | "releaseBuild"
>;

const FAILURES: Record<number, { title: string; detail: string; tone: UpdateView["tone"] }> = {
  [UpdateFailure.UNREACHABLE]: {
    tone: "yellow",
    title: "Couldn't check for updates",
    detail: "The release source didn't answer. Gateon tries again at the next daily check, or you can use Check now.",
  },
  [UpdateFailure.SIGNATURE]: {
    tone: "red",
    title: "The release list was refused",
    detail:
      "It is not signed by a Gateon release key, so nothing it says is shown here. If you use a mirror, check that it copies checksums.txt and checksums.txt.sig unmodified.",
  },
  [UpdateFailure.MALFORMED]: {
    tone: "yellow",
    title: "The release source sent something else",
    detail: "What it answered is not a Gateon release list. Check the release source below.",
  },
  [UpdateFailure.SOURCE]: {
    tone: "red",
    title: "The release source can't be used",
    detail: "It must be an https:// address, or http:// on this host's loopback for a local mirror. Change it below, or in GATEON_UPDATE_SOURCE.",
  },
};

const signatureNote = (s: UpdateFacts): string =>
  s.signature === UpdateSignature.VERIFIED
    ? "The release list is signed by a Gateon release key."
    : "This build has no release key, so the release list could not be verified.";

/**
 * What the Software update card says for a status. One function, so every
 * state the gateway can report has words, and a test can hold them.
 */
export function updateView(s: UpdateFacts): UpdateView {
  if (s.state === UpdateCheckState.DISABLED) {
    return {
      tone: "gray",
      title: "Update checks are off",
      detail: s.disabledByEnv
        ? "GATEON_UPDATE_CHECK turns them off on this host, so this gateway never asks whether a newer version exists."
        : "This gateway does not ask whether a newer version exists. Turn the daily check on below.",
    };
  }
  const latest = s.latestVersion ? `v${s.latestVersion}` : "";
  if (s.updateAvailable && latest) {
    return { tone: "blue", title: `Gateon ${latest} is available`, detail: signatureNote(s) };
  }
  if (s.state === UpdateCheckState.FAILED && !latest) {
    return FAILURES[s.failure] ?? FAILURES[UpdateFailure.UNREACHABLE];
  }
  if (!latest) {
    return {
      tone: "gray",
      title: "Not checked yet",
      detail: "The first check runs about a minute after the gateway starts. Use Check now to ask straight away.",
    };
  }
  if (!s.releaseBuild) {
    return {
      tone: "gray",
      title: `The newest release is ${latest}`,
      detail: `This gateway runs a development build (${s.currentVersion || "unversioned"}), which can't be compared with a release. ${signatureNote(s)}`,
    };
  }
  return { tone: "green", title: "You're up to date", detail: `${latest} is the newest release. ${signatureNote(s)}` };
}

/** A note under the card when the last check failed but an earlier answer is still shown. */
export function staleNote(s: UpdateFacts): string | null {
  if (s.state !== UpdateCheckState.FAILED || !s.latestVersion) return null;
  return "The last check didn't get an answer, so this is what an earlier check found.";
}

const KINDS: Record<number, string> = {
  [InstallKind.SYSTEMD]: "systemd service",
  [InstallKind.CONTAINER]: "container",
  [InstallKind.KUBERNETES]: "Kubernetes",
};

export const installKindLabel = (kind: InstallKind): string => KINDS[kind] ?? "standalone binary";

/** How this kind of install takes a new version, in one sentence and, for an image, a command. */
export function upgradeSteps(kind: InstallKind, latestVersion: string): { text: string; command?: string } {
  switch (kind) {
    case InstallKind.KUBERNETES:
      return {
        text: "This gateway runs in Kubernetes, so the chart decides which image runs. Set image.tag in your Helm values and upgrade the release:",
        command: `helm upgrade <release> <chart> --reuse-values --set image.tag=${latestVersion}`,
      };
    case InstallKind.CONTAINER:
      return {
        text: "This gateway runs in a container, so whatever started the container decides which image runs. Pull the new image there and recreate the container:",
        command: `docker pull ghcr.io/gsoultan/gateon:${latestVersion}`,
      };
    case InstallKind.SYSTEMD:
      return {
        text: "Download the package for this host from the release page and install it over the current one. The service is restarted on the new version. Read the release notes first: they list every change that needs action.",
      };
    default:
      return {
        text: "Download the archive for this host from the release page, replace the gateon binary and restart it. Read the release notes first: they list every change that needs action.",
      };
  }
}

/** "3 minutes ago", from Unix seconds. Empty when no check has finished. */
export function checkedAgo(checkedAt: bigint, nowMs: number): string {
  const at = Number(checkedAt) * 1000;
  if (!at) return "";
  const minutes = Math.max(0, Math.round((nowMs - at) / 60000));
  if (minutes < 1) return "a moment ago";
  if (minutes < 60) return `${minutes} ${minutes === 1 ? "minute" : "minutes"} ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours} ${hours === 1 ? "hour" : "hours"} ago`;
  return `${Math.round(hours / 24)} days ago`;
}
