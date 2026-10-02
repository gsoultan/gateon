// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { isSecretReference, isStoredSecret } from "../../utils/storedSecret";

/**
 * What the auth middleware form must refuse before it saves, said the way the
 * gateway refuses it (ADR 0043). The gateway is the authority -- it refuses the
 * same configs on every transport -- but a form that lets one through only to
 * be refused, or that saves a hole the gateway once accepted, is the defect.
 */

export type BasicUser = { name: string; password: string };

/** The basic-auth user list, "name:password,...", as rows. */
export function parseUsers(value: string): BasicUser[] {
  return value
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean)
    .map((part) => {
      const at = part.indexOf(":");
      return at < 0 ? { name: part, password: "" } : { name: part.slice(0, at), password: part.slice(at + 1) };
    });
}

export const joinUsers = (users: BasicUser[]) => users.map((u) => `${u.name}:${u.password}`).join(",");

export const EMPTY_PASSWORD =
  "Enter a password. A user with no password lets anyone in under this name.";

/**
 * Why a basic-auth user cannot be saved, or undefined. A stored password is
 * shown as the placeholder and kept by name (ADR 0033), so it counts as set.
 */
export function basicUserProblem(user: BasicUser): string | undefined {
  if (!user.name.trim()) return "Enter a user name.";
  if (!user.password.trim()) return EMPTY_PASSWORD;
  return undefined;
}

export const AUDIENCE_REQUIRED =
  "Required. The identity provider signs tokens for every application it serves; without an audience " +
  "this route accepts a token issued to any of them.";

/** Whether this auth config verifies tokens with a provider's published keys. */
function verifiesWithProviderKeys(config: Record<string, string>): boolean {
  const type = config.type || "jwt";
  return type === "oidc" || (type === "jwt" && !!(config.jwks_url || "").trim());
}

/** Why the audience cannot be left as it is, or undefined. */
export function audienceProblem(config: Record<string, string>): string | undefined {
  if (!verifiesWithProviderKeys(config)) return undefined;
  if ((config.audience || "").trim() || config.allow_any_audience === "true") return undefined;
  return AUDIENCE_REQUIRED;
}

/** The first reason this auth middleware config cannot be saved, or undefined. */
export function authConfigProblem(config: Record<string, string>): string | undefined {
  if ((config.type || "jwt") === "basic") {
    const users = config.users || "";
    if (users && !isStoredSecret(users) && !isSecretReference(users)) {
      for (const u of parseUsers(users)) {
        const problem = basicUserProblem(u);
        if (problem) return u.name.trim() ? `User "${u.name}": ${problem}` : problem;
      }
    }
    return undefined;
  }
  const audience = audienceProblem(config);
  return audience ? `Audience: ${audience}` : undefined;
}
