// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Code, ConnectError } from "@connectrpc/connect";

/**
 * What the API Tokens page shows and says (ADR 0050). A token is a long-lived,
 * scoped credential for a machine -- today, Prometheus scraping /metrics --
 * that an administrator issues and revokes. Its secret is shown once.
 */

/** The scopes a token can be issued with, as the gateway names them. */
export const TOKEN_SCOPES = [{ value: "metrics:read", label: "Read metrics (GET /metrics)" }] as const;

export const TOKEN_EXPIRY_OPTIONS = [
  { value: "0", label: "Never -- until revoked" },
  { value: "30", label: "30 days" },
  { value: "90", label: "90 days" },
  { value: "365", label: "1 year" },
];

/** The longest name the gateway accepts. */
export const TOKEN_NAME_MAX = 64;

/** A token as the page lists it. */
export interface TokenRow {
  id: string;
  name: string;
  scopes: string[];
  hint: string;
  createdBy: string;
  createdAt: string;
  lastUsedAt: string;
  expiresAt: string;
}

/** What is wrong with a token name, or null. */
export function tokenNameError(name: string): string | null {
  const n = name.trim();
  if (n === "") return "Give the token a name, such as the scraper that will use it";
  if (n.length > TOKEN_NAME_MAX) return `Use at most ${TOKEN_NAME_MAX} characters`;
  return null;
}

/** Whether the token has expired at now. */
export function isExpired(row: Pick<TokenRow, "expiresAt">, now: Date): boolean {
  if (!row.expiresAt) return false;
  const t = new Date(row.expiresAt).getTime();
  return !Number.isNaN(t) && t <= now.getTime();
}

/** An RFC 3339 time for a table cell, or `none` when there is none. */
export function formatTokenTime(iso: string, none: string): string {
  if (!iso) return none;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

/** A refused token request, in the dashboard's words. */
export function tokenRefusalMessage(err: unknown): string {
  const code = err instanceof ConnectError ? err.code : undefined;
  switch (code) {
    case Code.InvalidArgument:
      return `Give the token a name of up to ${TOKEN_NAME_MAX} characters and at least one scope.`;
    case Code.ResourceExhausted:
      return "There are already 50 API tokens. Revoke one before creating another.";
    case Code.PermissionDenied:
      return "Only an administrator can manage API tokens.";
    case Code.NotFound:
      return "That token no longer exists; it may already have been revoked.";
    case Code.Unavailable:
      return "API tokens are unavailable until setup has finished.";
    default:
      return "The request could not be completed. Please try again.";
  }
}

/**
 * The Prometheus job that scrapes the gateway with a token kept in a file
 * only Prometheus can read.
 */
export function prometheusJob(target: string): string {
  return [
    "- job_name: gateon",
    "  authorization:",
    "    credentials_file: /etc/prometheus/gateon.token",
    "  static_configs:",
    `    - targets: ["${target}"]`,
  ].join("\n");
}
