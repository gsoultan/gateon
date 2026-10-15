// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Kept apart from hooks/api.ts so the error notifier, which the query client
// loads at startup, does not pull the generated RPC client into the first load.
import { Code, ConnectError } from "@connectrpc/connect";

/** Returns a user-friendly message for API errors (e.g. 403 insufficient permissions). */
export function getApiErrorMessage(err: unknown): string {
  // A Connect call fails with a code and a message of its own. Its `message`
  // is prefixed "[permission_denied]" and the like, which is not for people.
  if (err instanceof ConnectError) {
    if (err.code === Code.PermissionDenied) {
      return "Insufficient permissions. You do not have access to perform this action.";
    }
    return err.rawMessage || "Request failed";
  }
  const raw = err instanceof Error ? err.message : String(err ?? "");
  try {
    const data = JSON.parse(raw);
    if (
      data?.error === "insufficient permissions" ||
      data?.error === "permission denied"
    ) {
      return "Insufficient permissions. You do not have access to perform this action.";
    }
    return data?.error || raw;
  } catch {
    return raw || "Request failed";
  }
}
