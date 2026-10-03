// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// What audit-only and DLP do to the client, in the words ADR 0055 settles on.
// The route editor and the global WAF card show the same text.

/** The route WAF's "Audit Only" switch. */
export const AUDIT_ONLY_HELP =
  "Record matched rules and block nothing on this route. Matches are counted as would-block and never " +
  "count against the client: no reputation penalty, no automatic block, no incident.";

/** The global WAF card, when the global WAF is audit-only. */
export const GLOBAL_AUDIT_ONLY_HELP =
  "The global WAF records what it would block and lets every request through. Its matches never count " +
  "against a client: no reputation penalty, no automatic block, no incident.";

/** The DLP action select, on a route WAF and on the global card. */
export const DLP_ACTION_HELP =
  "Roll out in stages: watch first, then redact, then block once the false-positive rate is known. " +
  "A leak is the backend's data: it is recorded on the route as a data exposure and never counts " +
  "against the client that received the page.";
