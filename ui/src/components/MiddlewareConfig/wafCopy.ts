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
  "against the client that received the page." +
  " A response that shows an exploit worked (an account file, command output, a cloud role credential) " +
  "is refused whole under Redact too: cutting two lines out of it would send the rest.";

/** The OpenAPI document field on a route WAF. */
export const OPENAPI_SPEC_HELP =
  "An OpenAPI 3 document (YAML or JSON) for the API behind this route. Requests to a path and method " +
  "it describes are checked against the parameter types, formats, enums, lengths and ranges it declares. " +
  "A path it does not describe is not checked. Leave empty for no check.";

/** The OpenAPI mode select: what each choice does to a request outside the document. */
export const OPENAPI_MODE_HELP =
  "Record first: published documents are usually narrower than the traffic an API really serves. " +
  "Recorded requests are forwarded, counted, and listed in the Security Hub under api_schema. " +
  "A refused request is not held against the client: no reputation penalty, no automatic block.";

/** Shown when the route is audit-only and the document is set to enforce. */
export const OPENAPI_AUDIT_ONLY_NOTE =
  "Audit Only is on for this route, so requests outside the document are recorded and not refused.";

/** The largest document the gateway accepts, in bytes (apischema.MaxDocumentBytes). */
export const OPENAPI_MAX_BYTES = 1 << 20;

/** Under the WebSocket inspection switch. */
export const WEBSOCKET_INSPECTION_HELP =
  "Check every message a client sends on a WebSocket this route upgrades, as a request body is checked. " +
  "A message the WAF refuses closes the connection (code 1008) and never reaches the backend. " +
  "With this on, compression (permessage-deflate) is not offered to the backend, because a compressed " +
  "message cannot be read, and the route carries WebSocket only: any other upgraded protocol is closed. " +
  "Messages the backend sends are not inspected.";

/** Under the WebSocket message limit. */
export const WEBSOCKET_LIMIT_HELP =
  "Largest message, in bytes, held for inspection. A larger one closes the connection (code 1009), " +
  "so padding a message does not get it past the WAF. 0 uses the gateway default for its resource profile " +
  "(16 KiB minimal, 64 KiB standard, 256 KiB enterprise). Never more than the request body limit.";

/** Shown when the route is audit-only and WebSocket inspection is on. */
export const WEBSOCKET_AUDIT_ONLY_NOTE =
  "Audit Only is on for this route, so a message the WAF would refuse is recorded and forwarded, " +
  "and a message past the limit is forwarded unread.";
