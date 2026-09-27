// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

/**
 * The fields of one line of the gateway's log, as the Logs page filters them.
 *
 * The gateway writes JSON or slog's text format depending on log.format, and
 * text is what an install gets unless it asks for JSON or runs with
 * ENV=production. The page's route, status and client filters used to read
 * fields from JSON only, so on a text-format gateway choosing any of them hid
 * every line, and the route list was always empty. They also looked for the
 * client under names the gateway never writes (ip, remoteAddr, clientIp) and
 * matched "5xx" -- the example in the status box -- literally.
 */
export type LogFields = Record<string, string>;

const QUOTE = '"';
const BACKSLASH = "\\";
const ESCAPES: Record<string, string> = { n: "\n", t: "\t", r: "\r", [QUOTE]: QUOTE, [BACKSLASH]: BACKSLASH };

/** Reads a double-quoted value starting at `start`; returns it and the index after the closing quote. */
function readQuoted(line: string, start: number): [string, number] | null {
  let out = "";
  for (let i = start + 1; i < line.length; i++) {
    const c = line[i];
    if (c === QUOTE) return [out, i + 1];
    if (c === BACKSLASH && i + 1 < line.length) {
      const next = line[i + 1] ?? "";
      out += ESCAPES[next] ?? c + next;
      i++;
      continue;
    }
    out += c;
  }
  return null;
}

/**
 * Parses a slog text-format (logfmt) line into its fields. Returns null for
 * anything that is not a sequence of key=value pairs, such as a Go panic or a
 * line some library printed on its own.
 */
export function parseLogfmt(line: string): LogFields | null {
  const text = line.trim();
  const fields: LogFields = {};
  let i = 0;
  while (i < text.length) {
    if (text[i] === " ") {
      i++;
      continue;
    }
    const eq = text.indexOf("=", i);
    const space = text.indexOf(" ", i);
    if (eq <= i || (space !== -1 && space < eq)) return null;
    const key = text.slice(i, eq);
    if (text[eq + 1] === QUOTE) {
      const quoted = readQuoted(text, eq + 1);
      if (!quoted) return null;
      [fields[key], i] = quoted;
    } else {
      const end = text.indexOf(" ", eq + 1);
      fields[key] = text.slice(eq + 1, end === -1 ? text.length : end);
      i = end === -1 ? text.length : end;
    }
  }
  return Object.keys(fields).length > 0 ? fields : null;
}

/** The fields of a JSON or text-format line, every value as a string. */
export function logFields(raw: string, json: Record<string, unknown> | null): LogFields | null {
  if (!json) return parseLogfmt(raw);
  const fields: LogFields = {};
  for (const [key, value] of Object.entries(json)) {
    fields[key] = typeof value === "string" ? value : JSON.stringify(value);
  }
  return fields;
}

/** The route a line is about, under either name the gateway has used. */
export function routeOf(fields: LogFields): string {
  return (fields.route ?? fields.routeId ?? "").trim();
}

/** Whether a line's status matches "404", a prefix such as "4", or a class such as "4xx". */
export function statusMatches(fields: LogFields, filter: string): boolean {
  const status = fields.status ?? "";
  const cls = /^([1-5])xx$/i.exec(filter.trim());
  if (cls) return status.length === 3 && status[0] === cls[1];
  return status.startsWith(filter.trim());
}

// The access log writes the resolved client as "client" and the TCP peer as
// "remote_addr"; the other names are what the page used to look for.
const CLIENT_KEYS = ["client", "remote_addr", "ip", "remoteAddr", "clientIp"];

/** Whether any of a line's client addresses contains the filter. */
export function clientMatches(fields: LogFields, filter: string): boolean {
  const want = filter.trim().toLowerCase();
  return CLIENT_KEYS.some((key) => (fields[key] ?? "").toLowerCase().includes(want));
}
