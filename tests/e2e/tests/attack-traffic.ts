// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import type { APIRequestContext, PlaywrightWorkerArgs } from '@playwright/test';

/**
 * A client of its own for requests a spec expects the WAF to refuse.
 *
 * A WAF block counts toward mitigating the client's JA4H fingerprint, and a
 * mitigated fingerprint is refused everything. The `request` fixture presents
 * one fingerprint to every spec -- GET over HTTP/1.1 with the admin session
 * cookie, a User-Agent, no Referer and no Accept-Language, which is all JA4H
 * reads (internal/telemetry/fingerprint.go) -- so attack traffic sent through
 * it spends a budget the whole suite shares, and the spec that tips it over
 * breaks whichever spec runs next, far from the cause.
 *
 * These contexts send no cookie, and each a different combination of the two
 * headers JA4H does read, so a spec's blocks are counted against a
 * fingerprint no other spec uses. One entry per spec file that sends attack
 * traffic; add one rather than share.
 */
const FINGERPRINTS = {
  'logs-page': { Referer: 'http://e2e.invalid/logs-page' },
  'waf-rule-editor': { 'Accept-Language': 'x-e2e' },
  'security-hub-tabs': { Referer: 'http://e2e.invalid/security-hub', 'Accept-Language': 'x-e2e' },
} as const;

export type AttackerName = keyof typeof FINGERPRINTS;

export function attackerContext(
  playwright: PlaywrightWorkerArgs['playwright'],
  name: AttackerName,
): Promise<APIRequestContext> {
  return playwright.request.newContext({
    storageState: { cookies: [], origins: [] },
    extraHTTPHeaders: { ...FINGERPRINTS[name] },
  });
}
