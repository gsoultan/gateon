// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test, expect, type APIRequestContext } from '@playwright/test';

/**
 * "IP Reputation -- sync with threat feeds to block known malicious actors"
 * loaded a feed and refused no one: only a WAF rule behind the WAF's own,
 * separate switch read it (truth T3). A listed address is now refused on every
 * route, with or without a WAF (ADR 0044). The harness trusts X-Forwarded-For
 * from loopback, so a request can speak for a listed address; the feed lists
 * documentation ranges only.
 */

const PROXY = 'http://localhost:8081';
const FEED = 'http://127.0.0.1:8082/reputation-feed.txt';

type Global = Record<string, unknown> & { securityAdvanced?: Record<string, unknown> };

async function adminApi(playwright: { request: { newContext: (o: object) => Promise<APIRequestContext> } }) {
  return playwright.request.newContext({ baseURL: 'http://localhost:8080', storageState: 'tests/.auth/admin.json' });
}

async function statusFrom(request: APIRequestContext, address: string): Promise<number> {
  const res = await request.get(`${PROXY}/test/reputation-feed-probe`, { headers: { 'X-Forwarded-For': address } });
  return res.status();
}

test.describe('IP reputation feed', () => {
  let snapshot: Global | undefined;

  test.afterAll(async ({ playwright }) => {
    if (!snapshot) return;
    const api = await adminApi(playwright);
    try {
      const res = await api.put('/v1/global', { data: snapshot });
      expect(res.ok(), `restoring the configuration: ${res.status()}`).toBe(true);
    } finally {
      await api.dispose();
    }
  });

  test('refuses what the feed lists, on a route with no reputation switch', async ({ playwright, request }) => {
    const api = await adminApi(playwright);
    try {
      const got = await api.get('/v1/global');
      expect(got.ok()).toBe(true);
      snapshot = (await got.json()) as Global;

      const next: Global = structuredClone(snapshot);
      next.securityAdvanced = {
        ...(next.securityAdvanced ?? {}),
        ipReputation: { enabled: true, feedUrls: [FEED], blockThreshold: 80, updateIntervalHours: 24 },
      };
      const saved = await api.put('/v1/global', { data: next });
      expect(saved.ok(), `saving the feed: ${await saved.text()}`).toBe(true);
    } finally {
      await api.dispose();
    }

    // The save starts the first fetch in the background.
    await expect.poll(() => statusFrom(request, '192.0.2.66'), { timeout: 20000 }).toBe(403);
    const refused = await request.get(`${PROXY}/test/reputation-feed-probe`, { headers: { 'X-Forwarded-For': '192.0.2.66' } });
    expect(await refused.text()).toContain('IP Reputation Feed');
    expect(await statusFrom(request, '198.51.100.7'), 'an address inside a listed range').toBe(403);
    expect(await statusFrom(request, '192.0.2.67'), 'an unlisted neighbour').toBe(200);

    // Switching the feed off takes its listings out of force at once.
    const off = await adminApi(playwright);
    try {
      const res = await off.put('/v1/global', { data: snapshot });
      expect(res.ok()).toBe(true);
    } finally {
      await off.dispose();
    }
    await expect.poll(() => statusFrom(request, '192.0.2.66'), { timeout: 20000 }).toBe(200);
  });
});
