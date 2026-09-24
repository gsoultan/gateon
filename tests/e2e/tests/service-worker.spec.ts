// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test, expect, type Page } from '@playwright/test';

/**
 * The dashboard's service worker is scoped to "/" on the management origin, and
 * that origin also serves the API, /healthz, Prometheus' /metrics and — whenever
 * a route shadows a path on the management entrypoint — proxied applications.
 * Anything the worker answers from its own cache never reaches the server, so it
 * is answered without the server's authentication, freshness or content.
 *
 * It used to hold two such rules. A stale-while-revalidate cache over
 * /v1/config* returned the previous export when an operator took a backup, and
 * kept serving the full configuration after logout. A catch-all navigation
 * fallback answered every page load on the origin with its install-time copy of
 * index.html: /healthz rendered the dashboard, and every page load reused one
 * CSP nonce that the server means to issue per response.
 *
 * Each test logs in for itself, as the rbac specs do.
 */
test.use({ storageState: { cookies: [], origins: [] } });
test.setTimeout(120000);

const ADMIN = { username: 'admin', password: 'password123' };

async function login(page: Page) {
  const res = await page.request.post('/v1/login', { data: ADMIN });
  expect(res.ok(), `login failed: ${res.status()}`).toBe(true);
}

/** Loads the dashboard and waits until the service worker controls the page. */
async function controlledByWorker(page: Page) {
  await page.goto('/login');
  await page.evaluate(() => navigator.serviceWorker.ready.then(() => true));
  if (!(await page.evaluate(() => !!navigator.serviceWorker.controller))) {
    await page.reload();
  }
  expect(
    await page.evaluate(() => !!navigator.serviceWorker.controller),
    'the page is not controlled by the service worker, so this test would pass without exercising it',
  ).toBe(true);
}

/** Exports the configuration the way the Settings card does: a fetch from the page. */
async function exportedServiceIds(page: Page): Promise<{ status: number; ids: string[] }> {
  return page.evaluate(async () => {
    const r = await fetch('/v1/config/export');
    if (!r.ok) return { status: r.status, ids: [] };
    const body = await r.json();
    return { status: r.status, ids: (body.services || []).map((s: { id: string }) => s.id) };
  });
}

test('a config export reflects the configuration at the moment it is taken', async ({ page }) => {
  await controlledByWorker(page);
  await login(page);
  const id = `svc-export-${Date.now()}`;

  const before = await exportedServiceIds(page);
  expect(before.status).toBe(200);
  expect(before.ids).not.toContain(id);

  const saved = await page.request.put('/v1/services', {
    data: { id, name: id, weightedTargets: [{ url: 'http://127.0.0.1:9', weight: 1 }] },
  });
  expect(saved.ok(), `saving the probe service failed: ${saved.status()}`).toBe(true);

  try {
    const after = await exportedServiceIds(page);
    expect(
      after.ids,
      'the export taken after the change is missing it: the backup is the previous export, served from a cache',
    ).toContain(id);
  } finally {
    await page.request.delete(`/v1/services/${encodeURIComponent(id)}`);
  }
});

test('nothing the API returned is readable from the page after logout', async ({ page }) => {
  await controlledByWorker(page);
  await login(page);
  expect((await exportedServiceIds(page)).status).toBe(200);

  const out = await page.request.post('/v1/logout');
  expect(out.ok()).toBe(true);

  const afterLogout = await exportedServiceIds(page);
  expect(
    afterLogout.status,
    'the configuration export, credentials included, was still served to the page after logout',
  ).toBe(401);
});

test('an export cached by the old service worker is removed when the dashboard loads', async ({ page }) => {
  // Workbox clears outdated precaches on upgrade, not runtime caches, so a
  // browser that ran the old worker keeps its copy of the export until the
  // dashboard deletes it. Seed that copy, then load the dashboard.
  await page.goto('/login');
  await page.evaluate(async () => {
    const cache = await caches.open('gateon-config-cache');
    await cache.put('/v1/config/export', new Response('{"services":[]}'));
  });
  expect(await page.evaluate(() => caches.has('gateon-config-cache')), 'seeding the old cache failed').toBe(true);

  await page.reload();
  await expect
    .poll(() => page.evaluate(() => caches.has('gateon-config-cache')), {
      message: "the old worker's cached config export survived a dashboard load",
    })
    .toBe(false);
});

test('the service worker answers no navigation to a resource that is not the dashboard', async ({ page }) => {
  await controlledByWorker(page);

  const res = await page.goto('/healthz');
  expect(res, 'no response for /healthz').not.toBeNull();
  expect(res!.fromServiceWorker(), '/healthz was answered by the service worker, not the gateway').toBe(false);
  expect((await page.content()).includes('<div id="root">'), '/healthz rendered the dashboard shell').toBe(false);
});

test('every page load gets its own CSP nonce', async ({ page }) => {
  await controlledByWorker(page);

  const nonce = async () => {
    await page.goto('/login');
    return page.evaluate(() => document.querySelector('script[nonce]')?.nonce ?? '');
  };
  const first = await nonce();
  const second = await nonce();
  expect(first, 'the page carried no nonce, so this compares nothing').not.toBe('');
  expect(second, 'two page loads reused one CSP nonce').not.toBe(first);
});
