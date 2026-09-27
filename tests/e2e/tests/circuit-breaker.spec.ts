// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test, expect, type APIRequestContext } from '@playwright/test';

/**
 * The Circuit Breaker page: every route's targets with their circuit state,
 * request and error counts, the CLOSED / OPEN / HALF-OPEN totals, and the
 * timeline of state changes.
 *
 * The fixture's targets are all healthy, so the spec brings its own service:
 * one target nothing listens on and one that answers, both health-checked over
 * TCP. The gateway marks a target down on its first failed check (the first
 * result is applied at once, pkg/proxy/health), and checks every 15 seconds.
 */

const PROXY = 'http://localhost:8081';
const DEAD = 'http://127.0.0.1:9';
const LIVE = 'http://127.0.0.1:8082';

const stamp = Date.now();
const SERVICE = `cb-e2e-svc-${stamp}`;
const ROUTE = `cb-e2e-route-${stamp}`;
const ROUTE_NAME = `CB e2e ${stamp}`;
const PREFIX = `/cb-e2e-${stamp}`;

async function admin(playwright: { request: { newContext: (o: object) => Promise<APIRequestContext> } }) {
  return playwright.request.newContext({ baseURL: 'http://localhost:8080', storageState: 'tests/.auth/admin.json' });
}

test.describe('Circuit Breaker', () => {
  test.setTimeout(120_000);

  test.beforeAll(async ({ playwright }) => {
    const api = await admin(playwright);
    try {
      const svc = await api.put('/v1/services', {
        data: {
          id: SERVICE,
          name: SERVICE,
          weightedTargets: [
            { url: DEAD, weight: 1 },
            { url: LIVE, weight: 1 },
          ],
          loadBalancerPolicy: 'round_robin',
          backendType: 'http',
          healthCheckType: 'HEALTH_CHECK_TYPE_TCP',
        },
      });
      expect(svc.ok(), `PUT /v1/services: ${svc.status()} ${await svc.text()}`).toBe(true);
      const route = await api.put('/v1/routes', {
        data: { id: ROUTE, name: ROUTE_NAME, type: 'http', rule: `PathPrefix(\`${PREFIX}\`)`, serviceId: SERVICE },
      });
      expect(route.ok(), `PUT /v1/routes: ${route.status()} ${await route.text()}`).toBe(true);
    } finally {
      await api.dispose();
    }
  });

  test.afterAll(async ({ playwright }) => {
    const api = await admin(playwright);
    try {
      await api.delete(`/v1/routes/${encodeURIComponent(ROUTE)}`);
      await api.delete(`/v1/services/${encodeURIComponent(SERVICE)}`);
    } finally {
      await api.dispose();
    }
  });

  test('shows the down target OPEN and the healthy one CLOSED, counts them, and records the change', async ({
    page,
    request,
    playwright,
  }) => {
    // A saved route goes live when the router is rebuilt, which the PUT does
    // not wait for, and the per-target counters live in the route's handler:
    // a rebuild shortly after the save starts them again at zero. So keep
    // sending traffic -- round robin gives the dead target every other request
    // -- until the gateway's own stats show an error there. That count is
    // what the page has to show.
    const api = await admin(playwright);
    let counted = 0;
    try {
      await expect
        .poll(
          async () => {
            await request.get(`${PROXY}${PREFIX}/warm`);
            const stats = (await (await api.get('/v1/routes/stats')).json()) as Record<string, { url: string; errorCount?: number }[]>;
            counted = stats[ROUTE]?.find((t) => t.url === DEAD)?.errorCount ?? 0;
            return counted;
          },
          { message: 'the gateway never counted an error on the dead target', timeout: 20_000 },
        )
        .toBeGreaterThan(0);
    } finally {
      await api.dispose();
    }

    await page.goto('/circuit-breaker');
    await expect(page.getByRole('heading', { name: 'Circuit Breaker', level: 2 })).toBeVisible();

    const targetRow = (url: string) =>
      page.getByRole('row').filter({ hasText: ROUTE_NAME }).filter({ has: page.getByRole('cell', { name: url, exact: true }) });
    const dead = targetRow(DEAD);
    const live = targetRow(LIVE);
    // One health-check interval, and a page refresh after it.
    await expect(dead, 'the target nothing listens on was never marked OPEN').toContainText('OPEN', { timeout: 60_000 });
    await expect(live).toContainText('CLOSED');
    // Columns: route, target, state, requests, errors.
    await expect
      .poll(async () => Number(await dead.getByRole('cell').nth(4).innerText()), {
        message: 'the page does not show the errors the gateway counted on the dead target',
        timeout: 15_000,
      })
      .toBeGreaterThanOrEqual(counted);

    // The OPEN total: the card's label, its number, "Failing targets".
    const openCount = page.locator('.mantine-Paper-root').filter({ hasText: 'Failing targets' }).locator('p').nth(1);
    await expect.poll(async () => Number(await openCount.innerText()), { timeout: 30_000 }).toBeGreaterThanOrEqual(1);

    const event = page
      .getByRole('row')
      .filter({ has: page.getByRole('cell', { name: DEAD, exact: true }) })
      .filter({ hasText: 'health check' });
    await expect(event.first(), 'the timeline has no event for the target going down').toContainText('OPEN', {
      timeout: 15_000,
    });

    // Only open circuits under the Open filter.
    // The label names the input and its listbox; the input is the one to click.
    await page.getByLabel('Filter by state').and(page.locator('input')).click();
    await page.getByRole('option', { name: 'Open', exact: true }).click();
    await expect(dead).toHaveCount(1);
    await expect(live, 'the Open filter kept a CLOSED target').toHaveCount(0);
  });
});
