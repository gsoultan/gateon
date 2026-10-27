// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test, expect, type APIRequestContext } from '@playwright/test';

/**
 * Each target's circuit, on the Services page: every service's targets with their circuit state,
 * request and error counts, the CLOSED / OPEN / HALF-OPEN totals, and the
 * timeline of state changes.
 *
 * The fixture's targets are all healthy, so the spec brings its own service:
 * one target nothing listens on and one that answers, with the health check
 * the dashboard's service form saves by default -- "Auto", no path -- which
 * checked nothing until ADR 0047 and now connects to each target. The gateway
 * marks a target down on its first failed check (the first result is applied
 * at once, pkg/proxy/health), and checks every 15 seconds.
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
          // No health check type or path: the form's default.
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

    await page.goto('/services');
    await expect(page.getByRole('heading', { name: 'Services', level: 2 })).toBeVisible();

    // The service's row sums its targets up, and opening it shows each one's
    // circuit. One health-check interval, and a stats refresh after it.
    const service = page.getByRole('row').filter({ hasText: SERVICE }).first();
    await expect(service, 'the service with one dead target of two does not read 1 of 2').toContainText('1 of 2', { timeout: 60_000 });
    await service.getByRole('button', { name: 'Show targets' }).click();
    const target = (url: string) => page.locator('.mantine-Group-root').filter({ has: page.getByText(url, { exact: true }) }).last();
    const dead = target(DEAD);
    const live = target(LIVE);
    await expect(dead, 'the target nothing listens on was never marked Down').toContainText('Down', { timeout: 60_000 });
    await expect(live).toContainText('Up');
    // The chip names the gateway's counts for the target.
    await expect
      .poll(
        async () => {
          const label = (await dead.getByLabel(/^Down:/).getAttribute('aria-label')) ?? '';
          return Number(/(\d+) errors/.exec(label)?.[1] ?? 0);
        },
        {
          message: 'the chip does not carry the errors the gateway counted on the dead target',
          timeout: 15_000,
        },
      )
      .toBeGreaterThanOrEqual(counted);

    const event = page
      .getByRole('row')
      .filter({ has: page.getByRole('cell', { name: DEAD, exact: true }) })
      .filter({ hasText: 'health check' });
    await expect(event.first(), 'the circuit events have no entry for the target going down').toContainText('Down', {
      timeout: 15_000,
    });
  });
});

/**
 * A circuit breaker made in the dashboard (there was no way to make one there),
 * on a route whose only target accepts TCP -- so its health check passes and
 * the health check alone would say CLOSED -- but answers no HTTP, so every
 * request fails. The breaker opens, and the target's chip under its service says
 * Down: it used to say CLOSED while the route refused everything with 503.
 */
const ECHO = 'http://127.0.0.1:8084'; // tcp_backend: echoes bytes, speaks no HTTP
const CB_SERVICE = `cb-mw-e2e-svc-${stamp}`;
const CB_ROUTE = `cb-mw-e2e-route-${stamp}`;
const CB_ROUTE_NAME = `CB mw e2e ${stamp}`;
const CB_PREFIX = `/cb-mw-e2e-${stamp}`;
const CB_NAME = `CB e2e breaker ${stamp}`;

test.describe('Circuit Breaker middleware from the dashboard', () => {
  test.setTimeout(120_000);
  let breakerId = '';

  test.beforeAll(async ({ playwright }) => {
    const api = await admin(playwright);
    try {
      const svc = await api.put('/v1/services', {
        data: {
          id: CB_SERVICE, name: CB_SERVICE, backendType: 'http',
          weightedTargets: [{ url: ECHO, weight: 1 }], healthCheckType: 'HEALTH_CHECK_TYPE_TCP',
        },
      });
      expect(svc.ok(), `PUT /v1/services: ${svc.status()} ${await svc.text()}`).toBe(true);
    } finally {
      await api.dispose();
    }
  });

  test.afterAll(async ({ playwright }) => {
    const api = await admin(playwright);
    try {
      await api.delete(`/v1/routes/${encodeURIComponent(CB_ROUTE)}`);
      if (breakerId) await api.delete(`/v1/middlewares/${encodeURIComponent(breakerId)}`);
      await api.delete(`/v1/services/${encodeURIComponent(CB_SERVICE)}`);
    } finally {
      await api.dispose();
    }
  });

  test('is created in the editor, opens on failures, and its route reads OPEN', async ({ page, request, playwright }) => {
    await page.goto('/policies');
    await page.getByRole('button', { name: 'Add policy' }).click();
    // A new policy starts at the catalog; picking a type opens its form.
    const catalog = page.getByRole('dialog', { name: 'Choose a policy' });
    await catalog.getByRole('button', { name: /^Circuit breaker/ }).click();
    const create = page.getByRole('dialog', { name: 'Add policy' });
    await create.getByLabel('Name', { exact: true }).fill(CB_NAME);
    await create.getByLabel('Minimum Requests').fill('3');
    await create.getByLabel('Sleep Window', { exact: true }).fill('1h');
    const saved = page.waitForResponse((r) => new URL(r.url()).pathname === '/v1/middlewares' && r.request().method() === 'PUT');
    await create.getByRole('button', { name: 'Save policy' }).click();
    const res = await saved;
    expect(res.status(), `PUT /v1/middlewares: ${await res.text()}`).toBe(200);
    const mw = (await res.json()) as { id: string; type: string; config: Record<string, string> };
    breakerId = mw.id;
    expect(mw.type).toBe('circuit_breaker');
    expect(mw.config).toMatchObject({ min_requests: '3', sleep_window: '1h' });

    const api = await admin(playwright);
    try {
      const route = await api.put('/v1/routes', {
        data: { id: CB_ROUTE, name: CB_ROUTE_NAME, type: 'http', rule: `PathPrefix(\`${CB_PREFIX}\`)`,
          serviceId: CB_SERVICE, middlewares: [breakerId] },
      });
      expect(route.ok(), `PUT /v1/routes: ${route.status()} ${await route.text()}`).toBe(true);
      // Fail until the breaker answers for the backend: 503 with its own message.
      await expect
        .poll(async () => (await request.get(`${PROXY}${CB_PREFIX}/x`)).text(), {
          message: 'the breaker never opened on a backend that fails every request',
          timeout: 30_000,
        })
        .toContain('circuit open');
      const stats = (await (await api.get('/v1/routes/stats')).json()) as Record<string, { url: string; alive: boolean; circuitState: string; breaker?: string }[]>;
      expect(stats[CB_ROUTE], 'route stats').toEqual([expect.objectContaining({ url: ECHO, alive: true, circuitState: 'OPEN', breaker: 'OPEN' })]);
    } finally {
      await api.dispose();
    }

    await page.goto('/services');
    await page.getByRole('row').filter({ hasText: CB_SERVICE }).first().getByRole('button', { name: 'Show targets' }).click();
    const target = page.locator('.mantine-Group-root').filter({ has: page.getByText(ECHO, { exact: true }) }).last();
    await expect(target, 'the target behind an open breaker does not read Down').toContainText('Down', { timeout: 30_000 });
  });
});
