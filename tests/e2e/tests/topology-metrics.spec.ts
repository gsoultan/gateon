// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test, expect, type APIRequestContext } from '@playwright/test';

/**
 * Topology and Metrics, the two pages whose content no spec asserted: the
 * topology graph has to draw the gateway's own routes and services, and the
 * Metrics page's golden-signal tiles have to show the snapshot's numbers.
 */

type Playwright = { request: { newContext: (o: object) => Promise<APIRequestContext> } };

const stamp = Date.now();
const SERVICE = `topo-e2e-svc-${stamp}`;
const SERVICE_NAME = `Topology e2e service ${stamp}`;
const ROUTE = `topo-e2e-route-${stamp}`;
const ROUTE_NAME = `Topology e2e route ${stamp}`;

function adminApi(playwright: Playwright) {
  return playwright.request.newContext({ baseURL: 'http://localhost:8080', storageState: 'tests/.auth/admin.json' });
}

test.describe('Topology', () => {
  test.beforeAll(async ({ playwright }) => {
    const api = await adminApi(playwright);
    try {
      const svc = await api.put('/v1/services', {
        data: { id: SERVICE, name: SERVICE_NAME, weightedTargets: [{ url: 'http://127.0.0.1:8082', weight: 1 }] },
      });
      expect(svc.ok(), `PUT /v1/services: ${svc.status()}`).toBe(true);
      const route = await api.put('/v1/routes', {
        data: { id: ROUTE, name: ROUTE_NAME, type: 'http', rule: `PathPrefix(\`/topo-e2e-${stamp}\`)`, serviceId: SERVICE },
      });
      expect(route.ok(), `PUT /v1/routes: ${route.status()}`).toBe(true);
    } finally {
      await api.dispose();
    }
  });

  test.afterAll(async ({ playwright }) => {
    const api = await adminApi(playwright);
    try {
      await api.delete(`/v1/routes/${encodeURIComponent(ROUTE)}`);
      await api.delete(`/v1/services/${encodeURIComponent(SERVICE)}`);
    } finally {
      await api.dispose();
    }
  });

  test("draws the gateway's routes, services and their backend", async ({ page }) => {
    await page.goto('/topology');
    await expect(page.getByRole('heading', { name: 'Traffic Topology' })).toBeVisible();
    // The spec's own route and service, and a fixture route with its service.
    await expect(page.getByText(ROUTE_NAME, { exact: true })).toBeVisible();
    await expect(page.getByText(SERVICE_NAME, { exact: true })).toBeVisible();
    await expect(page.getByText('Test Route', { exact: true })).toBeVisible();
    await expect(page.getByText('Mock Service', { exact: true })).toBeVisible();
  });

  test('says so when the topology cannot be loaded', async ({ page }) => {
    await page.route('**/v1/routes?*', (route) =>
      route.fulfill({ status: 500, contentType: 'application/json', body: '{"error":"route store unavailable"}' }),
    );
    await page.goto('/topology');
    const failed = page.getByRole('alert').filter({ hasText: "Couldn't load the topology" });
    await expect(failed, 'a failed load was drawn as an empty graph').toBeVisible({ timeout: 15_000 });
    await expect(failed).toContainText('route store unavailable');
    await expect(page.getByText('Test Route', { exact: true })).toHaveCount(0);

    await page.unroute('**/v1/routes?*');
    await failed.getByRole('button', { name: 'Try again' }).click();
    await expect(failed).toHaveCount(0);
    await expect(page.getByText('Test Route', { exact: true })).toBeVisible();
  });
});

test.describe('Metrics', () => {
  test("the golden-signal tiles show the snapshot's numbers", async ({ page }) => {
    // Known numbers on the gateway's own snapshot, and no pushes to replace it.
    await page.route('**/v1/watch*', (route) => route.abort());
    await page.route((url) => url.pathname === '/v1/diag/metrics', async (route) => {
      const res = await route.fetch();
      const snap = (await res.json()) as { goldenSignals?: Record<string, number> };
      snap.goldenSignals = {
        ...(snap.goldenSignals ?? {}),
        requestsTotal: 987,
        errorsTotal: 12,
        errorRate: 1.2158,
        avgLatencyMs: 12.34,
        p95LatencyMs: 45.67,
        p99LatencyMs: 0.5,
        inFlightTotal: 3,
        bytesInTotal: 2048,
        bytesOutTotal: 3 * 1024 * 1024,
      };
      await route.fulfill({ response: res, json: snap });
    });
    await page.goto('/metrics-dashboard');
    await expect(page.getByRole('heading', { name: 'Metrics Dashboard' })).toBeVisible();

    const tile = (label: string) =>
      page.locator('.mantine-Paper-root').filter({ has: page.getByText(label, { exact: true }) }).last();
    await expect(tile('Total Requests')).toContainText('987');
    await expect(tile('Error Rate')).toContainText('1.22%');
    await expect(tile('Error Rate')).toContainText('12 errors of 987 requests');
    await expect(tile('Avg Latency')).toContainText('12.3ms');
    await expect(tile('P95 Latency')).toContainText('45.7ms');
    await expect(tile('P99 Latency')).toContainText('500µs');
    await expect(tile('In-Flight')).toContainText('3');
    await expect(tile('Traffic In')).toContainText('2.0 KB');
    await expect(tile('Traffic Out')).toContainText('3.0 MB');
  });

  test('says so when the metrics cannot be loaded', async ({ page }) => {
    await page.route('**/v1/watch*', (route) => route.abort());
    await page.route((url) => url.pathname === '/v1/diag/metrics', (route) =>
      route.fulfill({ status: 500, contentType: 'application/json', body: '{"error":"metrics unavailable"}' }),
    );
    await page.goto('/metrics-dashboard');
    await expect(page.getByText(/Failed to load metrics/)).toBeVisible({ timeout: 15_000 });
  });
});
