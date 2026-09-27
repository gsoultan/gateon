// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test, expect, type Page } from '@playwright/test';

/**
 * Path Metrics: request count and average latency per host and path, from
 * /v1/diag/path-stats, refreshed while the page is open.
 *
 * The paths are whatever clients asked for -- the entrypoint records requests
 * no route took too -- so this is gateway-observed text, and one of the paths
 * below is markup.
 */

const PROXY = 'http://localhost:8081';
const HOSTILE = '<img src=x onerror=alert(1)>';
// Long enough for one refresh of the table (the dashboard's default interval is
// ten seconds) after the gateway has written the counts (every second on the
// enterprise tier the suite runs).
const NEXT_REFRESH = { timeout: 25_000 };

async function openPathMetrics(page: Page): Promise<void> {
  const loaded = page.waitForResponse(
    (r) => new URL(r.url()).pathname === '/v1/diag/path-stats' && r.request().method() === 'GET',
  );
  await page.goto('/path-metrics');
  expect((await loaded).status(), 'GET /v1/diag/path-stats').toBe(200);
}

/** The row for one exact path. */
function pathRow(page: Page, path: string) {
  return page.getByRole('row').filter({ has: page.getByRole('cell', { name: path, exact: true }) });
}

test.describe('Path Metrics', () => {
  test.setTimeout(90_000);

  test("lists the paths the gateway served with their counts, live, and a client's path as text", async ({
    page,
    request,
  }) => {
    const dialogs: string[] = [];
    page.on('dialog', (d) => {
      dialogs.push(d.message());
      void d.dismiss();
    });
    const marker = `pm-${Date.now()}`;
    for (let i = 0; i < 3; i++) {
      expect((await request.get(`${PROXY}/test/${marker}`)).status()).toBe(200);
    }
    // No route claims it, so no WAF sees it; the entrypoint still counts it.
    expect((await request.get(`${PROXY}/${marker}/${encodeURIComponent(HOSTILE)}`)).status()).toBe(404);

    await openPathMetrics(page);
    await page.getByPlaceholder('Search host or path text...').fill(marker);

    // On a tier with the trace store the list comes from the database, which
    // the writer fills every flush interval, so the paths may first appear at
    // the table's next refresh.
    const served = pathRow(page, `/test/${marker}`);
    await expect(served).toHaveCount(1, NEXT_REFRESH);
    await expect(pathRow(page, `/${marker}/${HOSTILE}`)).toHaveCount(1, NEXT_REFRESH);
    const cells = served.getByRole('cell');
    await expect(cells.nth(0)).toHaveText('localhost');
    await expect(cells.nth(2), 'requests to the path').toHaveText('3', NEXT_REFRESH);
    await expect(cells.nth(3)).toHaveText(/^\d+\.\d{3}s$/);
    await expect(page.getByText('2 paths', { exact: true })).toBeVisible();

    // The client's bytes, as characters, and nothing made of them.
    await expect(page.locator('img[src="x"]')).toHaveCount(0);
    expect(dialogs, 'a path ran as script').toEqual([]);

    // Refreshed while the page is open; nothing reloads it.
    for (let i = 0; i < 2; i++) {
      expect((await request.get(`${PROXY}/test/${marker}`)).status()).toBe(200);
    }
    await expect(cells.nth(2), 'the count did not follow the traffic').toHaveText('5', NEXT_REFRESH);
  });

  test('narrows to one route path, and clears back to every path', async ({ page, request }) => {
    const marker = `pm-select-${Date.now()}`;
    for (const suffix of ['a', 'b']) {
      expect((await request.get(`${PROXY}/test/${marker}-${suffix}`)).status()).toBe(200);
    }
    await openPathMetrics(page);
    const search = page.getByPlaceholder('Search host or path text...');
    await search.fill(marker);
    await expect(pathRow(page, `/test/${marker}-a`)).toHaveCount(1, NEXT_REFRESH);
    await expect(pathRow(page, `/test/${marker}-b`)).toHaveCount(1);

    await page.getByPlaceholder('Route path').click();
    await page.getByRole('option', { name: `/test/${marker}-b`, exact: true }).click();
    await expect(pathRow(page, `/test/${marker}-b`)).toHaveCount(1);
    await expect(pathRow(page, `/test/${marker}-a`)).toHaveCount(0);
    await expect(page.getByText('1 paths', { exact: true })).toBeVisible();

    const clear = page.getByRole('button', { name: 'Clear filters' });
    await clear.click();
    await expect(search).toHaveValue('');
    await expect(page.getByPlaceholder('Route path')).toHaveValue('');
    await expect(clear).toBeDisabled();
  });

  test('says so when the path metrics cannot be loaded, and recovers on retry', async ({ page, request }) => {
    expect((await request.get(`${PROXY}/test/pm-retry-${Date.now()}`)).status()).toBe(200);
    await page.route('**/v1/diag/path-stats', (route) =>
      route.fulfill({ status: 500, contentType: 'application/json', body: '{"error":"path statistics are unavailable"}' }),
    );
    await page.goto('/path-metrics');

    const failed = page.getByRole('alert').filter({ hasText: "Couldn't load path metrics" });
    await expect(failed, 'a failed load was shown as an empty one').toBeVisible();
    await expect(failed).toContainText('path statistics are unavailable');
    await expect(page.getByText('No path metrics collected yet.')).toHaveCount(0);

    await page.unroute('**/v1/diag/path-stats');
    const retried = page.waitForResponse((r) => new URL(r.url()).pathname === '/v1/diag/path-stats');
    await failed.getByRole('button', { name: 'Try again' }).click();
    expect((await retried).status()).toBe(200);
    await expect(failed).toHaveCount(0);
    await expect(page.getByRole('columnheader', { name: 'Path' })).toBeVisible();
  });
});
