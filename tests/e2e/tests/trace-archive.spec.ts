// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test, expect } from '@playwright/test';

// The trace archive, as a gateway that shares its archive's storage with
// another sees it (ADR-0023). Before the suite's gateway started,
// seed_trace_archive archived an hour of traces from two days ago as another
// node, gw-seed, into the directory the gateway reads; the gateway itself is
// gw-e2e. The gateway cannot archive an hour of its own during a run -- an hour
// is archived only after it ends -- so the seeded hour is what there is to list,
// search and open.

const seededFile = /traces-\d{4}-\d{2}-\d{2}T\d{2}Z\.gw-seed\.ndjson\.zst/;
const seededPaths = ['/archived/orders/1', '/archived/orders', '/archived/orders/2', '/archived/payments', '/archived/orders/3'];

test.describe('Trace archive', () => {
  test("lists another gateway's archived hour, and opens its traces", async ({ page }) => {
    await page.goto('/traces?tab=archive');
    await expect(page.getByRole('heading', { name: 'Archived hours' })).toBeVisible();
    await expect(page.getByText('This gateway archives as')).toContainText('gw-e2e');
    const hour = page.getByRole('row').filter({ hasText: seededFile });
    await expect(hour).toHaveCount(1);

    await hour.getByRole('button', { name: 'View' }).click();
    await expect(page.getByRole('tab', { name: 'History' })).toHaveAttribute('aria-selected', 'true');
    for (const path of seededPaths) {
      await expect(page.getByRole('cell', { name: path, exact: true })).toBeVisible();
    }
    await expect(page.getByText('5 traces · end of the period')).toBeVisible();

    // The detail view asks for a trace by its start time and ID, not by where
    // it is kept; the gateway finds it in gw-seed's file. The request header is
    // only in the full record, not in the summary the list was built from.
    await page.getByRole('button', { name: 'Details of trace gw-seed-trace-4' }).click();
    const details = page.getByRole('dialog');
    await expect(details).toContainText('gw-seed-trace-4');
    await expect(details).toContainText('/archived/payments');
    await expect(details).toContainText('application/json');
  });

  test("History merges this gateway's own traces with the archived ones, and names each one's gateway", async ({
    page,
    request,
  }) => {
    // Room for the poll below, which is longer than a test's default timeout.
    test.setTimeout(90_000);
    // A trace of this gateway's own, in its live store.
    const own = await request.get('http://localhost:8081/test/trace-archive-e2e');
    expect(own.ok(), `the request through the gateway: ${own.status()}`).toBe(true);

    const to = new Date(Date.now() + 5 * 60_000).toISOString();
    const from = new Date(Date.now() - 3 * 24 * 3600_000).toISOString();
    // The store writes traces in batches; look again until the new one is in.
    await expect(async () => {
      await page.goto(`/traces?tab=history&from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`);
      await expect(page.getByRole('cell', { name: '/test/trace-archive-e2e', exact: true })).toBeVisible({
        timeout: 5_000,
      });
    }).toPass({ timeout: 60_000 });

    await expect(page.getByRole('columnheader', { name: 'Node' })).toBeVisible();
    await expect(page.getByRole('row').filter({ hasText: '/test/trace-archive-e2e' })).toContainText('gw-e2e');
    await expect(page.getByRole('row').filter({ hasText: '/archived/payments' })).toContainText('gw-seed');
  });
});
