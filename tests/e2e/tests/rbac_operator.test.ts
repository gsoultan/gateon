// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test, expect } from '@playwright/test';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

test.use({ storageState: path.resolve(__dirname, '.auth/operator.json') });

test.describe('RBAC: Operator', () => {
  test.slow();

  test('can see dashboards and metrics', async ({ page }) => {
    await page.goto('/', { timeout: 60000 });
    await expect(page.getByText(/System Health/i)).toBeVisible({ timeout: 30000 });
    await expect(page.getByText(/TRAFFIC METRICS/i)).toBeVisible({ timeout: 20000 });
  });

  test('can see security hub', async ({ page }) => {
    await page.goto('/security-center', { timeout: 60000 });
    await expect(page.getByText(/Security Hub/i).first()).toBeVisible({ timeout: 30000 });
  });

  test('can see logs', async ({ page }) => {
    await page.goto('/traces', { timeout: 60000 });
    // The page is titled "Distributed Tracing"; /Traces/i never matched it and
    // only ever passed against an older heading.
    await expect(page.getByRole('heading', { name: /Distributed Tracing/i })).toBeVisible({ timeout: 30000 });
  });

  test('can manage WAF rules but NOT users', async ({ page }) => {
    await page.goto('/security-center', { timeout: 60000 });
    await page.getByRole('tab', { name: /WAF Rules/i }).click();
    await expect(page.getByRole('button', { name: /Add Rule/i })).toBeVisible({ timeout: 20000 });

    await page.goto('/users', { timeout: 60000 });
    await expect(page.getByText(/Access Denied/i)).toBeVisible({ timeout: 30000 });
  });
});
