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
    // This used to open /traces, so it said nothing about the Logs page at
    // all. The log stream authorizes on its own (isLogsRequestAuthorized, not
    // the REST middleware), so what an operator can see is the stream
    // connecting and delivering lines, not the page shell.
    await page.goto('/logs', { timeout: 60000 });
    const card = page.locator('.mantine-Card-root').filter({ has: page.getByRole('heading', { name: 'Live Logs' }) });
    await expect(card.getByText('LIVE', { exact: true }), 'the operator was refused the log stream').toBeVisible({ timeout: 30000 });
    await expect(card.getByText(/level=(DEBUG|INFO|WARN|ERROR)/).first()).toBeVisible({ timeout: 30000 });
  });

  test('can manage WAF rules but NOT users', async ({ page }) => {
    await page.goto('/security-center', { timeout: 60000 });
    await page.getByRole('tab', { name: /WAF Rules/i }).click();
    // Enabled, not visible: the button renders for every role and is disabled
    // for a viewer (rbac_viewer.test.ts), so visibility cannot tell "can
    // manage" from "cannot".
    await expect(page.getByRole('button', { name: /Add Rule/i })).toBeEnabled({ timeout: 20000 });

    await page.goto('/users', { timeout: 60000 });
    await expect(page.getByText(/Access Denied/i)).toBeVisible({ timeout: 30000 });
  });
});
