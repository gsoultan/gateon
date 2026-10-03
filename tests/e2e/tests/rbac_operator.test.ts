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

  // ADR 0040: the gateway refuses an operator's change to the settings that
  // guard the management plane. The dashboard shows them read-only with the
  // reason, and the whole-object save it sends -- those settings unchanged --
  // still goes through.
  test('sees the management plane settings read-only, and can still save', async ({ page }) => {
    const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === '/v1/global' && r.request().method() === 'GET');
    await page.goto('/settings?tab=gateway', { timeout: 60000 });
    expect((await loaded).status(), 'GET /v1/global').toBe(200);

    await expect(page.getByLabel('Bind Address')).toBeDisabled({ timeout: 20000 });
    await expect(page.getByLabel(/Allowed IPs/)).toBeDisabled();
    await expect(page.getByText(/Only an administrator can change this/).first()).toBeVisible();

    const saved = page.waitForResponse((r) => new URL(r.url()).pathname === '/v1/global' && r.request().method() === 'PUT');
    await page.getByRole('button', { name: 'Save Gateway Config' }).click();
    const res = await saved;
    expect(res.status(), `an operator's unchanged save: ${await res.text()}`).toBe(200);
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
