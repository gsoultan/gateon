// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test, expect } from '@playwright/test';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

test.use({ storageState: path.resolve(__dirname, '.auth/viewer.json') });

test.describe('RBAC: Viewer', () => {
  test.slow();

  test('can see dashboards and metrics', async ({ page }) => {
    await page.goto('/', { timeout: 60000 });
    await expect(page.getByText(/System Health/i)).toBeVisible({ timeout: 30000 });
  });

  test('can see security hub', async ({ page }) => {
    await page.goto('/security-center', { timeout: 60000 });
    await expect(page.getByText(/Security Hub/i).first()).toBeVisible({ timeout: 30000 });
  });

  test('cannot manage WAF rules or users', async ({ page }) => {
    await page.goto('/security-center', { timeout: 60000 });
    await page.getByRole('tab', { name: /WAF Rules/i }).click();
    // For Viewer, Add Rule button should be disabled
    await expect(page.getByRole('button', { name: /Add Rule/i })).toBeDisabled({ timeout: 20000 });

    await page.goto('/users', { timeout: 60000 });
    await expect(page.getByText(/Access Denied/i)).toBeVisible({ timeout: 30000 });
  });
});
