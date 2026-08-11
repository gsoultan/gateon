// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test, expect } from '@playwright/test';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

test.use({ storageState: path.resolve(__dirname, '.auth/admin.json') });

test.describe('RBAC: Administrator', () => {
  test.slow(); // Triple the default timeout

  test('can see everything and manage users', async ({ page }) => {
    await page.goto('/', { timeout: 60000 });
    await expect(page.getByText(/System Health/i)).toBeVisible({ timeout: 30000 });
    
    await page.goto('/users', { timeout: 60000 });
    await expect(page.getByRole('heading', { name: 'User Management', exact: false })).toBeVisible({ timeout: 30000 });
    await expect(page.getByRole('button', { name: /Add User/i })).toBeVisible({ timeout: 20000 });
  });

  test('can manage WAF rules', async ({ page }) => {
    await page.goto('/security-center', { timeout: 60000 });
    await expect(page.getByText(/Security Hub/i).first()).toBeVisible({ timeout: 30000 });
    
    await page.getByRole('tab', { name: /WAF Rules/i }).click();
    await expect(page.getByRole('button', { name: /Add Rule/i })).toBeVisible({ timeout: 20000 });
  });
});
