// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test as setup, expect } from '@playwright/test';
import { execSync } from 'child_process';

const adminFile = 'tests/.auth/admin.json';

setup('authenticate admin', async ({ page }) => {
  setup.setTimeout(120000);
  // Wait for gateon to be ready
  execSync('go run wait_for_port/main.go localhost:8080');
  
  await page.goto('/login');
  await page.getByPlaceholder('Enter your username').fill('admin');
  await page.getByPlaceholder('••••••••').fill('password123');
  await page.getByRole('button', { name: /Continue to Dashboard/i }).click();

  // Wait for dashboard to load
  await expect(page.getByRole('heading', { name: /System Overview/i })).toBeVisible({ timeout: 60000 });

  // Ensure localStorage is persisted
  await page.waitForFunction(() => {
    const auth = localStorage.getItem('gateon-auth');
    if (!auth) return false;
    const { state } = JSON.parse(auth);
    return state && state.token !== null && state.user !== null;
  }, { timeout: 10000 });

  await page.context().storageState({ path: adminFile });
});
