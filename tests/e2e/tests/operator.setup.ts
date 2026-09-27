// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test as setup, expect } from '@playwright/test';
import { execSync } from 'child_process';
import { expectSessionOnlyInCookie } from './session-storage';

const operatorFile = 'tests/.auth/operator.json';

setup('authenticate operator', async ({ page }) => {
  setup.setTimeout(120000);
  // Wait for gateon to be ready
  execSync('go run wait_for_port/main.go localhost:8080');
  
  await page.goto('/login');
  await page.getByPlaceholder('Enter your username').fill('operator');
  await page.getByPlaceholder('••••••••').fill('password123');
  await page.getByRole('button', { name: /Continue to Dashboard/i }).click();

  // Wait for dashboard to load
  await expect(page.getByRole('heading', { name: /System Overview/i })).toBeVisible({ timeout: 60000 });

  // The user persisted, and the session held only in the HttpOnly cookie.
  await expectSessionOnlyInCookie(page);

  await page.context().storageState({ path: operatorFile });
});
