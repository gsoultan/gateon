// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test, expect } from '@playwright/test';
import fs from 'fs';
import path from 'path';

// The setup wizard on a gateway whose global.json already names its database
// and refers to its session key -- what the Helm chart renders from
// externalDatabase and GATEON_SESSION_KEY: the "configured-run" project in
// playwright.config.ts (ADR 0057).
//
// The wizard always submitted a database, SQLite gateon.db by default. Setup
// created the administrator in the configured database, switched global.json
// to the wizard's, and the next start refused to run. It also showed a
// generated session key that Setup never used.

const dataDir = process.env.GATEON_E2E_CONFIGURED_RUN_DIR ?? '';
const admin = 'configured-admin';
const password = 'configured-Passw0rd';

test('the wizard keeps the configured database and session key, and says so', async ({ page }) => {
  test.setTimeout(120_000);
  expect(dataDir, 'playwright.config.ts names the configured-run data directory').not.toBe('');

  await page.goto('/');
  await expect(page).toHaveURL(/\/setup$/);

  const tokenFile = path.join(dataDir, 'setup-token');
  await page.getByRole('textbox', { name: 'Setup token' }).fill(fs.readFileSync(tokenFile, 'utf8').trim());
  await page.getByRole('textbox', { name: 'Username' }).fill(admin);
  await page.getByRole('textbox', { name: 'Password', exact: true }).fill(password);
  await page.getByRole('textbox', { name: 'Confirm', exact: true }).fill(password);
  // Leaving the account step asks the gateway, with the token, what setup keeps.
  const asked = page.waitForResponse((r) => r.url().endsWith('/gateon.v1.ApiService/IsSetupRequired'));
  await page.getByRole('button', { name: 'Next' }).click();
  expect((await asked).status()).toBe(200);

  // Security: no generated key to copy, because none will be used.
  await expect(page.getByText('Session key from the environment')).toBeVisible();
  await expect(page.getByRole('textbox', { name: 'PASETO Secret Key' })).toHaveCount(0);
  await page.getByRole('button', { name: 'Next' }).click();

  // Database: no choice to make, and the database named -- with the token, where it is.
  const configured = page.getByTestId('setup-database-configured');
  await expect(configured).toBeVisible();
  await expect(configured).toContainText('SQLite');
  await expect(configured).toContainText(path.join(dataDir, 'configured.db'));
  await expect(page.getByRole('button', { name: 'Test Connection' })).toHaveCount(0);
  await page.getByRole('button', { name: 'Next' }).click();

  await expect(page.getByText('Logging database already configured')).toBeVisible();
  await page.getByRole('button', { name: 'Next' }).click();
  await page.getByRole('textbox', { name: 'Bind Address' }).fill('127.0.0.1');
  await page.getByRole('button', { name: 'Next' }).click();
  await expect(page.getByText('from the environment (GATEON_SESSION_KEY)')).toBeVisible();

  const setup = page.waitForResponse((r) => r.url().endsWith('/gateon.v1.ApiService/Setup'));
  await page.getByRole('button', { name: 'Complete System Setup' }).click();
  expect((await setup).status()).toBe(200);
  await expect(page).toHaveURL(/\/login$/, { timeout: 15_000 });

  // global.json still names the database and the reference: the next start
  // opens the database the administrator is in, with the key every replica has.
  const global = JSON.parse(fs.readFileSync(path.join(dataDir, 'global.json'), 'utf8'));
  expect(global.auth?.database_config).toMatchObject({ driver: 'sqlite', sqlite_path: 'configured.db' });
  expect(global.auth?.database_url ?? '').toBe('');
  expect(global.auth?.paseto_secret).toBe('$env:GATEON_SESSION_KEY');

  await page.getByPlaceholder('Enter your username').fill(admin);
  await page.getByPlaceholder('••••••••').fill(password);
  await page.getByRole('button', { name: /Continue to Dashboard/i }).click();
  await expect(page.getByRole('heading', { name: /System Overview/i })).toBeVisible({ timeout: 60_000 });
});
