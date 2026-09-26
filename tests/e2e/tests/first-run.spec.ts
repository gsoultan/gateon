// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test, expect, type Page } from '@playwright/test';
import fs from 'fs';
import path from 'path';

// The first-run wizard, against a gateway that has never been set up: the
// "first-run" project in playwright.config.ts. Nothing drove it before. From
// v2.4.2 its connection test answered "missing database configuration" to every
// database, and finishing it saved none of the databases it asked for -- both of
// which read as a database problem rather than a broken wizard.

const dataDir = process.env.GATEON_E2E_FIRST_RUN_DIR ?? '';
const admin = 'first-run-admin';
const password = 'first-run-Passw0rd';

// Presses "Test Connection" and returns the status the gateway answered with.
async function testConnection(page: Page): Promise<number> {
  const answered = page.waitForResponse(
    (r) => r.url().endsWith('/v1/setup/test-db') && r.request().method() === 'POST',
  );
  await page.getByRole('button', { name: 'Test Connection' }).click();
  return (await answered).status();
}

test('the wizard tests the database it is given, and saves the one it submits', async ({ page }) => {
  test.setTimeout(120_000);
  expect(dataDir, 'playwright.config.ts names the first-run data directory').not.toBe('');

  await page.goto('/');
  await expect(page).toHaveURL(/\/setup$/);

  // Account, then Security, whose PASETO secret the wizard generates.
  await page.getByRole('textbox', { name: 'Username' }).fill(admin);
  await page.getByRole('textbox', { name: 'Password', exact: true }).fill(password);
  await page.getByRole('textbox', { name: 'Confirm', exact: true }).fill(password);
  await page.getByRole('button', { name: 'Next' }).click();
  await page.getByRole('button', { name: 'Next' }).click();

  // An address with no Postgres behind it gets the one message the wizard gives
  // any address that is not Postgres -- as a message, not the JSON body.
  await page.getByRole('checkbox', { name: 'Use connection string (URL)' }).check();
  await page.getByRole('textbox', { name: 'Connection string' }).fill('postgres://gateon:x@127.0.0.1:1/gateon?sslmode=disable');
  expect(await testConnection(page)).toBe(400);
  await expect(page.getByText(/could not connect to a database server at that address/)).toBeVisible();
  await expect(page.getByText(/"error"/)).toHaveCount(0);

  // The form, under a name that is not the default: the default is where the
  // gateway put its administrator whatever the operator chose.
  await page.getByRole('checkbox', { name: 'Use connection string (URL)' }).uncheck();
  await page.getByRole('textbox', { name: 'SQLite file path' }).fill('wizard.db');
  expect(await testConnection(page)).toBe(200);
  await expect(page.getByText('Connection successful')).toBeVisible();

  await page.getByRole('button', { name: 'Next' }).click(); // tests it again, then Logging
  await page.getByRole('button', { name: 'Next' }).click(); // logs kept with it, then API
  await page.getByRole('textbox', { name: 'Bind Address' }).fill('127.0.0.1');
  await page.getByRole('button', { name: 'Next' }).click(); // Review

  const setup = page.waitForResponse((r) => r.url().endsWith('/gateon.v1.ApiService/Setup'));
  await page.getByRole('button', { name: 'Complete System Setup' }).click();
  expect((await setup).status()).toBe(200);
  await expect(page).toHaveURL(/\/login$/, { timeout: 15_000 });

  // Saved where the next start reads it from.
  const global = JSON.parse(fs.readFileSync(path.join(dataDir, 'global.json'), 'utf8'));
  expect(global.auth?.database_config).toMatchObject({ driver: 'sqlite', sqlite_path: 'wizard.db' });

  // And the administrator the wizard created can sign in.
  await page.getByPlaceholder('Enter your username').fill(admin);
  await page.getByPlaceholder('••••••••').fill(password);
  await page.getByRole('button', { name: /Continue to Dashboard/i }).click();
  await expect(page.getByRole('heading', { name: /System Overview/i })).toBeVisible({ timeout: 60_000 });
});
