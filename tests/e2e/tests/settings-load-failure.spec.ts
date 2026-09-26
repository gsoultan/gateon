// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test, expect } from '@playwright/test';

// Settings keeps the gateway's config in local state, and it starts from
// placeholders: TLS off, no Redis or OTel, the management allowlist open to
// every address. A failed read was swallowed, so the form showed those
// placeholders as though they were the gateway's -- and Save sent them. The
// server keeps only the sections a save leaves out, and all of these are sent,
// so one failed load and one Save reset TLS, Redis, OTel, logging and the
// allowlist.
test('a failed settings load holds the form instead of offering placeholders to save', async ({ page }) => {
  let puts = 0;
  page.on('request', (r) => {
    if (r.method() === 'PUT' && new URL(r.url()).pathname === '/v1/global') puts++;
  });
  // A failed read, as a dropped connection or a 5xx gives one.
  await page.route('**/v1/global', (route) =>
    route.request().method() === 'GET'
      ? route.fulfill({ status: 500, contentType: 'application/json', body: '{"error":"gateway unavailable"}' })
      : route.continue(),
  );

  await page.goto('/settings');
  const failed = page.getByRole('alert').filter({ hasText: 'Gateway settings could not be loaded' });
  await expect(failed).toBeVisible();
  const save = page.getByRole('button', { name: 'Save Global Configuration' });
  await expect(save).toBeDisabled();

  // Once the gateway answers again, Retry brings the form back.
  await page.unroute('**/v1/global');
  await failed.getByRole('button', { name: 'Retry' }).click();
  await expect(failed).toHaveCount(0);
  await expect(save).toBeEnabled();
  expect(puts, 'nothing was saved while the settings were unknown').toBe(0);
});
