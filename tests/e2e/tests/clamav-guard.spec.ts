// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test, expect } from '@playwright/test';
test.setTimeout(90000);

// Opening a page must never start an antivirus scan. RunDeepScan starts one when
// none is running, so any GET-shaped use of it is a trap on a 2-core host.
test('opening the Security page never POSTs the scan endpoint', async ({ page }) => {
  const posts: string[] = [];
  page.on('request', r => {
    const u = new URL(r.url());
    if (u.pathname === '/v1/security/clamav/scan' && r.method() === 'POST') posts.push(u.pathname);
  });
  await page.goto('/security', { waitUntil: 'load' });
  await page.waitForTimeout(15000);
  expect(posts, 'a page load started a ClamAV deep scan').toHaveLength(0);
});

test('the old antivirus address opens the malware settings, which explain themselves when ClamAV is absent', async ({ page }) => {
  await page.goto('/clamav', { waitUntil: 'load' });
  await expect(page).toHaveURL(/\/settings\?.*tab=security/);
  // The malware settings sit inside the global WAF card, which shows them only
  // while "Protect all routes" is on, and advanced-security.test.ts, which
  // runs before this file, ends by switching it off and saving. This spec
  // passed only on the runs where that cleanup lost its race with the page
  // load. So turn the switch on in the form, unsaved, which is all the card
  // reads and leaves the gateway as the next spec expects it. The switch is
  // drawn before /v1/global arrives and is set again when it does, so look
  // again until the notice is there rather than clicking once.
  const protectAll = page.getByLabel('Protect all routes');
  await expect(async () => {
    if (!(await protectAll.isChecked())) {
      await page.locator('label').filter({ hasText: 'Protect all routes' }).click();
    }
    await expect(page.getByText('ClamAV Not Detected')).toBeVisible({ timeout: 3000 });
  }).toPass({ timeout: 20000 });
  await expect(page.getByRole('button', { name: 'Install Now' })).toBeVisible();
});

test('the Antivirus nav entry is hidden while ClamAV is not installed', async ({ page }) => {
  await page.goto('/security', { waitUntil: 'load' });
  await page.waitForTimeout(3000);
  await expect(page.getByRole('link', { name: 'Antivirus' })).toHaveCount(0);
});
