// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test, expect } from '@playwright/test';
test.setTimeout(90000);

// Opening a page must never start an antivirus scan. RunDeepScan starts one when
// none is running, so any GET-shaped use of it is a trap on a 2-core host.
test('opening the Security Hub never POSTs the scan endpoint', async ({ page }) => {
  const posts: string[] = [];
  page.on('request', r => {
    const u = new URL(r.url());
    if (u.pathname === '/v1/security/clamav/scan' && r.method() === 'POST') posts.push(u.pathname);
  });
  await page.goto('/security-center', { waitUntil: 'load' });
  await page.waitForTimeout(15000);
  expect(posts, 'a page load started a ClamAV deep scan').toHaveLength(0);
});

test('the antivirus page loads and explains itself when ClamAV is absent', async ({ page }) => {
  await page.goto('/clamav', { waitUntil: 'load' });
  await expect(page.getByText('ClamAV is not installed')).toBeVisible({ timeout: 20000 });
  await expect(page.getByRole('button', { name: 'Install ClamAV' })).toBeVisible();
});

test('the Antivirus nav entry is hidden while ClamAV is not installed', async ({ page }) => {
  await page.goto('/security-center', { waitUntil: 'load' });
  await page.waitForTimeout(3000);
  await expect(page.getByRole('link', { name: 'Antivirus' })).toHaveCount(0);
});
