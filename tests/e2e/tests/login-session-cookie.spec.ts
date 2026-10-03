// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test, expect } from '@playwright/test';

/**
 * A browser's sign-in is answered with the session as the HttpOnly
 * gateon_session cookie and nowhere else.
 *
 * The login response used to carry the same token in its JSON body, where any
 * script in the page -- including script that wrapped fetch before the form was
 * submitted -- could read it and carry it off as a bearer credential that
 * outlives the tab. The gateway recognises a browser by Sec-Fetch-Mode, which
 * only a real browser sends and page script can neither set nor remove, so this
 * has to be proved in one: the Go tests can only set the header themselves.
 */
test.use({ storageState: { cookies: [], origins: [] } });

test('a browser sign-in gets the session only as the HttpOnly cookie', async ({ page }) => {
  await page.goto('/login');
  const loginResponse = page.waitForResponse(
    (r) => new URL(r.url()).pathname === '/v1/login' && r.request().method() === 'POST',
  );
  await page.getByPlaceholder('Enter your username').fill('admin');
  await page.getByPlaceholder('••••••••').fill('e2e-horse-battery-42');
  await page.getByRole('button', { name: /Continue to Dashboard/i }).click();

  const res = await loginResponse;
  expect(res.status()).toBe(200);
  expect(await res.request().headerValue('sec-fetch-mode'), 'the browser did not send Sec-Fetch-Mode').toBeTruthy();
  const body = await res.json();
  expect(body.token ?? '', 'the sign-in response handed the page its session token').toBe('');
  expect(body.user?.username).toBe('admin');

  const session = (await page.context().cookies()).find((c) => c.name === 'gateon_session');
  expect(session?.value, 'sign-in set no session cookie').toBeTruthy();
  expect(session?.httpOnly, 'gateon_session is readable by script').toBe(true);

  // The dashboard signs in on the cookie alone.
  await expect(page.getByRole('heading', { name: /System Overview/i })).toBeVisible({ timeout: 60000 });
});
