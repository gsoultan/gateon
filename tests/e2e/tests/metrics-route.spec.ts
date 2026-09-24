// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test, expect } from '@playwright/test';

/**
 * The dashboard is served from the same origin as the gateway's Prometheus
 * endpoint, and the Metrics page used to live at /metrics. Client-side
 * navigation never asked the server for it, so the page looked fine until
 * anything loaded the URL itself: a reload, a bookmark, a link opened in a new
 * tab. The gateway then answered /metrics as Prometheus, and the operator got a
 * page of raw exposition text instead of the Metrics page.
 *
 * The service worker's navigation fallback used to hide this in browsers where
 * it was installed. Blocking the worker here is the plain-HTTP management UI
 * reached by LAN address, which is not a secure context, so no worker ever
 * registers there and the collision was the everyday behaviour.
 */
test.use({ storageState: { cookies: [], origins: [] } });
test.setTimeout(120000);

test('the Metrics page survives a reload without a service worker', async ({ browser }) => {
  const context = await browser.newContext({ serviceWorkers: 'block' });
  const page = await context.newPage();
  try {
    const login = await page.request.post('/v1/login', {
      data: { username: 'admin', password: 'password123' },
    });
    expect(login.ok(), `login failed: ${login.status()}`).toBe(true);

    await page.goto('/');
    const href = await page.getByRole('link', { name: 'Metrics', exact: true }).first().getAttribute('href');
    expect(href, 'the navigation has no Metrics link').toBeTruthy();

    await page.goto(href!);
    await expect(
      page.getByRole('heading', { name: 'Metrics Dashboard' }),
      `reloading ${href} did not render the Metrics page; the server answered that path itself`,
    ).toBeVisible({ timeout: 30000 });
  } finally {
    await context.close();
  }
});
