// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test, expect, type APIRequestContext, type Locator, type Page } from '@playwright/test';
import path from 'path';
import { fileURLToPath } from 'url';

/**
 * The command palette (Ctrl+K / Cmd+K): search every page and a few actions,
 * move with the arrow keys, run with Enter.
 *
 * The shortcut is Mantine's "mod+K", which takes Ctrl or Cmd. It is pressed as
 * Ctrl here because that is what the header advertises under the suite's
 * browser (Desktop Chrome, a Windows user agent) -- and only once the header
 * is on screen, since the listener is registered by the shell, not the page.
 */

const __dirname = path.dirname(fileURLToPath(import.meta.url));

async function openPalette(page: Page, at = '/'): Promise<{ palette: Locator; search: Locator }> {
  await page.goto(at);
  await expect(page.getByRole('button', { name: 'Open command palette' })).toBeVisible();
  await page.keyboard.press('Control+k');
  const palette = page.getByRole('dialog', { name: 'Command palette' });
  await expect(palette, 'Ctrl+K opened no dialog named "Command palette"').toBeVisible();
  const search = palette.getByRole('textbox', { name: 'Search commands' });
  await expect(search).toBeFocused();
  return { palette, search };
}

test.describe('Command palette', () => {
  test('typing narrows the commands, and Enter goes to the page', async ({ page }) => {
    const { palette, search } = await openPalette(page);
    await search.fill('path metrics');
    await expect(palette.getByRole('button')).toHaveCount(1);
    await expect(palette.getByRole('button', { name: 'Path Metrics /path-metrics' })).toBeVisible();

    await search.press('Enter');
    await expect(page).toHaveURL(/\/path-metrics$/);
    await expect(page.getByRole('heading', { name: 'Path Metrics', level: 2 })).toBeVisible();
    await expect(palette, 'the palette stayed open after running a command').toBeHidden();
  });

  test('keywords match, the arrow keys choose, nothing found says so, and Escape closes', async ({ page }) => {
    const { palette, search } = await openPalette(page);
    // "waf" is a keyword of the Security Hub, not part of its name.
    await search.fill('waf');
    await expect(palette.getByRole('button', { name: 'Security Hub /security-center' })).toBeVisible();

    // Two matches, in navigation order: Audit Logs, then Logs.
    await search.fill('logs');
    await expect(palette.getByRole('button')).toHaveText([/^Audit Logs/, /^Logs/]);
    await search.press('ArrowDown');
    await search.press('Enter');
    await expect(page, 'ArrowDown then Enter did not run the second command').toHaveURL(/\/logs$/);

    await page.keyboard.press('Control+k');
    await expect(palette).toBeVisible();
    await expect(search, 'the palette kept the last query').toHaveValue('');
    await search.fill('zzzz-no-such-command');
    await expect(palette.getByText('No matching commands')).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(palette).toBeHidden();
  });

  test('the theme commands switch the colour scheme', async ({ page }) => {
    const html = page.locator('html');
    let { search } = await openPalette(page);
    await search.fill('theme dark');
    await search.press('Enter');
    await expect(html).toHaveAttribute('data-mantine-color-scheme', 'dark');

    await page.keyboard.press('Control+k');
    search = page.getByRole('dialog', { name: 'Command palette' }).getByRole('textbox', { name: 'Search commands' });
    await search.fill('theme light');
    await search.press('Enter');
    await expect(html).toHaveAttribute('data-mantine-color-scheme', 'light');
  });

  test('Users is offered to an administrator', async ({ page }) => {
    const { palette, search } = await openPalette(page);
    await search.fill('users');
    await expect(palette.getByRole('button', { name: 'Users /users' })).toBeVisible();
  });
});

test.describe('Command palette as an operator', () => {
  test.use({ storageState: path.resolve(__dirname, '.auth/operator.json') });

  test('Users is not offered to an operator', async ({ page }) => {
    const { palette, search } = await openPalette(page);
    await search.fill('users');
    await expect(palette.getByText('No matching commands')).toBeVisible();
    // Everything else still is.
    await search.fill('settings');
    await expect(palette.getByRole('button', { name: 'Settings /settings' })).toBeVisible();
  });
});

test.describe('Command palette sign out', () => {
  // An account of its own, not just a session of its own: signing out ends
  // every session of the account, so signing out as the shared admin would
  // end the session in .auth/admin.json that every other spec runs on.
  test.use({ storageState: { cookies: [], origins: [] } });

  const USER = `e2e-sign-out-${Date.now()}`;
  const PASSWORD = 'correct-horse-battery-staple-7';

  async function adminApi(playwright: { request: { newContext: (o: object) => Promise<APIRequestContext> } }) {
    return playwright.request.newContext({
      baseURL: 'http://localhost:8080',
      storageState: path.resolve(__dirname, '.auth/admin.json'),
    });
  }

  test.beforeAll(async ({ playwright }) => {
    const api = await adminApi(playwright);
    try {
      const made = await api.put('/v1/users', { data: { username: USER, password: PASSWORD, role: 'viewer' } });
      expect(made.ok(), `creating ${USER}: ${made.status()}`).toBe(true);
    } finally {
      await api.dispose();
    }
  });

  test.afterAll(async ({ playwright }) => {
    const api = await adminApi(playwright);
    try {
      const list = await api.get(`/v1/users?search=${encodeURIComponent(USER)}`);
      const users = ((await list.json()) as { users?: { id: string; username: string }[] }).users ?? [];
      for (const u of users.filter((x) => x.username === USER)) await api.delete(`/v1/users/${u.id}`);
    } finally {
      await api.dispose();
    }
  });

  /** Logs in, signs out from the palette, and returns the session cookie's value from before. */
  async function signOutFromPalette(page: Page): Promise<string> {
    const login = await page.request.post('/v1/login', { data: { username: USER, password: PASSWORD } });
    expect(login.ok(), `login failed: ${login.status()}`).toBe(true);
    const session = (await page.context().cookies()).find((c) => c.name === 'gateon_session');
    expect(session, 'login set no gateon_session cookie').toBeDefined();

    const { palette, search } = await openPalette(page);
    await search.fill('sign out');
    await expect(palette.getByText('Ends every session of this account, on every device')).toBeVisible();
    const loggedOut = page.waitForResponse(
      (r) => new URL(r.url()).pathname === '/v1/logout' && r.request().method() === 'POST',
    );
    await search.press('Enter');
    expect((await loggedOut).status(), 'POST /v1/logout').toBe(200);
    await expect(page).toHaveURL(/\/login$/);
    return session!.value;
  }

  test('Sign out tells the gateway, drops the cookie and returns to the login page', async ({ page }) => {
    await signOutFromPalette(page);
    const left = (await page.context().cookies()).find((c) => c.name === 'gateon_session');
    expect(left?.value ?? '', 'the browser still holds the session cookie').toBe('');
    expect((await page.request.get('/v1/me')).status(), 'the browser is still signed in').toBe(401);
  });

  test('a signed-out session cannot be used again', async ({ page }) => {
    // POST /v1/logout used to clear the cookie and nothing else: the PASETO it
    // held stayed valid until it expired, eight hours later, for anyone with a
    // copy. Signing out now advances the account's session epoch, which every
    // earlier session of the account stops matching (internal/auth).
    const token = await signOutFromPalette(page);
    // The old cookie, presented on purpose, as whoever copied it would.
    const replay = await page.request.get('/v1/me', { headers: { Cookie: `gateon_session=${token}` } });
    expect(replay.status(), 'the signed-out session still works').toBe(401);
  });
});
