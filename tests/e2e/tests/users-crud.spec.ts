// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test, expect, type APIRequestContext, type Locator, type Page } from '@playwright/test';

/**
 * Users: create an account, change its role, disable and enable it, and
 * delete it, each checked against what the account can then do -- log in,
 * keep a session -- rather than only against the table.
 *
 * Every account here is the spec's own. The shared admin, operator and viewer
 * sessions in tests/.auth belong to every other spec and are never touched.
 */

const stamp = Date.now();
const USER = `e2e-user-${stamp}`;
const PASSWORD = 'correct-horse-battery-staple-1';

type Playwright = { request: { newContext: (o: object) => Promise<APIRequestContext> } };

function adminApi(playwright: Playwright) {
  return playwright.request.newContext({ baseURL: 'http://localhost:8080', storageState: 'tests/.auth/admin.json' });
}

// /v1/login allows five attempts a minute per client address, and every spec
// logs in from loopback. These logins come from an address of their own
// (TEST-NET-2; the harness trusts X-Forwarded-For from loopback, as a gateway
// behind a proxy does), so they neither starve nor are starved by the suite's.
const LOGIN_CLIENT = '198.51.100.61';

/** Logs in as a user in a context of its own; returns the login status and the context. */
async function login(playwright: Playwright, username: string, password: string, client = LOGIN_CLIENT) {
  const ctx = await playwright.request.newContext({
    baseURL: 'http://localhost:8080',
    extraHTTPHeaders: { 'X-Forwarded-For': client },
  });
  const res = await ctx.post('/v1/login', { data: { username, password } });
  return { status: res.status(), ctx };
}

async function loginStatus(playwright: Playwright, username: string, password: string, client = LOGIN_CLIENT) {
  const { status, ctx } = await login(playwright, username, password, client);
  await ctx.dispose();
  return status;
}

function userRow(page: Page, username: string): Locator {
  return page.getByRole('row').filter({ hasText: username });
}

function waitForUserSave(page: Page) {
  return page.waitForResponse((r) => new URL(r.url()).pathname === '/v1/users' && r.request().method() === 'PUT');
}

async function pickRole(page: Page, dialog: Locator, role: string) {
  await dialog.getByLabel('Role').and(page.locator('input')).click();
  await page.getByRole('option', { name: role }).click();
}

async function deleteUserById(playwright: Playwright, username: string) {
  const api = await adminApi(playwright);
  try {
    const list = await api.get(`/v1/users?search=${encodeURIComponent(username)}`);
    const users = ((await list.json()) as { users?: { id: string; username: string }[] }).users ?? [];
    for (const u of users.filter((x) => x.username === username)) await api.delete(`/v1/users/${u.id}`);
  } finally {
    await api.dispose();
  }
}

test.describe('Users', () => {
  test.setTimeout(120_000);

  test.afterAll(async ({ playwright }) => {
    await deleteUserById(playwright, USER);
  });

  test('create, change role, disable, enable and delete an account, each taking effect on login', async ({
    page,
    playwright,
  }) => {
    await page.goto('/users');

    // Create an operator.
    await page.getByRole('button', { name: 'Add User' }).click();
    const create = page.getByRole('dialog', { name: 'Create New User' });
    await create.getByPlaceholder('Enter username').fill(USER);
    await create.getByPlaceholder('Enter password').fill(PASSWORD);
    await pickRole(page, create, 'Operator (Read/Write Config)');
    const created = waitForUserSave(page);
    await create.getByRole('button', { name: 'Create User' }).click();
    expect((await created).status()).toBe(200);
    await expect(page.getByText(`User "${USER}" saved.`)).toBeVisible();
    await expect(create).toBeHidden();
    const row = userRow(page, USER);
    await expect(row).toContainText('operator');

    // The account works, and its session is an operator's.
    const session = await login(playwright, USER, PASSWORD);
    expect(session.status, 'the new account cannot log in').toBe(200);
    const me = (await (await session.ctx.get('/v1/me')).json()) as { user?: { role?: string } };
    expect(me.user?.role).toBe('operator');

    // Change the role: the edit keeps the account, and ends the session
    // issued under the old role.
    await page.getByRole('button', { name: `Edit user ${USER}` }).click();
    const edit = page.getByRole('dialog', { name: 'Edit User' });
    await expect(edit.getByPlaceholder('Enter username')).toHaveValue(USER);
    await pickRole(page, edit, 'Viewer (Read Only)');
    const edited = waitForUserSave(page);
    await edit.getByRole('button', { name: 'Update User' }).click();
    const editedRes = await edited;
    expect(editedRes.status()).toBe(200);
    expect(editedRes.request().postDataJSON()).toMatchObject({ username: USER, role: 'viewer' });
    await expect(row).toContainText('viewer');
    expect((await session.ctx.get('/v1/me')).status(), 'the session outlived the role it was issued for').toBe(401);
    await session.ctx.dispose();

    // Disable: the account can no longer log in. Enable: it can again.
    const disabled = waitForUserSave(page);
    await page.getByRole('button', { name: `Disable user ${USER}` }).click();
    expect(((await disabled).request().postDataJSON() as { disabled?: boolean }).disabled).toBe(true);
    await expect(row).toContainText('Disabled');
    expect(await loginStatus(playwright, USER, PASSWORD), 'a disabled account logged in').not.toBe(200);

    const enabled = waitForUserSave(page);
    await page.getByRole('button', { name: `Enable user ${USER}` }).click();
    expect(((await enabled).request().postDataJSON() as { disabled?: boolean }).disabled).toBe(false);
    await expect(row.getByText('Disabled', { exact: true })).toHaveCount(0);
    expect(await loginStatus(playwright, USER, PASSWORD), 'a re-enabled account cannot log in').toBe(200);

    // Delete: asked first, naming the account; Cancel keeps it.
    const deletes: string[] = [];
    page.on('request', (r) => {
      if (r.method() === 'DELETE' && new URL(r.url()).pathname.startsWith('/v1/users/')) deletes.push(r.url());
    });
    await page.getByRole('button', { name: `Delete user ${USER}` }).click();
    const confirm = page.getByRole('dialog', { name: 'Delete user' });
    await expect(confirm, 'the confirmation does not say which account').toBeVisible();
    await expect(confirm).toContainText(`"${USER}"`);
    await confirm.getByRole('button', { name: 'Cancel' }).click();
    expect(deletes, 'Cancel deleted the account').toEqual([]);

    await page.getByRole('button', { name: `Delete user ${USER}` }).click();
    const deleted = page.waitForResponse((r) => r.request().method() === 'DELETE' && new URL(r.url()).pathname.startsWith('/v1/users/'));
    await page.getByRole('dialog', { name: 'Delete user' }).getByRole('button', { name: 'Delete user' }).click();
    expect((await deleted).status()).toBe(200);
    await expect(page.getByText(`User "${USER}" deleted.`)).toBeVisible();
    await expect(row).toHaveCount(0);
    expect(await loginStatus(playwright, USER, PASSWORD), 'a deleted account logged in').not.toBe(200);
  });

  test('a save the gateway refuses says so and keeps the form', async ({ page }) => {
    await page.route('**/v1/users', (route) =>
      route.request().method() === 'PUT'
        ? route.fulfill({ status: 500, contentType: 'application/json', body: '{"error":"user store unavailable"}' })
        : route.continue(),
    );
    await page.goto('/users');
    await page.getByRole('button', { name: 'Add User' }).click();
    const create = page.getByRole('dialog', { name: 'Create New User' });
    await create.getByPlaceholder('Enter username').fill(`${USER}-refused`);
    await create.getByPlaceholder('Enter password').fill(PASSWORD);
    // Viewer is preselected; choosing it again must keep it, not clear it.
    await pickRole(page, create, 'Viewer (Read Only)');
    await expect(create.getByLabel('Role').and(page.locator('input'))).toHaveValue('Viewer (Read Only)');
    await create.getByRole('button', { name: 'Create User' }).click();
    const refused = page.getByRole('alert').filter({ hasText: 'Could not save user' });
    await expect(refused, 'a refused save went unreported').toBeVisible();
    await expect(refused).toContainText('user store unavailable');
    await expect(create, 'the form closed on a refused save').toBeVisible();
    await expect(create.getByPlaceholder('Enter username')).toHaveValue(`${USER}-refused`);
  });

  test("adding a user whose name is taken leaves the existing account alone", async ({ page, playwright }) => {
    // OPEN (mgmt/sec, internal/auth/queries.go): the user insert is
    // "INSERT ... ON CONFLICT(username) DO UPDATE SET password, role", and the
    // same PUT /v1/users serves Add User. So adding a user under a name that
    // exists replaces that account's password and role, and the dashboard
    // reports it as saved. Seen from Add User it is data loss; an administrator
    // who types a colleague's name takes over their account. When the gateway
    // refuses the duplicate, this test passes and the annotation must go.
    test.fail();
    const taken = `${USER}-taken`;
    const api = await adminApi(playwright);
    try {
      const made = await api.put('/v1/users', { data: { username: taken, password: PASSWORD, role: 'viewer' } });
      expect(made.ok(), `PUT /v1/users: ${made.status()}`).toBe(true);
    } finally {
      await api.dispose();
    }
    try {
      await page.goto('/users');
      await page.getByRole('button', { name: 'Add User' }).click();
      const create = page.getByRole('dialog', { name: 'Create New User' });
      await create.getByPlaceholder('Enter username').fill(taken);
      await create.getByPlaceholder('Enter password').fill('a-different-password-2');
      await pickRole(page, create, 'Administrator (Full Access)');
      const answered = waitForUserSave(page);
      await create.getByRole('button', { name: 'Create User' }).click();
      await answered;
      // The existing account first: that is the damage.
      expect(
        await loginStatus(playwright, taken, PASSWORD, '198.51.100.62'),
        "the existing account's password was replaced",
      ).toBe(200);
      expect(
        await loginStatus(playwright, taken, 'a-different-password-2', '198.51.100.62'),
        'the password typed into Add User opens the existing account',
      ).not.toBe(200);
      await expect(page.getByRole('alert').filter({ hasText: 'Could not save user' })).toBeVisible({ timeout: 5000 });
    } finally {
      await deleteUserById(playwright, taken);
    }
  });
});
