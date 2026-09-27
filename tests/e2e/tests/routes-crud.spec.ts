// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test, expect, type APIRequestContext, type Page } from '@playwright/test';

/**
 * Routes, driven the way an operator does it: the four-step form to create
 * one, the row menu to edit, pause, resume and delete it. Each change is
 * checked on the proxy as well as on the page -- a route the list shows but
 * the router does not serve is the failure that matters.
 */

const PROXY = 'http://localhost:8081';
const stamp = Date.now();
const NAME = `Routes e2e ${stamp}`;
const RENAMED = `Routes e2e renamed ${stamp}`;
const PREFIX = `/routes-e2e-${stamp}`;

/** What the proxy answers for the route's prefix, once the router has caught up. */
async function expectProxyStatus(request: APIRequestContext, status: number, message: string) {
  await expect
    .poll(async () => (await request.get(`${PROXY}${PREFIX}/probe`)).status(), { message, timeout: 20_000 })
    .toBe(status);
}

function waitForRouteSave(page: Page) {
  return page.waitForResponse((r) => new URL(r.url()).pathname === '/v1/routes' && r.request().method() === 'PUT');
}

async function openRowMenu(page: Page, name: string) {
  await page.getByPlaceholder('Search ID, name, rule, service...').fill(name);
  await page.getByRole('button', { name: `Manage route ${name}` }).click();
}

/** Steps through the form from wherever it is to Review, and saves. */
async function finishForm(page: Page, drawerName: string) {
  const drawer = page.getByRole('dialog', { name: drawerName });
  for (let i = 0; i < 3 && (await drawer.getByRole('button', { name: 'Next Step' }).count()) > 0; i++) {
    await drawer.getByRole('button', { name: 'Next Step' }).click();
  }
  const saved = waitForRouteSave(page);
  await drawer.getByRole('button', { name: 'Save Route' }).click();
  const res = await saved;
  expect(res.status(), `PUT /v1/routes: ${await res.text()}`).toBe(200);
  await expect(drawer).toBeHidden();
  return res.json() as Promise<{ id: string; name: string; rule: string; serviceId: string; disabled?: boolean }>;
}

test.describe('Routes', () => {
  test.setTimeout(150_000);
  let routeId = '';

  // A failed run must not leave a route behind for the next spec to trip on.
  test.afterAll(async ({ playwright }) => {
    if (!routeId) return;
    const api = await playwright.request.newContext({ baseURL: 'http://localhost:8080', storageState: 'tests/.auth/admin.json' });
    try {
      await api.delete(`/v1/routes/${encodeURIComponent(routeId)}`);
    } finally {
      await api.dispose();
    }
  });

  test('create, edit, pause, resume and delete a route, each taking effect on the proxy', async ({ page, request }) => {
    await expectProxyStatus(request, 404, 'the prefix is already routed before the test created anything');
    await page.goto('/routes');

    // Create.
    await page.getByRole('button', { name: 'Create Route' }).click();
    const create = page.getByRole('dialog', { name: 'Create New Route' });
    await create.getByLabel('Friendly Name').fill(NAME);
    await create.getByRole('button', { name: 'Add first condition' }).click();
    await create.getByLabel('Path prefix').fill(PREFIX);
    await create.getByRole('button', { name: 'Next Step' }).click();
    await create.getByPlaceholder('Choose a service').click();
    await page.getByRole('option', { name: 'Mock Service (http)' }).click();
    const created = await finishForm(page, 'Create New Route');
    routeId = created.id;
    expect(created).toMatchObject({ name: NAME, rule: `PathPrefix(\`${PREFIX}\`)`, serviceId: 'mock-service' });
    await expect(page.getByText(`Route ${routeId} has been successfully created/updated.`)).toBeVisible();
    await expectProxyStatus(request, 200, 'the created route does not serve its prefix');

    // Edit: a new name, the same route.
    await openRowMenu(page, NAME);
    await page.getByRole('menuitem', { name: 'Edit' }).click();
    const edit = page.getByRole('dialog', { name: 'Edit Route' });
    await expect(edit.getByLabel('Friendly Name')).toHaveValue(NAME);
    await edit.getByLabel('Friendly Name').fill(RENAMED);
    const edited = await finishForm(page, 'Edit Route');
    expect(edited).toMatchObject({ id: routeId, name: RENAMED, rule: `PathPrefix(\`${PREFIX}\`)` });
    await page.getByPlaceholder('Search ID, name, rule, service...').fill(RENAMED);
    await expect(page.getByRole('row').filter({ hasText: RENAMED })).toContainText(routeId);

    // Pause: kept, but no longer served.
    await openRowMenu(page, RENAMED);
    const paused = waitForRouteSave(page);
    await page.getByRole('menuitem', { name: 'Pause' }).click();
    expect((await paused).status()).toBe(200);
    await expect(page.getByText(`"${RENAMED}" is now paused.`)).toBeVisible();
    await expect(page.getByRole('row').filter({ hasText: RENAMED })).toContainText('PAUSED');
    await expectProxyStatus(request, 404, 'a paused route is still served');

    // Resume.
    await openRowMenu(page, RENAMED);
    const resumed = waitForRouteSave(page);
    await page.getByRole('menuitem', { name: 'Resume' }).click();
    expect((await resumed).status()).toBe(200);
    await expect(page.getByText(`"${RENAMED}" is now active.`)).toBeVisible();
    await expectProxyStatus(request, 200, 'a resumed route is not served again');

    // Delete asks first, naming the route, and Cancel deletes nothing.
    const deletes: string[] = [];
    page.on('request', (r) => {
      if (r.method() === 'DELETE' && new URL(r.url()).pathname.startsWith('/v1/routes/')) deletes.push(r.url());
    });
    await openRowMenu(page, RENAMED);
    await page.getByRole('menuitem', { name: 'Delete' }).click();
    const confirm = page.getByRole('dialog', { name: 'Delete route' });
    await expect(confirm, 'Delete removed the route without asking').toBeVisible();
    await expect(confirm).toContainText(`"${RENAMED}" (${routeId})`);
    await confirm.getByRole('button', { name: 'Cancel' }).click();
    await expect(confirm).toBeHidden();
    expect(deletes, 'Cancel deleted the route').toEqual([]);

    await openRowMenu(page, RENAMED);
    await page.getByRole('menuitem', { name: 'Delete' }).click();
    const deleted = page.waitForResponse((r) => r.request().method() === 'DELETE' && new URL(r.url()).pathname === `/v1/routes/${routeId}`);
    await page.getByRole('dialog', { name: 'Delete route' }).getByRole('button', { name: 'Delete route' }).click();
    expect((await deleted).status(), 'DELETE answered').toBe(204);
    await expect(page.getByText('The route has been successfully removed.')).toBeVisible();
    await expect(page.getByRole('row').filter({ hasText: RENAMED })).toHaveCount(0);
    await expectProxyStatus(request, 404, 'the deleted route is still served');
    routeId = '';
  });
});
