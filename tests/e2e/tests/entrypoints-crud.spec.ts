// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test, expect, type Page } from '@playwright/test';

/**
 * EntryPoints: create, edit and delete one from the dashboard.
 *
 * A listener opens and closes only at restart (the form says so), so what an
 * operator can check today is the stored entrypoint -- what the PUT answered,
 * what the table and its totals show, and that a deleted one is gone -- not a
 * socket. The address is one nothing in the suite uses.
 */

const stamp = Date.now();
const NAME = `EP e2e ${stamp}`;
const RENAMED = `EP e2e renamed ${stamp}`;
const ADDRESS = '127.0.0.1:39981';

function waitForSave(page: Page) {
  return page.waitForResponse((r) => new URL(r.url()).pathname === '/v1/entryPoints' && r.request().method() === 'PUT');
}

async function total(page: Page): Promise<number> {
  const card = page.locator('.mantine-Paper-root').filter({ hasText: /^Total/ });
  return Number(await card.locator('p').nth(1).innerText());
}

test.describe('EntryPoints', () => {
  let entryPointId = '';

  test.afterAll(async ({ playwright }) => {
    if (!entryPointId) return;
    const api = await playwright.request.newContext({ baseURL: 'http://localhost:8080', storageState: 'tests/.auth/admin.json' });
    try {
      await api.delete(`/v1/entryPoints/${encodeURIComponent(entryPointId)}`);
    } finally {
      await api.dispose();
    }
  });

  test('create, edit and delete an entrypoint', async ({ page }) => {
    const listed = page.waitForResponse((r) => new URL(r.url()).pathname === '/v1/entryPoints' && r.request().method() === 'GET');
    await page.goto('/entryPoints');
    await listed;
    await expect(page.getByRole('row').filter({ hasText: 'http-plain' })).toBeVisible();
    const before = await total(page);

    await page.getByRole('button', { name: 'Create EntryPoint' }).click();
    const create = page.getByRole('dialog', { name: 'Create New EntryPoint' });
    await expect(create.getByText('Listener changes apply after a restart')).toBeVisible();
    await create.getByLabel('EntryPoint Name').fill(NAME);
    await create.getByLabel('Listening Address').fill(ADDRESS);
    const created = waitForSave(page);
    await create.getByRole('button', { name: 'Create EntryPoint' }).click();
    const createdRes = await created;
    expect(createdRes.status(), `PUT /v1/entryPoints: ${await createdRes.text()}`).toBe(200);
    const saved = (await createdRes.json()) as { id: string; name: string; address: string; accessLogEnabled?: boolean };
    entryPointId = saved.id;
    expect(saved).toMatchObject({ name: NAME, address: ADDRESS, accessLogEnabled: true });
    await expect(page.getByText(`EntryPoint ${entryPointId} has been successfully created/updated.`)).toBeVisible();
    await expect(create).toBeHidden();

    const row = page.getByRole('row').filter({ hasText: entryPointId });
    await expect(row).toContainText(NAME);
    await expect(row).toContainText(ADDRESS);
    await expect(row).toContainText('TCP');
    await expect(row).toContainText('Plain');
    await expect(row).toContainText('Active');
    await expect.poll(() => total(page)).toBe(before + 1);

    // Edit: the drawer opens on what was saved, and the id stays.
    await page.getByRole('button', { name: `Manage entrypoint ${NAME}` }).click();
    await page.getByRole('menuitem', { name: 'Edit' }).click();
    const edit = page.getByRole('dialog', { name: 'Edit EntryPoint' });
    await expect(edit.getByLabel('Listening Address')).toHaveValue(ADDRESS);
    await edit.getByLabel('EntryPoint Name').fill(RENAMED);
    const edited = waitForSave(page);
    await edit.getByRole('button', { name: 'Update EntryPoint' }).click();
    const editedRes = await edited;
    expect(editedRes.status()).toBe(200);
    expect((await editedRes.json()) as object).toMatchObject({ id: entryPointId, name: RENAMED, address: ADDRESS });
    await expect(row).toContainText(RENAMED);

    // Delete asks first, naming it, and Cancel deletes nothing.
    const deletes: string[] = [];
    page.on('request', (r) => {
      if (r.method() === 'DELETE' && new URL(r.url()).pathname.startsWith('/v1/entryPoints/')) deletes.push(r.url());
    });
    await page.getByRole('button', { name: `Manage entrypoint ${RENAMED}` }).click();
    await page.getByRole('menuitem', { name: 'Delete' }).click();
    const confirm = page.getByRole('dialog', { name: 'Delete entrypoint' });
    await expect(confirm, 'Delete removed the entrypoint without asking').toBeVisible();
    await expect(confirm).toContainText(`"${RENAMED}" (${entryPointId})`);
    await confirm.getByRole('button', { name: 'Cancel' }).click();
    await expect(confirm).toBeHidden();
    expect(deletes, 'Cancel deleted the entrypoint').toEqual([]);

    await page.getByRole('button', { name: `Manage entrypoint ${RENAMED}` }).click();
    await page.getByRole('menuitem', { name: 'Delete' }).click();
    const deleted = page.waitForResponse(
      (r) => r.request().method() === 'DELETE' && new URL(r.url()).pathname === `/v1/entryPoints/${entryPointId}`,
    );
    await page.getByRole('dialog', { name: 'Delete entrypoint' }).getByRole('button', { name: 'Delete entrypoint' }).click();
    expect((await deleted).status(), 'DELETE answered').toBe(204);
    await expect(page.getByText('The entrypoint has been successfully removed.')).toBeVisible();
    await expect(row).toHaveCount(0);
    await expect.poll(() => total(page)).toBe(before);
    entryPointId = '';
  });
});
