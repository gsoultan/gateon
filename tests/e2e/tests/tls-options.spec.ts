// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test, expect, type Locator, type Page } from '@playwright/test';

/**
 * TLS Options: named TLS policies routes can use -- protocol versions, cipher
 * suites, strict SNI, client-certificate policy. Create one, see it warn about
 * a deprecated protocol, edit it, and delete it by name.
 */

const stamp = Date.now();
const NAME = `TLS e2e ${stamp}`;

function waitForSave(page: Page) {
  return page.waitForResponse((r) => new URL(r.url()).pathname === '/v1/tls-options' && r.request().method() === 'PUT');
}

async function pick(page: Page, dialog: Locator, label: string, option: string) {
  await dialog.getByLabel(label).and(page.locator('input')).click();
  await page.getByRole('option', { name: option, exact: true }).click();
}

test.describe('TLS Options', () => {
  let optionId = '';

  test.afterAll(async ({ playwright }) => {
    if (!optionId) return;
    const api = await playwright.request.newContext({ baseURL: 'http://localhost:8080', storageState: 'tests/.auth/admin.json' });
    try {
      await api.delete(`/v1/tls-options/${encodeURIComponent(optionId)}`);
    } finally {
      await api.dispose();
    }
  });

  test('create, warn, edit and delete a TLS option', async ({ page }) => {
    await page.goto('/tls-options');
    await page.getByRole('button', { name: 'Add TLS Option' }).click();
    const dialog = page.getByRole('dialog', { name: 'Add TLS Option' });
    await dialog.getByLabel('Friendly Name').fill(NAME);

    // A deprecated floor is called out before it is saved, and goes away
    // when the floor is raised again.
    await pick(page, dialog, 'Min TLS Version', 'TLS 1.0 (Insecure)');
    await expect(dialog.getByRole('alert').filter({ hasText: 'Security Warning' })).toBeVisible();
    await pick(page, dialog, 'Min TLS Version', 'TLS 1.2');
    await expect(dialog.getByText('Security Warning')).toHaveCount(0);

    const created = waitForSave(page);
    await dialog.getByRole('button', { name: 'Save TLS Option' }).click();
    const createdRes = await created;
    expect(createdRes.status(), `PUT /v1/tls-options: ${await createdRes.text()}`).toBe(200);
    const saved = (await createdRes.json()) as { id: string; name: string; minTlsVersion: string; maxTlsVersion: string };
    optionId = saved.id;
    expect(optionId, 'the gateway gave the option no id').not.toBe('');
    expect(saved).toMatchObject({ name: NAME, minTlsVersion: 'TLS1.2', maxTlsVersion: 'TLS1.3' });
    await expect(page.getByText('The TLS configuration has been updated.')).toBeVisible();
    await expect(dialog).toBeHidden();

    await page.getByPlaceholder('Search TLS options...').fill(NAME);
    const row = page.getByRole('row').filter({ hasText: optionId });
    await expect(row).toContainText(NAME);
    await expect(row).toContainText('TLS1.2');
    await expect(row).toContainText('TLS1.3');
    await expect(row).toContainText('Default');

    // Edit: two cipher suites and strict SNI.
    await page.getByRole('button', { name: `Edit TLS option ${NAME}` }).click();
    const edit = page.getByRole('dialog', { name: 'Edit TLS Option' });
    await expect(edit.getByLabel('Friendly Name')).toHaveValue(NAME);
    await edit.getByPlaceholder('Select cipher suites').click();
    await page.getByRole('option', { name: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', exact: true }).click();
    await page.getByRole('option', { name: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', exact: true }).click();
    // Close the list by clicking away: Escape would close the dialog too.
    await edit.getByLabel('Friendly Name').click();
    await edit.getByRole('switch', { name: 'Strict SNI' }).check();
    const edited = waitForSave(page);
    await edit.getByRole('button', { name: 'Save TLS Option' }).click();
    const editedRes = await edited;
    expect(editedRes.status()).toBe(200);
    expect(editedRes.request().postDataJSON()).toMatchObject({
      id: optionId,
      sniStrict: true,
      cipherSuites: ['TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'],
    });
    await expect(row).toContainText('2 selected');
    await expect(row.getByText('Yes', { exact: true })).toBeVisible();

    // Delete: asked first, naming it; Cancel deletes nothing.
    const deletes: string[] = [];
    page.on('request', (r) => {
      if (r.method() === 'DELETE' && new URL(r.url()).pathname.startsWith('/v1/tls-options/')) deletes.push(r.url());
    });
    await page.getByRole('button', { name: `Remove TLS option ${NAME}` }).click();
    const confirm = page.getByRole('dialog', { name: 'Delete TLS option' });
    await expect(confirm, 'the confirmation does not say which option').toBeVisible();
    await expect(confirm).toContainText(`"${NAME}" (${optionId})`);
    await confirm.getByRole('button', { name: 'Cancel' }).click();
    expect(deletes, 'Cancel deleted the option').toEqual([]);

    await page.getByRole('button', { name: `Remove TLS option ${NAME}` }).click();
    const deleted = page.waitForResponse(
      (r) => r.request().method() === 'DELETE' && new URL(r.url()).pathname === `/v1/tls-options/${optionId}`,
    );
    await page.getByRole('dialog', { name: 'Delete TLS option' }).getByRole('button', { name: 'Delete TLS option' }).click();
    expect((await deleted).status(), 'DELETE answered').toBe(204);
    await expect(page.getByText('The TLS option has been removed.')).toBeVisible();
    await expect(row).toHaveCount(0);
    optionId = '';
  });

  test('says so when the options cannot be loaded', async ({ page }) => {
    await page.route('**/v1/tls-options*', (route) =>
      route.fulfill({ status: 500, contentType: 'application/json', body: '{"error":"gateway unavailable"}' }),
    );
    await page.goto('/tls-options');
    const failed = page.getByRole('alert').filter({ hasText: "Couldn't load TLS options" });
    await expect(failed, 'a failed load was shown as an empty list').toBeVisible();
    await expect(failed).toContainText('gateway unavailable');
    await expect(page.getByText('No TLS options configured')).toHaveCount(0);
  });
});
