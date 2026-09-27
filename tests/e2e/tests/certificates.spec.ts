// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test, expect, type Page, type Request } from '@playwright/test';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

/**
 * Certificates: add one by pasting its PEM and uploading its key, see the
 * gateway validate it, and remove it by name.
 *
 * The page edits tls.certificates inside the global configuration and saves
 * the whole tls section back, which the gateway stores as sent. So every save
 * is also checked for what it must not change: TLS stays on and the fixture's
 * own certificate stays in the list.
 *
 * The PEM pair is the suite's own (tests/e2e/cert.pem, key.pem); pasted and
 * uploaded files land in the gateway's data directory, the repo root here.
 */

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CERT_PEM = fs.readFileSync(path.resolve(__dirname, '..', 'cert.pem'), 'utf8');
const KEY_PATH = path.resolve(__dirname, '..', 'key.pem');
const NAME = `Cert e2e ${Date.now()}`;

interface TlsBody {
  tls?: { enabled?: boolean; certificates?: { id: string; name: string; certFile?: string; keyFile?: string }[] };
}

function globalSaves(page: Page): Request[] {
  const puts: Request[] = [];
  page.on('request', (r) => {
    if (r.method() === 'PUT' && new URL(r.url()).pathname === '/v1/global') puts.push(r);
  });
  return puts;
}

async function openCertificates(page: Page) {
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === '/v1/global' && r.request().method() === 'GET');
  await page.goto('/certificates');
  expect((await loaded).status()).toBe(200);
  await expect(page.getByRole('row').filter({ hasText: 'Test Certificate' })).toBeVisible();
}

async function saveTls(page: Page, click: () => Promise<void>): Promise<TlsBody> {
  const saved = page.waitForResponse((r) => new URL(r.url()).pathname === '/v1/global' && r.request().method() === 'PUT');
  await click();
  const res = await saved;
  expect(res.status(), `PUT /v1/global: ${await res.text()}`).toBe(200);
  const body = res.request().postDataJSON() as TlsBody;
  // What a certificate change must leave alone.
  expect(body.tls?.enabled, 'saving a certificate turned TLS off').toBe(true);
  expect(body.tls?.certificates?.map((c) => c.name), 'saving a certificate dropped another').toContain('Test Certificate');
  await expect(page.getByText('Certificates updated successfully!')).toBeVisible();
  return body;
}

test.describe('Certificates', () => {
  test.setTimeout(90_000);

  test('add a certificate by paste and upload, see it validated, and remove it by name', async ({ page }) => {
    await openCertificates(page);

    await page.getByRole('button', { name: 'Add Certificate' }).click();
    const dialog = page.getByRole('dialog', { name: 'Add Certificate' });
    await dialog.getByLabel('Friendly Name').fill(NAME);
    await expect(dialog, 'naming a new certificate retitled the dialog').toBeVisible();

    // The certificate, pasted.
    await dialog.getByRole('button', { name: 'Paste certificate' }).click();
    const paste = page.getByRole('dialog', { name: 'Paste Certificate' });
    await paste.getByLabel('PEM Content').fill(CERT_PEM);
    const pasted = page.waitForResponse((r) => new URL(r.url()).pathname === '/v1/certs/paste');
    await paste.getByRole('button', { name: 'Confirm and Save' }).click();
    const pastedRes = await pasted;
    expect(pastedRes.status()).toBe(200);
    const certPath = ((await pastedRes.json()) as { path: string }).path;
    await expect(paste).toBeHidden();
    await expect(dialog.getByLabel('Certificate File (.crt, .pem)')).toHaveValue(certPath);

    // The key, uploaded.
    const uploaded = page.waitForResponse((r) => new URL(r.url()).pathname === '/v1/certs/upload');
    await dialog.locator('input[type="file"][accept=".pem,.key"]').setInputFiles(KEY_PATH);
    const uploadedRes = await uploaded;
    expect(uploadedRes.status()).toBe(200);
    const keyPath = ((await uploadedRes.json()) as { path: string }).path;
    await expect(dialog.getByLabel('Private Key File (.key, .pem)')).toHaveValue(keyPath);

    const added = await saveTls(page, () => dialog.getByRole('button', { name: 'Save Certificate' }).click());
    expect(added.tls?.certificates?.find((c) => c.name === NAME)).toMatchObject({ certFile: certPath, keyFile: keyPath });
    const row = page.getByRole('row').filter({ hasText: NAME });
    await expect(row).toContainText(certPath);
    await expect(row).toContainText(keyPath);

    // The gateway validates the pair when the configuration is read.
    await openCertificates(page);
    await page.getByRole('button', { name: `Edit certificate ${NAME}` }).click();
    const edit = page.getByRole('dialog', { name: 'Edit Certificate' });
    await expect(edit.getByText('Validation')).toBeVisible();
    await expect(edit.getByText('Recommended Cipher Suites')).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(edit).toBeHidden();

    // Remove: asked first, naming it; Cancel keeps it.
    const puts = globalSaves(page);
    await page.getByRole('button', { name: `Remove certificate ${NAME}` }).click();
    const confirm = page.getByRole('dialog', { name: 'Delete certificate' });
    await expect(confirm, 'Remove deleted the certificate without asking').toBeVisible();
    await expect(confirm).toContainText(`"${NAME}"`);
    await confirm.getByRole('button', { name: 'Cancel' }).click();
    await expect(confirm).toBeHidden();
    expect(puts, 'Cancel saved the configuration').toEqual([]);

    await page.getByRole('button', { name: `Remove certificate ${NAME}` }).click();
    const removed = await saveTls(page, () =>
      page.getByRole('dialog', { name: 'Delete certificate' }).getByRole('button', { name: 'Delete certificate' }).click(),
    );
    expect(removed.tls?.certificates?.map((c) => c.name)).not.toContain(NAME);
    await expect(row).toHaveCount(0);
  });

  test('a failed load offers nothing to save, so it cannot overwrite TLS', async ({ page }) => {
    // Every section a save sends replaces the stored one. A page that shows
    // its empty placeholder after a failed read, and saves from it, sends TLS
    // off with only the new certificate: every other certificate is gone.
    const puts = globalSaves(page);
    await page.route('**/v1/global', (route) =>
      route.request().method() === 'GET'
        ? route.fulfill({ status: 500, contentType: 'application/json', body: '{"error":"gateway unavailable"}' })
        : route.fulfill({ status: 500, contentType: 'application/json', body: '{"error":"refused by the test"}' }),
    );
    await page.goto('/certificates');
    const failed = page.getByRole('alert').filter({ hasText: 'Certificates could not be loaded' });
    await expect(failed, 'a failed load was shown as an empty list').toBeVisible();
    await expect(failed).toContainText('gateway unavailable');
    await expect(page.getByText('No certificates configured')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Add Certificate' })).toBeDisabled();

    await page.unroute('**/v1/global');
    await failed.getByRole('button', { name: 'Retry' }).click();
    await expect(failed).toHaveCount(0);
    await expect(page.getByRole('row').filter({ hasText: 'Test Certificate' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Add Certificate' })).toBeEnabled();
    expect(puts, 'the configuration was saved while it was unknown').toEqual([]);
  });
});
