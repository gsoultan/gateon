// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test, expect, type Page, type Request } from '@playwright/test';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

/**
 * Client Authorities: the CAs trusted for mTLS. Add one by pasting its PEM,
 * pick the client-auth policy, find it offered where TLS options choose CAs,
 * and remove it by name.
 *
 * Like Certificates, the page saves the whole tls section of the global
 * configuration, so each save is checked for what it must not change.
 */

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// The suite's self-signed certificate is its own issuer, so it serves as a CA.
const CA_PEM = fs.readFileSync(path.resolve(__dirname, '..', 'cert.pem'), 'utf8');
const NAME = `CA e2e ${Date.now()}`;

interface TlsBody {
  tls?: {
    enabled?: boolean;
    certificates?: { name: string }[];
    clientAuthorities?: { id: string; name: string; caFile?: string; clientAuthType?: string }[];
  };
}

function globalSaves(page: Page): Request[] {
  const puts: Request[] = [];
  page.on('request', (r) => {
    if (r.method() === 'PUT' && new URL(r.url()).pathname === '/v1/global') puts.push(r);
  });
  return puts;
}

async function openAuthorities(page: Page) {
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === '/v1/global' && r.request().method() === 'GET');
  await page.goto('/client-authorities');
  expect((await loaded).status()).toBe(200);
  await expect(page.getByRole('heading', { name: 'Client Authorities', level: 2 })).toBeVisible();
}

async function saveTls(page: Page, click: () => Promise<void>): Promise<TlsBody> {
  const saved = page.waitForResponse((r) => new URL(r.url()).pathname === '/v1/global' && r.request().method() === 'PUT');
  await click();
  const res = await saved;
  expect(res.status(), `PUT /v1/global: ${await res.text()}`).toBe(200);
  const body = res.request().postDataJSON() as TlsBody;
  expect(body.tls?.enabled, 'saving a client authority turned TLS off').toBe(true);
  expect(body.tls?.certificates?.map((c) => c.name), 'saving a client authority dropped a certificate').toContain(
    'Test Certificate',
  );
  await expect(page.getByText('Client authorities updated successfully!')).toBeVisible();
  return body;
}

test.describe('Client Authorities', () => {
  test.setTimeout(90_000);

  test('add a CA by paste with an mTLS policy, find it in TLS options, and remove it by name', async ({ page }) => {
    await openAuthorities(page);

    await page.getByRole('button', { name: 'Add CA' }).click();
    const dialog = page.getByRole('dialog', { name: 'Add Client Authority' });
    await dialog.getByLabel('Name', { exact: true }).fill(NAME);
    await expect(dialog, 'naming a new authority retitled the dialog').toBeVisible();

    await dialog.getByRole('button', { name: 'Paste CA certificate' }).click();
    const paste = page.getByRole('dialog', { name: 'Paste CA Certificate' });
    await paste.getByLabel('PEM Content').fill(CA_PEM);
    const pasted = page.waitForResponse((r) => new URL(r.url()).pathname === '/v1/certs/paste');
    await paste.getByRole('button', { name: 'Confirm and Save' }).click();
    const pastedRes = await pasted;
    expect(pastedRes.status()).toBe(200);
    expect(pastedRes.request().postDataJSON()).toMatchObject({ type: 'ca' });
    const caPath = ((await pastedRes.json()) as { path: string }).path;
    await expect(dialog.getByLabel('CA Certificate File')).toHaveValue(caPath);

    await dialog.getByLabel('Client Auth Type').and(page.locator('input')).click();
    await page.getByRole('option', { name: 'RequireAndVerifyClientCert (mTLS)' }).click();

    const added = await saveTls(page, () => dialog.getByRole('button', { name: 'Save Authority' }).click());
    const saved = added.tls?.clientAuthorities?.find((c) => c.name === NAME);
    expect(saved).toMatchObject({ caFile: caPath, clientAuthType: 'RequireAndVerifyClientCert' });
    const row = page.getByRole('row').filter({ hasText: NAME });
    await expect(row).toContainText(caPath);
    await expect(row).toContainText('RequireAndVerifyClientCert');

    // Offered where a TLS option picks the CAs it trusts.
    await page.goto('/tls-options');
    await page.getByRole('button', { name: 'Add TLS Option' }).click();
    const option = page.getByRole('dialog', { name: 'Add TLS Option' });
    await option.getByLabel('Client Auth Type').and(page.locator('input')).click();
    await page.getByRole('option', { name: 'Require and verify' }).click();
    await option.getByLabel('Client Authorities (CA bundles)').and(page.locator('input')).click();
    await expect(page.getByRole('option', { name: `${NAME} (${saved!.id})` })).toBeVisible();
    await page.keyboard.press('Escape');

    // Remove: asked first, naming it; Cancel keeps it.
    await openAuthorities(page);
    const puts = globalSaves(page);
    await page.getByRole('button', { name: `Remove client authority ${NAME}` }).click();
    const confirm = page.getByRole('dialog', { name: 'Delete client authority' });
    await expect(confirm, 'Remove deleted the authority without asking').toBeVisible();
    await expect(confirm).toContainText(`"${NAME}"`);
    await confirm.getByRole('button', { name: 'Cancel' }).click();
    await expect(confirm).toBeHidden();
    expect(puts, 'Cancel saved the configuration').toEqual([]);

    await page.getByRole('button', { name: `Remove client authority ${NAME}` }).click();
    const removed = await saveTls(page, () =>
      page.getByRole('dialog', { name: 'Delete client authority' }).getByRole('button', { name: 'Delete client authority' }).click(),
    );
    expect(removed.tls?.clientAuthorities?.map((c) => c.name) ?? []).not.toContain(NAME);
    await expect(page.getByRole('row').filter({ hasText: NAME })).toHaveCount(0);
  });

  test('a failed load offers nothing to save, so it cannot overwrite TLS', async ({ page }) => {
    const puts = globalSaves(page);
    await page.route('**/v1/global', (route) =>
      route.request().method() === 'GET'
        ? route.fulfill({ status: 500, contentType: 'application/json', body: '{"error":"gateway unavailable"}' })
        : route.fulfill({ status: 500, contentType: 'application/json', body: '{"error":"refused by the test"}' }),
    );
    await page.goto('/client-authorities');
    const failed = page.getByRole('alert').filter({ hasText: 'Client authorities could not be loaded' });
    await expect(failed, 'a failed load was shown as an empty list').toBeVisible();
    await expect(failed).toContainText('gateway unavailable');
    await expect(page.getByText('No client authorities configured')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Add CA' })).toBeDisabled();

    await page.unroute('**/v1/global');
    await failed.getByRole('button', { name: 'Retry' }).click();
    await expect(failed).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Add CA' })).toBeEnabled();
    expect(puts, 'the configuration was saved while it was unknown').toEqual([]);
  });
});
