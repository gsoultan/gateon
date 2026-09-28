// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test, expect } from '@playwright/test';

/**
 * Stored secrets are write-only (ADR 0028). GET /v1/global used to hand every
 * administrator the PASETO key that signs sessions, among every other stored
 * credential, so one stolen session or one script in the dashboard could mint
 * sessions for any account. Now the read carries a placeholder, and a save that
 * sends the placeholder back keeps the stored secret -- so saving Settings
 * without touching the key must not sign anyone out.
 */

// What the gateway returns in place of a stored secret: storedsecret.Sentinel,
// and STORED_SECRET_SENTINEL in the dashboard; a Go test pins the two equal.
const STORED_SECRET = '__gateon_redacted__';
// config/global.json's session key, the one secret every run of the suite has.
const SESSION_KEY = '12345678901234567890123456789012';

const isGlobal = (method: string) => (r: { url(): string; request(): { method(): string } }) =>
  new URL(r.url()).pathname === '/v1/global' && r.request().method() === method;

test.describe('Settings secrets are write-only', () => {
  test('an administrator reads no secret, saves Settings, and stays signed in', async ({ page }) => {
    const read = page.waitForResponse(isGlobal('GET'));
    await page.goto('/settings');
    const res = await read;
    expect(res.status(), 'GET /v1/global').toBe(200);
    const body = await res.text();
    expect(body, 'GET /v1/global carried the session key').not.toContain(SESSION_KEY);
    const config = JSON.parse(body) as { auth?: { pasetoSecret?: string } };
    expect(config.auth?.pasetoSecret, 'the session key does not read as stored').toBe(STORED_SECRET);

    const save = page.getByRole('button', { name: 'Save Global Configuration' });
    await expect(save).toBeEnabled();
    const saved = page.waitForResponse(isGlobal('PUT'));
    await save.click();
    const put = await saved;
    expect(put.status(), `PUT /v1/global: ${await put.text()}`).toBe(200);
    const sent = put.request().postDataJSON() as { auth?: { pasetoSecret?: string } };
    expect(sent.auth?.pasetoSecret, 'the save sent something other than the placeholder').toBe(STORED_SECRET);
    await expect(page.getByText('Configuration successfully updated!')).toBeVisible();

    // The save kept the key, so the session it signed still verifies.
    const me = await page.request.get('/v1/me');
    expect(me.status(), 'saving Settings signed the administrator out').toBe(200);
    const again = page.waitForResponse(isGlobal('GET'));
    await page.reload();
    expect((await again).status(), 'GET /v1/global after the save').toBe(200);
    await expect(page).toHaveURL(/\/settings/);
  });
});
