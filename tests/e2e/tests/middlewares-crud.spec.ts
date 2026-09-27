// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test, expect, type APIRequestContext, type Page } from '@playwright/test';

/**
 * Middlewares, built in the dashboard's config editor and checked on the
 * proxy.
 *
 * The editor and the gateway have disagreed before about what a setting is
 * called -- the dashboard wrote camelCase, the factories read snake_case, and
 * seventy-three settings did nothing -- so saving and reading back the JSON is
 * not enough. A header middleware made here is put on a route of the spec's
 * own, and the response has to carry the header.
 */

const PROXY = 'http://localhost:8081';
const stamp = Date.now();
const NAME = `MW e2e ${stamp}`;
const ROUTE = `mw-e2e-route-${stamp}`;
const PREFIX = `/mw-e2e-${stamp}`;
const HEADER = 'X-E2E-Middleware';

function adminApi(playwright: { request: { newContext: (o: object) => Promise<APIRequestContext> } }) {
  return playwright.request.newContext({ baseURL: 'http://localhost:8080', storageState: 'tests/.auth/admin.json' });
}

/** The header the proxy returns for the route, once the router has caught up. */
async function expectHeader(request: APIRequestContext, value: string | undefined, message: string) {
  await expect
    .poll(
      async () => {
        const res = await request.get(`${PROXY}${PREFIX}/probe`);
        return res.status() === 200 ? res.headers()[HEADER.toLowerCase()] ?? 'absent' : `status ${res.status()}`;
      },
      { message, timeout: 20_000 },
    )
    .toBe(value ?? 'absent');
}

function waitForSave(page: Page) {
  return page.waitForResponse((r) => new URL(r.url()).pathname === '/v1/middlewares' && r.request().method() === 'PUT');
}

test.describe('Middlewares', () => {
  test.setTimeout(150_000);
  let middlewareId = '';

  test.beforeAll(async ({ playwright }) => {
    const api = await adminApi(playwright);
    try {
      const route = await api.put('/v1/routes', {
        data: { id: ROUTE, name: ROUTE, type: 'http', rule: `PathPrefix(\`${PREFIX}\`)`, serviceId: 'mock-service' },
      });
      expect(route.ok(), `PUT /v1/routes: ${route.status()}`).toBe(true);
    } finally {
      await api.dispose();
    }
  });

  test.afterAll(async ({ playwright }) => {
    const api = await adminApi(playwright);
    try {
      await api.delete(`/v1/routes/${encodeURIComponent(ROUTE)}`);
      if (middlewareId) await api.delete(`/v1/middlewares/${encodeURIComponent(middlewareId)}`);
    } finally {
      await api.dispose();
    }
  });

  test('a header middleware made in the editor changes responses, follows edits, and is removed with its routes named', async ({
    page,
    request,
    playwright,
  }) => {
    await expectHeader(request, undefined, 'the route carries the header before any middleware exists');
    await page.goto('/middlewares');

    // Create: Header Manipulation, one response header, from the form.
    await page.getByRole('button', { name: 'Add Middleware' }).click();
    const create = page.getByRole('dialog', { name: 'Add Middleware' });
    await create.getByLabel('Friendly Name').fill(NAME);
    await create.getByLabel('Type').and(page.locator('input')).click();
    await page.getByRole('option', { name: 'Header Manipulation', exact: true }).click();
    await create.getByRole('button', { name: 'Add Set Response Headers' }).click();
    await create.getByPlaceholder('X-Header').last().fill(HEADER);
    await create.getByPlaceholder('Value').last().fill('from-the-dashboard');
    const created = waitForSave(page);
    await create.getByRole('button', { name: 'Save Middleware' }).click();
    const createdRes = await created;
    expect(createdRes.status(), `PUT /v1/middlewares: ${await createdRes.text()}`).toBe(200);
    const saved = (await createdRes.json()) as { id: string; type: string; config: Record<string, string> };
    middlewareId = saved.id;
    expect(saved.type).toBe('headers');
    expect(saved.config).toEqual({ [`set_response_${HEADER}`]: 'from-the-dashboard' });
    await expect(page.getByText('The middleware configuration has been updated.')).toBeVisible();
    await page.getByPlaceholder('Search middlewares...').fill(NAME);
    const row = page.getByRole('row').filter({ hasText: middlewareId });
    await expect(row).toContainText(NAME);
    await expect(row).toContainText('headers');

    // On a route, it does what the editor said.
    const api = await adminApi(playwright);
    try {
      const attach = await api.put('/v1/routes', {
        data: {
          id: ROUTE, name: ROUTE, type: 'http', rule: `PathPrefix(\`${PREFIX}\`)`,
          serviceId: 'mock-service', middlewares: [middlewareId],
        },
      });
      expect(attach.ok(), `PUT /v1/routes: ${attach.status()}`).toBe(true);
    } finally {
      await api.dispose();
    }
    await expectHeader(request, 'from-the-dashboard', 'the middleware saved from the editor does nothing on its route');

    // Edit the value; the route follows.
    await page.getByRole('button', { name: `Edit middleware ${NAME}` }).click();
    const edit = page.getByRole('dialog', { name: 'Edit Middleware' });
    await expect(edit.getByPlaceholder('X-Header').last()).toHaveValue(HEADER);
    await edit.getByPlaceholder('Value').last().fill('edited-in-the-dashboard');
    const edited = waitForSave(page);
    await edit.getByRole('button', { name: 'Save Middleware' }).click();
    expect((await edited).status()).toBe(200);
    await expectHeader(request, 'edited-in-the-dashboard', 'the route kept the old header after the edit');

    // Delete: the confirmation names it and the route that uses it.
    await page.getByRole('button', { name: `Delete middleware ${NAME}` }).click();
    const confirm = page.getByRole('dialog', { name: 'Delete Middleware' });
    await expect(confirm).toContainText(`Delete "${NAME}"?`);
    await expect(confirm).toContainText('Used by 1 route:');
    await expect(confirm).toContainText(ROUTE);
    const deleted = page.waitForResponse(
      (r) => r.request().method() === 'DELETE' && new URL(r.url()).pathname === `/v1/middlewares/${middlewareId}`,
    );
    await confirm.getByRole('button', { name: 'Delete', exact: true }).click();
    expect((await deleted).status(), 'DELETE answered').toBe(204);
    await expect(page.getByText('The middleware has been removed.')).toBeVisible();
    await expect(row).toHaveCount(0);
    await expectHeader(request, undefined, 'the route still runs the deleted middleware');
    middlewareId = '';
  });
});
