// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test, expect, type APIRequestContext, type Page } from '@playwright/test';

/**
 * Services, created, edited and deleted from the dashboard, with a route of
 * the spec's own sending traffic to the service so that every change is
 * checked where it matters: on the proxy.
 */

const PROXY = 'http://localhost:8081';
const BACKEND = '127.0.0.1:8082';
// Nothing listens here, so a target pointed at it fails.
const NOWHERE = '127.0.0.1:9';
const stamp = Date.now();
const NAME = `Services e2e ${stamp}`;
const ROUTE = `svc-e2e-route-${stamp}`;
const PREFIX = `/svc-e2e-${stamp}`;

function adminApi(playwright: { request: { newContext: (o: object) => Promise<APIRequestContext> } }) {
  return playwright.request.newContext({ baseURL: 'http://localhost:8080', storageState: 'tests/.auth/admin.json' });
}

async function expectProxyStatus(request: APIRequestContext, ok: boolean, message: string) {
  await expect
    .poll(async () => (await request.get(`${PROXY}${PREFIX}/probe`)).status() === 200, { message, timeout: 20_000 })
    .toBe(ok);
}

function waitForServiceSave(page: Page) {
  return page.waitForResponse((r) => new URL(r.url()).pathname === '/v1/services' && r.request().method() === 'PUT');
}

function serviceRow(page: Page, id: string) {
  return page.getByRole('row').filter({ hasText: id }).first();
}

test.describe('Services', () => {
  test.setTimeout(150_000);
  let serviceId = '';

  test.afterAll(async ({ playwright }) => {
    const api = await adminApi(playwright);
    try {
      await api.delete(`/v1/routes/${encodeURIComponent(ROUTE)}`);
      if (serviceId) await api.delete(`/v1/services/${encodeURIComponent(serviceId)}`);
    } finally {
      await api.dispose();
    }
  });

  test('create, edit and delete a service, each taking effect on the proxy', async ({ page, request, playwright }) => {
    await page.goto('/services');

    // Create.
    await page.getByRole('button', { name: 'Create Service' }).click();
    const create = page.getByRole('dialog', { name: 'Create New Service' });
    await create.getByLabel('Service Name').fill(NAME);
    await create.getByLabel('URL (host:port)').fill(BACKEND);
    const created = waitForServiceSave(page);
    await create.getByRole('button', { name: 'Save Service' }).click();
    const createdRes = await created;
    expect(createdRes.status(), `PUT /v1/services: ${await createdRes.text()}`).toBe(200);
    const saved = (await createdRes.json()) as { id: string; name: string; weightedTargets: { url: string }[] };
    serviceId = saved.id;
    expect(saved.name).toBe(NAME);
    expect(saved.weightedTargets.map((t) => t.url)).toEqual([`http://${BACKEND}`]);
    await expect(page.getByText(`Service ${serviceId} has been successfully created/updated.`)).toBeVisible();
    await expect(create).toBeHidden();
    await page.getByPlaceholder('Search services...').fill(serviceId);
    await expect(serviceRow(page, serviceId)).toContainText(NAME);

    // It serves: a route of the spec's own sends traffic to it.
    const api = await adminApi(playwright);
    try {
      const route = await api.put('/v1/routes', {
        data: { id: ROUTE, name: ROUTE, type: 'http', rule: `PathPrefix(\`${PREFIX}\`)`, serviceId },
      });
      expect(route.ok(), `PUT /v1/routes: ${route.status()}`).toBe(true);
    } finally {
      await api.dispose();
    }
    await expectProxyStatus(request, true, 'the created service does not serve its route');

    // Edit: point the target at nothing, and the route stops answering.
    await page.getByRole('button', { name: `Manage service ${NAME}` }).click();
    await page.getByRole('menuitem', { name: 'Edit' }).click();
    const edit = page.getByRole('dialog', { name: 'Edit Service' });
    await expect(edit.getByLabel('Service Name')).toHaveValue(NAME);
    await edit.getByLabel('URL (host:port)').fill(NOWHERE);
    const edited = waitForServiceSave(page);
    await edit.getByRole('button', { name: 'Save Service' }).click();
    const editedRes = await edited;
    expect(editedRes.status()).toBe(200);
    expect(((await editedRes.json()) as { id: string }).id, 'the edit saved a different service').toBe(serviceId);
    await expectProxyStatus(request, false, 'the route still answers after its only target was moved away');

    // Back to the backend, then delete: asked first, naming the service.
    await page.getByRole('button', { name: `Manage service ${NAME}` }).click();
    await page.getByRole('menuitem', { name: 'Edit' }).click();
    await edit.getByLabel('URL (host:port)').fill(BACKEND);
    const restored = waitForServiceSave(page);
    await edit.getByRole('button', { name: 'Save Service' }).click();
    expect((await restored).status()).toBe(200);
    await expectProxyStatus(request, true, 'the route did not come back with its target');

    const deletes: string[] = [];
    page.on('request', (r) => {
      if (r.method() === 'DELETE' && new URL(r.url()).pathname.startsWith('/v1/services/')) deletes.push(r.url());
    });
    await page.getByRole('button', { name: `Manage service ${NAME}` }).click();
    await page.getByRole('menuitem', { name: 'Delete' }).click();
    const confirm = page.getByRole('dialog', { name: 'Delete service' });
    await expect(confirm, 'Delete removed the service without asking').toBeVisible();
    await expect(confirm).toContainText(`"${NAME}" (${serviceId})`);
    await confirm.getByRole('button', { name: 'Cancel' }).click();
    await expect(confirm).toBeHidden();
    expect(deletes, 'Cancel deleted the service').toEqual([]);

    await page.getByRole('button', { name: `Manage service ${NAME}` }).click();
    await page.getByRole('menuitem', { name: 'Delete' }).click();
    const deleted = page.waitForResponse(
      (r) => r.request().method() === 'DELETE' && new URL(r.url()).pathname === `/v1/services/${serviceId}`,
    );
    await page.getByRole('dialog', { name: 'Delete service' }).getByRole('button', { name: 'Delete service' }).click();
    expect((await deleted).status(), 'DELETE answered').toBe(204);
    await expect(page.getByText('The service has been successfully removed.')).toBeVisible();
    await expect(page.getByRole('row').filter({ hasText: serviceId })).toHaveCount(0);
    // The route that used it has lost its upstream.
    await expectProxyStatus(request, false, 'the route still reaches the deleted service');
    serviceId = '';
  });
});
