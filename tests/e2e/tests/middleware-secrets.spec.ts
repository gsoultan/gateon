// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test, expect, type APIRequestContext, type Page } from '@playwright/test';

/**
 * Middleware secrets are write-only (ADR 0030). An operator -- anyone who may
 * write middlewares -- used to read every basic-auth password, signing key,
 * client secret and API key verbatim, so one stolen session or one script in
 * the dashboard carried them off. Now the dashboard reads placeholders, shows
 * them as "Stored", and a save that sends the placeholders back keeps the
 * stored passwords: the route goes on authenticating the same users.
 */

const PROXY = 'http://localhost:8081';
const STORED = '__gateon_redacted__';
const stamp = Date.now();
const MW = `mwsecret-e2e-${stamp}`;
const NAME = `Secret MW e2e ${stamp}`;
const ROUTE = `mwsecret-e2e-route-${stamp}`;
const PREFIX = `/mwsecret-e2e-${stamp}`;
// Distinct and random on every run: nothing the dashboard reads may contain them.
const ALICE = `S3CR3T-alice-${stamp}-${Math.random().toString(36).slice(2)}`;
const BOB = `S3CR3T-bob-${stamp}-${Math.random().toString(36).slice(2)}`;

function operatorApi(playwright: { request: { newContext: (o: object) => Promise<APIRequestContext> } }) {
  return playwright.request.newContext({ baseURL: 'http://localhost:8080', storageState: 'tests/.auth/operator.json' });
}

const basic = (user: string, password: string) => 'Basic ' + Buffer.from(`${user}:${password}`).toString('base64');

type Playwright = { request: { newContext: (o?: object) => Promise<APIRequestContext> } };

/**
 * The status the route answers with these credentials, once the router has
 * caught up. Each probe is a new client with no cookies: the proxy is reached
 * as a stranger would reach it, not with the operator's session.
 */
async function expectStatus(playwright: Playwright, auth: string | undefined, want: number, message: string) {
  await expect
    .poll(
      async () => {
        const client = await playwright.request.newContext();
        try {
          const res = await client.get(`${PROXY}${PREFIX}/probe`, { headers: auth ? { Authorization: auth } : {}, timeout: 5_000 });
          return res.status();
        } catch (e) {
          return String(e).split('\n')[0];
        } finally {
          await client.dispose();
        }
      },
      { message, timeout: 20_000 },
    )
    .toBe(want);
}

/**
 * Every management API response the page reads, as text, from now on. The
 * /v1/watch event stream is left out: it never ends while the page is open, so
 * its body never resolves, and it carries audit entries and threats -- an
 * audit entry names a middleware's id, never its config.
 */
function recordResponses(page: Page) {
  const bodies: Promise<string>[] = [];
  page.on('response', (r) => {
    const stream = (r.headers()['content-type'] ?? '').includes('text/event-stream');
    if (new URL(r.url()).pathname.startsWith('/v1/') && !stream) {
      bodies.push(r.text().catch(() => ''));
    }
  });
  return async () => Promise.all(bodies);
}

test.use({ storageState: 'tests/.auth/operator.json' });

test.describe('Middleware secrets are write-only', () => {
  test.setTimeout(150_000);

  test.beforeAll(async ({ playwright }) => {
    const api = await operatorApi(playwright);
    try {
      const mw = await api.put('/v1/middlewares', {
        data: { id: MW, name: NAME, type: 'auth', config: { type: 'basic', realm: 'e2e', users: `alice:${ALICE},bob:${BOB}` } },
      });
      const saved = await mw.text();
      expect(mw.status(), `PUT /v1/middlewares: ${saved}`).toBe(200);
      expect(saved, 'the answer to the save carried a password').not.toContain(ALICE);
      const route = await api.put('/v1/routes', {
        data: { id: ROUTE, name: ROUTE, type: 'http', rule: `PathPrefix(\`${PREFIX}\`)`, serviceId: 'mock-service', middlewares: [MW] },
      });
      expect(route.ok(), `PUT /v1/routes: ${route.status()}`).toBe(true);
    } finally {
      await api.dispose();
    }
  });

  test.afterAll(async ({ playwright }) => {
    const api = await operatorApi(playwright);
    try {
      await api.delete(`/v1/routes/${encodeURIComponent(ROUTE)}`);
      await api.delete(`/v1/middlewares/${encodeURIComponent(MW)}`);
    } finally {
      await api.dispose();
    }
  });

  test('an operator edits a basic-auth middleware without reading a password, and it still authenticates', async ({
    page,
    playwright,
  }) => {
    await expectStatus(playwright, basic('alice', ALICE), 200, 'alice does not authenticate before the edit');
    await expectStatus(playwright, undefined, 401, 'the route lets a request without credentials through');

    const read = recordResponses(page);
    await page.goto('/middlewares');
    await page.getByPlaceholder('Search middlewares...').fill(NAME);
    await page.getByRole('button', { name: `Edit middleware ${NAME}` }).click();
    const edit = page.getByRole('dialog', { name: 'Edit Middleware' });
    await expect(edit.getByText('Stored')).toHaveCount(2);
    await expect(edit.getByLabel('Username').first()).toHaveValue('alice');

    await edit.getByLabel('Friendly Name').fill(`${NAME} edited`);
    const saving = page.waitForResponse((r) => new URL(r.url()).pathname === '/v1/middlewares' && r.request().method() === 'PUT');
    await edit.getByRole('button', { name: 'Save Middleware' }).click();
    const saved = await saving;
    expect(saved.status(), `PUT /v1/middlewares: ${await saved.text()}`).toBe(200);
    const sent = saved.request().postDataJSON() as { config: Record<string, string> };
    expect(sent.config.users, 'the save sent something other than the placeholders').toBe(`alice:${STORED},bob:${STORED}`);

    for (const body of await read()) {
      expect(body, 'a management API response carried a stored password').not.toContain(ALICE);
      expect(body, 'a management API response carried a stored password').not.toContain(BOB);
    }

    // The save kept both passwords, so the route authenticates as before.
    await expectStatus(playwright, basic('alice', ALICE), 200, 'alice no longer authenticates after the save');
    await expectStatus(playwright, basic('bob', BOB), 200, 'bob no longer authenticates after the save');
    await expectStatus(playwright, basic('alice', STORED), 401, 'the placeholder became alice\'s password');
  });
});
