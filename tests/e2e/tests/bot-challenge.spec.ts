// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test, expect, type APIRequestContext } from '@playwright/test';

/**
 * The bot-management JavaScript challenge (ADR 0045), against the built
 * gateway with a real browser and a real HTTP client that runs no script.
 *
 * T9: on a route with a path rule the page asked for /_gateon/seed, which that
 * route never receives, so every visitor was held on the challenge for ever.
 * The route here is PathPrefix, and the browser must reach the backend.
 *
 * T23: curl passed by fetching the seed, waiting two seconds and posting it
 * back. For that test only, a second route, PathPrefix(`/_gateon`), with the
 * same middleware gives the old flow the endpoints it used (as a Host() route
 * did); it must not yield a pass any more, and neither may anything else a
 * client sends without doing the work. It is not up while the browser runs,
 * or it would hand the old page the paths T9 is about.
 *
 * Every request comes from loopback, whose threats the gateway does not hold
 * against anyone, so the refusals below poison no later spec.
 */

const PROXY = 'http://localhost:8081';
const stamp = Date.now();
const MW = `botchal-e2e-${stamp}`;
const ROUTE = `botchal-e2e-route-${stamp}`;
const LEGACY_ROUTE = `botchal-e2e-legacy-${stamp}`;
const PREFIX = `/botchal-e2e-${stamp}`;
const PAGE = `${PROXY}${PREFIX}/deep/page?tab=2`;
const COOKIE = 'gateon_bot_challenge';

type Playwright = { request: { newContext: (o?: object) => Promise<APIRequestContext> } };

function adminApi(playwright: Playwright) {
  return playwright.request.newContext({ baseURL: 'http://localhost:8080', storageState: 'tests/.auth/admin.json' });
}

async function putRoute(playwright: Playwright, id: string, rule: string) {
  const api = await adminApi(playwright);
  try {
    const route = await api.put('/v1/routes', {
      data: { id, name: id, type: 'http', rule, serviceId: 'mock-service', middlewares: [MW] },
    });
    expect(route.ok(), `PUT /v1/routes ${id}: ${route.status()} ${await route.text()}`).toBe(true);
  } finally {
    await api.dispose();
  }
}

async function deleteRoute(playwright: Playwright, id: string) {
  const api = await adminApi(playwright);
  try {
    await api.delete(`/v1/routes/${encodeURIComponent(id)}`);
  } finally {
    await api.dispose();
  }
}

/**
 * Waits until the router has caught up: url answers `want`, or, with
 * `{ not: true }`, anything but `want`.
 */
async function until(playwright: Playwright, url: string, want: number, opts: { not?: boolean } = {}) {
  const probe = await playwright.request.newContext();
  try {
    const poll = expect.poll(
      async () => (await probe.get(url, { timeout: 5_000 }).catch(() => null))?.status() ?? 0,
      { message: `${url} never came up`, timeout: 30_000 },
    );
    await (opts.not ? poll.not.toBe(want) : poll.toBe(want));
  } finally {
    await probe.dispose();
  }
}

test.describe('Bot challenge', () => {
  test.setTimeout(120_000);

  test.beforeAll(async ({ playwright }) => {
    const api = await adminApi(playwright);
    try {
      const mw = await api.put('/v1/middlewares', {
        data: { id: MW, name: MW, type: 'bot_management', config: { enable_js_challenge: 'true' } },
      });
      expect(mw.status(), `PUT /v1/middlewares: ${await mw.text()}`).toBe(200);
    } finally {
      await api.dispose();
    }
    await putRoute(playwright, ROUTE, `PathPrefix(\`${PREFIX}\`)`);
    await until(playwright, PAGE, 403);
  });

  test.afterAll(async ({ playwright }) => {
    await deleteRoute(playwright, LEGACY_ROUTE);
    await deleteRoute(playwright, ROUTE);
    const api = await adminApi(playwright);
    try {
      await api.delete(`/v1/middlewares/${encodeURIComponent(MW)}`);
    } finally {
      await api.dispose();
    }
  });

  test('a browser runs the challenge on a path-prefix route and reaches the backend', async ({ browser }) => {
    const context = await browser.newContext();
    const page = await context.newPage();
    let documents = 0;
    page.on('response', (r) => {
      if (r.request().resourceType() === 'document') documents++;
    });
    try {
      await page.goto(PAGE);
      // The page solves, answers at its own URL, confirms the cookie and reloads into the backend.
      await expect(page.locator('body')).toContainText('Hello from mock backend', { timeout: 30_000 });
      expect(new URL(page.url()).pathname).toBe(`${PREFIX}/deep/page`);
      const cookies = await context.cookies(PROXY);
      expect(cookies.find((c) => c.name === COOKIE)?.httpOnly, 'no HttpOnly pass cookie was set').toBe(true);
      expect(documents, 'the page reloaded more than once').toBe(2);
    } finally {
      await context.close();
    }
  });

  test('the challenge page explains itself to a screen reader and without JavaScript', async ({ browser }) => {
    const context = await browser.newContext({ javaScriptEnabled: false });
    const page = await context.newPage();
    try {
      const res = await page.goto(PAGE);
      expect(res?.status()).toBe(403);
      await expect(page.getByRole('heading', { level: 1, name: 'Checking your browser' })).toBeVisible();
      await expect(page.getByRole('status')).toContainText('short calculation');
      // Playwright turns script execution off without turning off the
      // parser's scripting flag, so Chromium never renders <noscript> here;
      // the markup is what a browser without JavaScript shows.
      expect(await res!.text()).toMatch(/<noscript><p>This check needs JavaScript\. [^<]+<\/p><\/noscript>/);
      await expect(page.locator('html')).toHaveAttribute('lang', 'en');
    } finally {
      await context.close();
    }
  });

  test('a refused answer is explained and waits for the visitor instead of looping', async ({ browser }) => {
    const context = await browser.newContext();
    const page = await context.newPage();
    let documents = 0;
    page.on('response', (r) => {
      if (r.request().resourceType() === 'document') documents++;
    });
    // The gateway refuses this visitor's answer.
    await page.route((url) => url.pathname === `${PREFIX}/deep/page`, async (route) => {
      if ((await route.request().headerValue('x-gateon-challenge')) === 'answer') {
        await route.fulfill({ status: 403, body: '' });
        return;
      }
      await route.continue();
    });
    try {
      await page.goto(PAGE);
      await expect(page.getByRole('status')).toContainText('could not confirm this check', { timeout: 30_000 });
      const retry = page.getByRole('button', { name: 'Try again' });
      await expect(retry).toBeVisible();
      await expect(retry).toBeFocused();
      expect(documents, 'a failed check reloaded the page by itself').toBe(1);
    } finally {
      await context.close();
    }
  });

  test('a client that does not run the script does not pass', async ({ playwright }) => {
    await putRoute(playwright, LEGACY_ROUTE, 'PathPrefix(`/_gateon`)');
    await until(playwright, `${PROXY}/_gateon/seed`, 404, { not: true });
    const curl = await playwright.request.newContext({ extraHTTPHeaders: { 'User-Agent': 'curl/8.4.0' } });
    try {
      // The old flow, verbatim: fetch the seed, wait the two seconds the page
      // waited, post it back. It used to set the pass cookie.
      const seed = await curl.get(`${PROXY}/_gateon/seed`);
      const token = await seed.text();
      await new Promise((r) => setTimeout(r, 2_100));
      const posted = await curl.post(`${PROXY}/_gateon/challenge`, {
        form: { token, redirect: `${PREFIX}/deep/page` },
        maxRedirects: 0,
      });
      expect(posted.headers()['set-cookie'] ?? '', 'the wait-only flow was handed a pass').not.toContain(COOKIE);

      const first = await curl.get(PAGE);
      expect(first.status()).toBe(403);
      const html = await first.text();
      expect(html, 'the challenge page sends the browser to a /_gateon/ path').not.toContain('/_gateon/');
      const id = /var id = "([^"]+)"/.exec(html)?.[1];
      expect(id, 'the challenge page carries no challenge').toBeTruthy();

      // Everything the page hands over, sent back without the work.
      const answer = await curl.get(PAGE, {
        headers: { 'X-Gateon-Challenge': 'answer', 'X-Gateon-Challenge-ID': id!, 'X-Gateon-Challenge-Nonce': '0' },
      });
      expect(answer.status(), 'an answer without the work was accepted').toBe(403);
      const asCookie = await curl.get(PAGE, { headers: { Cookie: `${COOKIE}=${id}` } });
      expect(asCookie.status(), 'the challenge ID from the page source worked as a pass').toBe(403);

      const last = await curl.get(PAGE);
      expect(last.status(), 'a client that ran no script reached the backend').toBe(403);
    } finally {
      await curl.dispose();
      await deleteRoute(playwright, LEGACY_ROUTE);
    }
  });
});
