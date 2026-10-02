// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test, expect, type APIRequestContext, type Browser, type Page } from '@playwright/test';
import { createHmac } from 'crypto';

/**
 * Two-factor sign-in through the dashboard, end to end (ADR 0039).
 *
 * The second step used to take an account id and a code and nothing else, so
 * an id -- which a viewer reads in the audit log -- and one code signed anyone
 * in with no password. It now needs the challenge the password step answers
 * with. These drive the sign-in page as a person does, for the enrolment an
 * administrator requires and for the sign-in after it, and check the gateway
 * refuses the step without the challenge.
 *
 * The account is the spec's own; the shared sessions in tests/.auth are not
 * touched.
 */

const USER = `e2e-2fa-${Date.now()}`;
const PASSWORD = 'correct-horse-battery-staple-2';
// Sign-ins from an address of their own, so the per-address login limit
// neither starves nor is starved by the rest of the suite (see users-crud).
const CLIENT = '198.51.100.81';

type Playwright = { request: { newContext: (o: object) => Promise<APIRequestContext> } };

function adminApi(playwright: Playwright) {
  return playwright.request.newContext({ baseURL: 'http://localhost:8080', storageState: 'tests/.auth/admin.json' });
}

/** RFC 6238 TOTP (SHA-1, 30 s, 6 digits) for a base32 secret, as an authenticator computes it. */
function totp(secret: string, at = Date.now()): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const ch of secret.replace(/=+$/, '').toUpperCase()) {
    bits += alphabet.indexOf(ch).toString(2).padStart(5, '0');
  }
  const key = Buffer.from((bits.match(/.{8}/g) ?? []).map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 30000)));
  const mac = createHmac('sha1', key).update(counter).digest();
  const offset = mac[mac.length - 1] & 0xf;
  return String((mac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, '0');
}

async function freshPage(browser: Browser): Promise<Page> {
  const ctx = await browser.newContext({ extraHTTPHeaders: { 'X-Forwarded-For': CLIENT } });
  return ctx.newPage();
}

async function submitPassword(page: Page) {
  await page.goto('/login');
  await page.getByPlaceholder('Enter your username').fill(USER);
  await page.getByPlaceholder('••••••••').fill(PASSWORD);
  await page.getByRole('button', { name: /Continue to Dashboard/i }).click();
}

/** Submits the code and returns the body the page sent to the second step. */
async function submitCode(page: Page, code: string, button: RegExp) {
  await page.getByLabel('Verification Code').fill(code);
  const sent = page.waitForRequest((r) => new URL(r.url()).pathname === '/v1/auth/2fa/verify');
  await page.getByRole('button', { name: button }).click();
  return (await sent).postDataJSON() as { id?: string; code?: string; challenge?: string };
}

async function expectSignedInWithoutStoredChallenge(page: Page) {
  await expect(page.getByRole('heading', { name: /System Overview/i })).toBeVisible({ timeout: 60000 });
  const stored = await page.evaluate(() => JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage }));
  expect(stored, 'a token reached web storage').not.toContain('v4.local.');
}

test.describe('two-factor sign-in', () => {
  let secret = '';
  let userId = '';

  test.beforeAll(async ({ playwright }) => {
    const api = await adminApi(playwright);
    try {
      const made = await api.put('/v1/users', {
        data: { username: USER, password: PASSWORD, role: 'viewer', twoFactorPending: true },
      });
      expect(made.ok(), `PUT /v1/users: ${made.status()}`).toBe(true);
    } finally {
      await api.dispose();
    }
  });

  test.afterAll(async ({ playwright }) => {
    const api = await adminApi(playwright);
    try {
      const list = await api.get(`/v1/users?search=${encodeURIComponent(USER)}`);
      const users = ((await list.json()) as { users?: { id: string; username: string }[] }).users ?? [];
      for (const u of users.filter((x) => x.username === USER)) await api.delete(`/v1/users/${u.id}`);
    } finally {
      await api.dispose();
    }
  });

  test('a required enrolment signs in with the password step\'s challenge', async ({ browser }) => {
    const page = await freshPage(browser);
    await submitPassword(page);
    await expect(page.getByRole('heading', { name: 'Set Up Two-Factor' })).toBeVisible();
    secret = (await page.getByText('Or enter this secret manually').locator('code').innerText()).trim();
    expect(secret).toMatch(/^[A-Z2-7]+=*$/);

    const sent = await submitCode(page, totp(secret), /Verify & Enable/);
    expect(sent.challenge ?? '', 'the enrolment step carried no challenge').toMatch(/^v4\.local\./);
    userId = sent.id ?? '';
    await expectSignedInWithoutStoredChallenge(page);
    await page.context().close();
  });

  test('the next sign-in asks for the code and carries the challenge', async ({ browser }) => {
    test.skip(!secret, 'needs the enrolment above');
    const page = await freshPage(browser);
    await submitPassword(page);
    await expect(page.getByLabel('Verification Code')).toBeVisible();

    const sent = await submitCode(page, totp(secret), /Verify & Sign in/);
    expect(sent.challenge ?? '', 'the code step carried no challenge').toMatch(/^v4\.local\./);
    await expectSignedInWithoutStoredChallenge(page);
    await page.context().close();
  });

  test('an id and a valid code without the password step are refused', async ({ playwright }) => {
    test.skip(!secret || !userId, 'needs the enrolment above');
    const ctx = await playwright.request.newContext({
      baseURL: 'http://localhost:8080',
      extraHTTPHeaders: { 'X-Forwarded-For': CLIENT },
    });
    try {
      for (const challenge of [undefined, '', 'v4.local.not-a-challenge']) {
        const res = await ctx.post('/v1/auth/2fa/verify', { data: { id: userId, code: totp(secret), challenge } });
        expect(res.status(), `challenge ${JSON.stringify(challenge)}`).toBe(401);
        expect(((await res.json()) as { code?: string }).code).toBe('two_factor_challenge_invalid');
        expect(res.headers()['set-cookie'] ?? '', 'a session cookie was set').not.toContain('gateon_session=v4.');
      }
    } finally {
      await ctx.dispose();
    }
  });
});
