// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { expect, type APIRequestContext, type APIResponse, type Page } from '@playwright/test';
import { createHmac } from 'crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';

/**
 * Signing in with the second factor every account must have (ADR 0087).
 *
 * The password step never ends a sign-in: an account without a second factor
 * enrols an authenticator first, and the session comes from a code. The
 * secret an account enrolled with is kept in tests/.auth/<username>.totp, next
 * to the shared sessions, so a spec that signs the same account in again --
 * the setup projects' admin, operator and viewer above all -- can answer.
 */

const AUTH_DIR = 'tests/.auth';

/** RFC 6238 TOTP (SHA-1, 30 s, 6 digits) for a base32 secret, as an authenticator computes it. */
export function totp(secret: string, at = Date.now()): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const ch of secret.replace(/=+$/, '').toUpperCase()) {
    bits += alphabet.indexOf(ch).toString(2).padStart(5, '0');
  }
  const key = Buffer.from((bits.match(/.{8}/g) ?? []).map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 30000)));
  const mac = createHmac('sha1', key).update(counter).digest();
  const offset = (mac[mac.length - 1] ?? 0) & 0xf;
  return String((mac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, '0');
}

function secretFile(username: string): string {
  return `${AUTH_DIR}/${username.replace(/[^A-Za-z0-9._-]/g, '_')}.totp`;
}

/** Records the authenticator secret username enrolled with. */
export function saveSecret(username: string, secret: string): void {
  mkdirSync(AUTH_DIR, { recursive: true });
  writeFileSync(secretFile(username), secret);
}

/** The authenticator secret username enrolled with, or ''. */
export function loadSecret(username: string): string {
  const file = secretFile(username);
  return existsSync(file) ? readFileSync(file, 'utf8').trim() : '';
}

function stepFile(username: string): string {
  return `${secretFile(username)}.step`;
}

/**
 * A code from secret for a step username has not used. The gateway accepts
 * each step's code once (review L1), and the suite signs the same accounts in
 * many times, so a code is taken from the earliest step in the accepted window
 * -- the current one and one either side -- after the last one used, waiting
 * for the next step when all three are spent.
 */
export async function nextCode(username: string, secret: string): Promise<string> {
  for (;;) {
    const file = stepFile(username);
    const last = existsSync(file) ? Number(readFileSync(file, 'utf8')) || 0 : 0;
    const cur = Math.floor(Date.now() / 30000);
    for (const step of [cur - 1, cur, cur + 1]) {
      if (step > last) {
        mkdirSync(AUTH_DIR, { recursive: true });
        writeFileSync(file, String(step));
        return totp(secret, step * 30000 + 15000);
      }
    }
    await new Promise((resolve) => setTimeout(resolve, (cur + 1) * 30000 - Date.now() + 250));
  }
}

/**
 * Finishes a sign-in on the login page once the password has been submitted:
 * enrols an authenticator the first time, answers a code after that.
 */
export async function finishSignInPage(page: Page, username: string): Promise<void> {
  const code = page.getByLabel('Verification Code');
  await expect(code).toBeVisible({ timeout: 60000 });
  if (await page.getByRole('heading', { name: 'Set Up Two-Factor' }).isVisible()) {
    const secret = (await page.getByText('Or enter this secret manually').locator('code').innerText()).trim();
    saveSecret(username, secret);
    await code.fill(await nextCode(username, secret));
    await page.getByRole('button', { name: /Verify & Enable/ }).click();
    return;
  }
  const secret = loadSecret(username);
  expect(secret, `no authenticator was saved for ${username}`).not.toBe('');
  await code.fill(await nextCode(username, secret));
  await page.getByRole('button', { name: /Verify & Sign in/ }).click();
}

/** Fills the login form, submits it and finishes the sign-in. */
export async function signInPage(page: Page, username: string, password: string): Promise<void> {
  await page.getByPlaceholder('Enter your username').fill(username);
  await page.getByPlaceholder('••••••••').fill(password);
  await page.getByRole('button', { name: /Continue to Dashboard/i }).click();
  await finishSignInPage(page, username);
}

/**
 * A whole sign-in through the API: /v1/login, /v1/auth/2fa/enroll the first
 * time, /v1/auth/2fa/verify. Answers the response of the step that ended it --
 * the one that set the session cookie, or the one that refused.
 */
export async function apiSignIn(
  ctx: APIRequestContext,
  username: string,
  password: string,
  headers?: Record<string, string>,
): Promise<APIResponse> {
  const login = await ctx.post('/v1/login', { data: { username, password }, headers });
  if (!login.ok()) return login;
  const step = (await login.json()) as {
    user?: { id?: string };
    twoFactorRequired?: boolean;
    twoFactorSetupRequired?: boolean;
    twoFactorChallenge?: string;
  };
  if (!step.twoFactorRequired && !step.twoFactorSetupRequired) return login;
  let id = step.user?.id ?? '';
  let secret = loadSecret(username);
  if (step.twoFactorSetupRequired) {
    const enrol = await ctx.post('/v1/auth/2fa/enroll', { data: { username, password }, headers });
    if (!enrol.ok()) return enrol;
    const enrolled = (await enrol.json()) as { id?: string; secret?: string };
    id = enrolled.id ?? '';
    secret = enrolled.secret ?? '';
    saveSecret(username, secret);
  }
  return ctx.post('/v1/auth/2fa/verify', {
    data: { id, code: await nextCode(username, secret), challenge: step.twoFactorChallenge },
    headers,
  });
}
