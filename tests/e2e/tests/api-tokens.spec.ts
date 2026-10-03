// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test, expect, type APIRequestContext } from '@playwright/test';

/**
 * ADR 0050 in the dashboard, against the real gateway: an administrator
 * issues a scrape token, the token reads /metrics and nothing else, revoking
 * it stops it, a viewer cannot reach the page, and the audit page's integrity
 * check answers in the dashboard's words.
 *
 * /metrics used to accept only a user's eight-hour session, so a scraper needed
 * an account and a script signing it in again on a timer.
 */

const GATEWAY = 'http://localhost:8080';
const NAME = `e2e-scraper-${Date.now()}`;

type Playwright = { request: { newContext: (o: object) => Promise<APIRequestContext> } };

/**
 * A context with no session at all: what a Prometheus server is. The empty
 * storage state is not a formality -- a context made here otherwise inherits
 * the spec's admin cookie, and the session would answer for the token.
 */
function scraper(playwright: Playwright, secret: string) {
  return playwright.request.newContext({
    baseURL: GATEWAY,
    storageState: { cookies: [], origins: [] },
    extraHTTPHeaders: { Authorization: `Bearer ${secret}` },
  });
}

test.describe('API tokens', () => {
  test.use({ storageState: 'tests/.auth/admin.json' });

  test('an administrator issues a scrape token that reads /metrics and nothing else, and revokes it', async ({
    page,
    playwright,
  }) => {
    await page.goto('/api-tokens');
    await expect(page.getByRole('heading', { name: 'API tokens' })).toBeVisible();

    await page.getByRole('button', { name: 'Create token' }).click();
    const create = page.getByRole('dialog', { name: 'Create API token' });
    await create.getByLabel('Name').fill(NAME);
    await create.getByRole('button', { name: 'Create token' }).click();

    const issued = page.getByRole('dialog', { name: `API token "${NAME}" created` });
    await expect(issued).toBeVisible();
    const secret = (await issued.locator('pre').first().innerText()).trim();
    expect(secret).toMatch(/^gateon_tok_[A-Za-z0-9_-]{43}$/);
    await issued.getByRole('button', { name: 'I have copied it' }).click();

    const row = page.getByRole('row').filter({ hasText: NAME });
    await expect(row).toBeVisible();
    // Listed by its hint; the secret is never shown again.
    await expect(page.getByText(secret)).toHaveCount(0);

    const ctx = await scraper(playwright, secret);
    try {
      const metrics = await ctx.get('/metrics');
      expect(metrics.status(), 'the token scraping /metrics').toBe(200);
      expect(await metrics.text()).toContain('# HELP');
      expect((await ctx.get('/v1/status')).status(), 'the token on the API').toBe(401);
      expect((await ctx.get('/v1/api-tokens')).status(), 'the token listing tokens').toBe(401);

      await row.getByRole('button', { name: `Revoke API token ${NAME}` }).click();
      const confirm = page.getByRole('dialog', { name: 'Delete API token' });
      await expect(confirm).toContainText(NAME);
      await confirm.getByRole('button', { name: 'Delete API token' }).click();
      await expect(row).toHaveCount(0);

      expect((await ctx.get('/metrics')).status(), 'a revoked token scraping /metrics').toBe(401);
    } finally {
      await ctx.dispose();
    }
  });

  test('the integrity check answers in the dashboard\'s words', async ({ page }) => {
    await page.goto('/audit-logs');
    await page.getByRole('button', { name: 'Verify integrity' }).click();
    // The suite's gateway runs with audit signing off, so there is no chain:
    // the page says so, rather than showing a status code or the server's text.
    const answer = page.getByRole('alert').filter({ hasText: 'Audit signing is off' })
      .or(page.getByRole('status').filter({ hasText: 'The audit log verifies' }));
    await expect(answer).toBeVisible();
    await expect(page.getByText('failed_precondition')).toHaveCount(0);
  });
});

test.describe('API tokens as a viewer', () => {
  test.use({ storageState: 'tests/.auth/viewer.json' });

  test('a viewer is not offered the page and cannot use it', async ({ page }) => {
    await page.goto('/api-tokens');
    await expect(page.getByText('Only an administrator can manage API tokens.')).toBeVisible();
    await expect(page.getByRole('link', { name: 'API Tokens' })).toHaveCount(0);
  });
});
