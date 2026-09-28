// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test, expect, type APIRequestContext, type Locator, type Page } from '@playwright/test';

/**
 * The Settings cards other specs never opened: Appearance, Quick Presets,
 * Resource Profile, Forensic Audit Logging, Trace archive and GeoIP.
 *
 * Several of these save the gateway's global configuration, which every other
 * spec runs against, so the configuration is read before the file starts and
 * put back after it ends, whatever happens in between.
 */

type Playwright = { request: { newContext: (o: object) => Promise<APIRequestContext> } };

// What GET /v1/global returns for a stored secret: storedsecret.Sentinel in the
// gateway and STORED_SECRET_SENTINEL in the dashboard, pinned equal by a Go test.
const STORED_SECRET = '__gateon_redacted__';

function adminApi(playwright: Playwright) {
  return playwright.request.newContext({ baseURL: 'http://localhost:8080', storageState: 'tests/.auth/admin.json' });
}

/** Opens /settings and returns once the gateway's configuration is on the form. */
async function openSettings(page: Page) {
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === '/v1/global' && r.request().method() === 'GET');
  await page.goto('/settings');
  expect((await loaded).status(), 'GET /v1/global').toBe(200);
  await expect(page.getByRole('button', { name: 'Save Global Configuration' })).toBeEnabled();
}

/**
 * Opens a Settings tab. Tabs are unmounted while hidden, so a card on another
 * tab is not on the page until its tab is opened.
 */
async function openTab(page: Page, name: 'General' | 'Gateway' | 'Security' | 'Network & HA') {
  await page.getByRole('tab', { name }).click();
  await expect(page.getByRole('tab', { name })).toHaveAttribute('aria-selected', 'true');
}

/** A settings card, found by its title. */
function card(page: Page, title: string): Locator {
  return page.locator('.mantine-Card-root').filter({ has: page.getByRole('heading', { name: title, exact: true }) });
}

async function saveGlobal(page: Page): Promise<Record<string, unknown>> {
  const saved = page.waitForResponse((r) => new URL(r.url()).pathname === '/v1/global' && r.request().method() === 'PUT');
  await page.getByRole('button', { name: 'Save Global Configuration' }).click();
  const res = await saved;
  expect(res.status(), `PUT /v1/global: ${await res.text()}`).toBe(200);
  await expect(page.getByText('Configuration successfully updated!')).toBeVisible();
  return res.request().postDataJSON() as Record<string, unknown>;
}

let snapshot: unknown;

test.beforeAll(async ({ playwright }) => {
  const api = await adminApi(playwright);
  try {
    const res = await api.get('/v1/global');
    expect(res.ok(), 'reading the configuration to restore').toBe(true);
    snapshot = await res.json();
  } finally {
    await api.dispose();
  }
});

test.afterAll(async ({ playwright }) => {
  if (!snapshot) return;
  const api = await adminApi(playwright);
  try {
    const res = await api.put('/v1/global', { data: snapshot });
    expect(res.ok(), `restoring the configuration: ${res.status()}`).toBe(true);
  } finally {
    await api.dispose();
  }
});

test.describe('Settings cards', () => {
  test.setTimeout(90_000);

  test('Appearance: language, theme and table density apply at once and survive a reload', async ({ page }) => {
    await openSettings(page);
    const appearance = card(page, 'Appearance');

    await appearance.getByText('Dark', { exact: true }).click();
    await expect(page.locator('html')).toHaveAttribute('data-mantine-color-scheme', 'dark');
    await appearance.getByLabel('Language').and(page.locator('input')).click();
    await page.getByRole('option', { name: 'Bahasa Indonesia' }).click();
    await expect(card(page, 'Tampilan'), 'the card did not switch language').toBeVisible();

    await page.reload();
    await expect(card(page, 'Tampilan'), 'the language did not survive a reload').toBeVisible();
    await expect(page.locator('html')).toHaveAttribute('data-mantine-color-scheme', 'dark');
    await card(page, 'Tampilan').getByLabel('Bahasa').and(page.locator('input')).click();
    await page.getByRole('option', { name: 'English' }).click();
    await expect(card(page, 'Appearance')).toBeVisible();
    await card(page, 'Appearance').getByText('Light', { exact: true }).click();
    await expect(page.locator('html')).toHaveAttribute('data-mantine-color-scheme', 'light');

    // Density: the same table, measured before and after. Compact is the
    // smaller cell padding (Mantine's verticalSpacing).
    const cellFont = async () => {
      await page.goto('/entryPoints');
      const cell = page.getByRole('row').filter({ hasText: 'http-plain' }).getByRole('cell').first();
      await expect(cell).toBeVisible();
      // Runs in the page, where globalThis is the window; the e2e project has
      // no DOM types, hence the cast.
      return cell.evaluate((el) => {
        const win = globalThis as unknown as { getComputedStyle: (e: unknown) => { paddingTop: string } };
        return parseFloat(win.getComputedStyle(el).paddingTop);
      });
    };
    const comfortable = await cellFont();
    await openSettings(page);
    await card(page, 'Appearance').getByText('Compact', { exact: true }).click();
    const compact = await cellFont();
    expect(compact, 'compact rows are not tighter than comfortable ones').toBeLessThan(comfortable);
  });

  test('a preset fills what it names and keeps every other setting', async ({ page }) => {
    const puts: string[] = [];
    page.on('request', (r) => {
      if (r.method() === 'PUT' && new URL(r.url()).pathname === '/v1/global') puts.push(r.url());
    });
    await openSettings(page);
    await openTab(page, 'Gateway');
    const threats = page.getByLabel('Security threats retention (days)');
    await threats.fill('45');

    await card(page, 'Quick Presets').getByRole('button', { name: 'Production' }).click();
    await expect(page.getByLabel('Log Level').and(page.locator('input'))).toHaveValue('Info');
    await expect(page.getByLabel('Log Format').and(page.locator('input'))).toHaveValue('JSON');
    await expect(page.getByLabel('Path metrics retention (days)')).toHaveValue('30');
    await expect(threats, 'the preset reset a retention it does not mention').toHaveValue('45');

    // Presets fill the form; only Save writes it. The open tab is kept in the
    // URL, so the reload comes back to it.
    await page.reload();
    await expect(page.getByLabel('Log Level').and(page.locator('input'))).toHaveValue('Debug');
    expect(puts, 'applying a preset saved the configuration').toEqual([]);
  });

  test('Resource Profile shows the profile the gateway runs, and that it is pinned', async ({ page }) => {
    const status = page.waitForResponse((r) => new URL(r.url()).pathname === '/v1/status' && r.request().method() === 'GET');
    await openSettings(page);
    const running = (await (await status).json()) as { profile?: string; profilePinned?: boolean };
    // The suite's gateway runs with GATEON_PROFILE=enterprise.
    expect(running).toMatchObject({ profile: 'enterprise', profilePinned: true });

    const profile = card(page, 'Resource Profile');
    await expect(profile.getByText('Pinned by Environment')).toBeVisible();
    await expect(profile.getByText('GATEON_PROFILE', { exact: true })).toBeVisible();
    const select = profile.getByLabel('Active Profile').and(page.locator('input'));
    await expect(select).toBeDisabled();
    await expect(select, 'the card names a profile the gateway is not running').toHaveValue('Enterprise (8+ Cores, 16GB+ RAM)');
  });

  test('Forensic audit logging: signing with no key gets one generated on save', async ({ page, playwright }) => {
    await openSettings(page);
    await openTab(page, 'Security');
    const audit = card(page, 'Forensic Audit Logging');
    const enabled = audit.getByRole('switch', { name: 'Forensic audit logging' });
    // Mantine hides a switch's input behind its track; with no visible label
    // there is nothing else to click.
    if (!(await enabled.isChecked())) await enabled.check({ force: true });
    await expect(enabled).toBeChecked();
    const signing = audit.getByRole('switch', { name: 'Cryptographic signing' });
    if (!(await signing.isChecked())) await signing.check({ force: true });
    await expect(signing).toBeChecked();
    await audit.getByLabel('Signature Key').fill('');

    const body = (await saveGlobal(page)) as { audit?: { enabled?: boolean; signEntries?: boolean; signatureKey?: string } };
    expect(body.audit).toMatchObject({ enabled: true, signEntries: true });
    expect(body.audit?.signatureKey ?? '').toBe('');

    // The key itself is never read back (ADR 0028): a stored one reads as the
    // placeholder, and the card shows it as stored rather than as a value.
    const api = await adminApi(playwright);
    try {
      const stored = (await (await api.get('/v1/global')).json()) as { audit?: { signatureKey?: string } };
      expect(stored.audit?.signatureKey, 'the gateway generated no signing key').toBe(STORED_SECRET);
    } finally {
      await api.dispose();
    }
    await openSettings(page);
    await openTab(page, 'Security');
    await expect(card(page, 'Forensic Audit Logging').getByText('Stored', { exact: true })).toBeVisible();
  });

  test('Trace archive: retention and size limit are saved and read back', async ({ page }) => {
    await openSettings(page);
    await openTab(page, 'Gateway');
    const archive = card(page, 'Trace archive');
    await archive.getByLabel('Keep archived hours for (days)').fill('3');
    await archive.getByLabel('Archive size limit (MB)').fill('64');
    const body = (await saveGlobal(page)) as { log?: { traceArchiveRetentionDays?: number; traceArchiveMaxSizeMb?: number } };
    expect(body.log).toMatchObject({ traceArchiveRetentionDays: 3, traceArchiveMaxSizeMb: 64 });

    await openSettings(page);
    await openTab(page, 'Gateway');
    await expect(card(page, 'Trace archive').getByLabel('Keep archived hours for (days)')).toHaveValue('3');
    await expect(card(page, 'Trace archive').getByLabel('Archive size limit (MB)')).toHaveValue('64');
  });

  test('GeoIP says whether a database is loaded, and which', async ({ page }) => {
    // The suite's gateway has no GeoIP database.
    // The card asks for the status when it mounts, which is when its tab opens.
    const real = page.waitForResponse((r) => new URL(r.url()).pathname === '/v1/geoip/status');
    await openSettings(page);
    await openTab(page, 'Security');
    expect(((await (await real).json()) as { exists?: boolean }).exists ?? false).toBe(false);
    const geoip = card(page, 'GeoIP Configuration');
    await expect(geoip.getByText('Not Loaded', { exact: true })).toBeVisible();
    await expect(geoip.getByText(/GeoIP database is missing/)).toBeVisible();

    // One that has a database says which, from the gateway's own answer.
    await page.route('**/v1/geoip/status', (route) =>
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ exists: true, info: 'GeoLite2-City build 2026-09-20', path: 'geoip/GeoLite2-City.mmdb' }),
      }),
    );
    await openSettings(page);
    await openTab(page, 'Security');
    await expect(geoip.getByText('Database Loaded', { exact: true })).toBeVisible();
    await expect(geoip).toContainText('GeoLite2-City build 2026-09-20');
    await expect(geoip).toContainText('geoip/GeoLite2-City.mmdb');
    await expect(geoip.getByText(/GeoIP database is missing/)).toHaveCount(0);
  });
});
