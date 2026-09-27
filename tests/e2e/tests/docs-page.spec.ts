// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test, expect, type Page } from '@playwright/test';

/**
 * The Docs page: four bundled markdown guides (ui/docs), one per tab, rendered
 * with react-markdown into Mantine components.
 *
 * The content is shipped with the dashboard, not observed from traffic, so
 * rendering it as markdown is the feature rather than a hazard.
 */

interface Guide {
  tab: string;
  title: string;
  section: string;
  code?: string;
}

const GUIDES: Guide[] = [
  { tab: 'Introduction', title: 'Gateon Documentation', section: 'Available Guides' },
  { tab: 'Proxy Protocol', title: 'Proxy Protocol in Gateon', section: 'Versions: v1 vs v2', code: 'PROXY TCP4' },
  { tab: 'Email Backend (SMTP, IMAP, POP3)', title: 'Email Backend Setup (SMTP, IMAP, POP3)', section: 'Enable PROXY Protocol in Gateon' },
  { tab: 'Running as a Service', title: 'Running Gateon as a Service', section: 'Built-in install command', code: 'gateon install' },
];

async function openGuide(page: Page, tab: string) {
  const handle = page.getByRole('tab', { name: tab, exact: true });
  await handle.click();
  await expect(handle).toHaveAttribute('aria-selected', 'true');
  return page.getByRole('tabpanel', { name: tab, exact: true });
}

test.describe('Docs page', () => {
  test('every guide renders as a document: headings, prose and code, no markdown syntax', async ({ page }) => {
    await page.goto('/docs');
    await expect(page.getByRole('heading', { name: 'Documentation', exact: true })).toBeVisible();
    await expect(page.getByRole('tab')).toHaveCount(GUIDES.length);

    for (const guide of GUIDES) {
      const panel = await openGuide(page, guide.tab);
      await expect(panel.getByRole('heading', { name: guide.title, exact: true }), `${guide.tab}: title`).toBeVisible();
      await expect(panel.getByRole('heading', { name: guide.section, exact: true }), `${guide.tab}: section`).toBeVisible();
      // Markdown that was not rendered shows its own syntax. Paragraphs only:
      // shell comments inside a code block start with "#" legitimately.
      const prose = panel.locator('p');
      await expect(prose.filter({ hasText: /^#{1,6} / }), `${guide.tab}: a heading left as "#" text`).toHaveCount(0);
      await expect(prose.filter({ hasText: '```' }), `${guide.tab}: a code fence left as text`).toHaveCount(0);
      if (guide.code) {
        await expect(panel.locator('pre, code').filter({ hasText: guide.code }).first(), `${guide.tab}: code block`).toBeVisible();
      }
    }
  });

  test('links open in a new tab without handing it this page', async ({ page }) => {
    await page.goto('/docs');
    const panel = await openGuide(page, 'Introduction');
    const links = panel.getByRole('link');
    await expect(links.first()).toBeVisible();
    for (const link of await links.all()) {
      await expect(link).toHaveAttribute('target', '_blank');
      await expect(link).toHaveAttribute('rel', /noopener/);
    }
  });

  test('tables in the guides render as tables', async ({ page }) => {
    // OPEN: react-markdown renders GitHub tables only with the remark-gfm
    // plugin, which ui/package.json does not include, so the guide index on
    // the Introduction tab and the tables in Proxy Protocol and Email Backend
    // show as raw "| Document | Description | |---|" text. The DocsPage table
    // components are never used. Fixing it is a new dependency; left for a
    // decision. When it is fixed this test passes and the annotation must go.
    test.fail();
    await page.goto('/docs');
    const intro = await openGuide(page, 'Introduction');
    await expect(intro.getByRole('table')).toBeVisible({ timeout: 3000 });
    await expect(intro.getByRole('columnheader', { name: 'Document' })).toBeVisible({ timeout: 3000 });
    await expect(intro.getByText('|----------|')).toHaveCount(0);
  });

  test("the Introduction's guide links lead to a guide", async ({ page }) => {
    // OPEN: the index links to ./services.md and friends, which the gateway
    // does not serve, so each opens a tab reading "Not Found". Two of the five
    // (management-entrypoint.md, websockets-sse.md) have no tab on this page
    // at all. When it is fixed this test passes and the annotation must go.
    test.fail();
    await page.goto('/docs');
    const intro = await openGuide(page, 'Introduction');
    const [guide] = await Promise.all([
      page.waitForEvent('popup'),
      intro.getByRole('link', { name: 'services.md' }).click(),
    ]);
    await guide.waitForLoadState();
    await expect(guide.getByRole('heading', { name: 'Running Gateon as a Service' })).toBeVisible({ timeout: 3000 });
  });
});
