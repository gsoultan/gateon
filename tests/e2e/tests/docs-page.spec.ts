// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test, expect, type Page } from '@playwright/test';

/**
 * The Docs page: six bundled markdown guides (ui/docs), one per tab, rendered
 * with react-markdown (and remark-gfm, for tables) into Mantine components.
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
  { tab: 'Management Entrypoint', title: 'Secure Management Entrypoint', section: 'Security Features' },
  { tab: 'WebSockets & SSE', title: 'WebSockets and Server-Sent Events (SSE) Support', section: 'Server-Sent Events (SSE) Support' },
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

  test('links to other sites open in a new tab without handing it this page', async ({ page }) => {
    await page.goto('/docs');
    // The Introduction links only to other guides, which open their tab; the
    // service guide links out to other sites.
    const panel = await openGuide(page, 'Running as a Service');
    const links = panel.getByRole('link');
    await expect(links.first()).toBeVisible();
    for (const link of await links.all()) {
      await expect(link).toHaveAttribute('target', '_blank');
      await expect(link).toHaveAttribute('rel', /noopener/);
    }
  });

  test('tables in the guides render as tables', async ({ page }) => {
    // react-markdown parses GitHub tables only with remark-gfm; without it the
    // guide index showed as raw "| Document | Description |" text.
    await page.goto('/docs');
    const intro = await openGuide(page, 'Introduction');
    await expect(intro.getByRole('table')).toBeVisible({ timeout: 3000 });
    await expect(intro.getByRole('columnheader', { name: 'Document' })).toBeVisible({ timeout: 3000 });
    await expect(intro.getByText('|----------|')).toHaveCount(0);
  });

  test("the Introduction's guide links open each guide's tab", async ({ page }) => {
    // The index links to its guides as files (./services.md), which the gateway
    // does not serve: followed as links, each opened a window reading "Not
    // Found", and two of the five guides had no tab at all.
    await page.goto('/docs');
    const links: Array<[string, string, string]> = [
      ['management-entrypoint.md', 'Management Entrypoint', 'Secure Management Entrypoint'],
      ['services.md', 'Running as a Service', 'Running Gateon as a Service'],
      ['email-backend-setup.md', 'Email Backend (SMTP, IMAP, POP3)', 'Email Backend Setup (SMTP, IMAP, POP3)'],
      ['proxy-protocol.md', 'Proxy Protocol', 'Proxy Protocol in Gateon'],
      ['websockets-sse.md', 'WebSockets & SSE', 'WebSockets and Server-Sent Events (SSE) Support'],
    ];
    for (const [link, tab, title] of links) {
      const intro = await openGuide(page, 'Introduction');
      const popups: unknown[] = [];
      page.on('popup', (p) => popups.push(p));
      await intro.getByRole('button', { name: link, exact: true }).click();
      await expect(page.getByRole('tab', { name: tab, exact: true }), `${link}: its tab is selected`).toHaveAttribute('aria-selected', 'true');
      await expect(page.getByRole('tabpanel', { name: tab, exact: true }).getByRole('heading', { name: title, exact: true })).toBeVisible();
      expect(popups, `${link}: opened a window`).toHaveLength(0);
    }
  });
});
