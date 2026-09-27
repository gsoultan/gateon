// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test, expect, type APIRequestContext, type Locator, type Page } from '@playwright/test';
import { attackerContext } from './attack-traffic';

/**
 * The Logs page: the gateway's own log, pushed over a WebSocket as it is
 * written, with text, route, status and client filters, pause, clear, and an
 * analysis of the lines on screen.
 *
 * No spec opened it before. The operator's "can see logs" visited /traces.
 *
 * The suite's gateway logs in slog's text format (config/global.json), which
 * is also what an install that sets neither log.format nor ENV=production
 * gets. So a line reads `level=INFO msg="access log" ... path=/x status=403
 * client=1.2.3.4 route="Blocked Route"`, and that is the shape every filter
 * below has to understand.
 *
 * Every request here is routed: the fixture entrypoint does not log what no
 * route takes, only the routes do.
 */

const PROXY = 'http://localhost:8081';
const HOSTILE = '<img src=x onerror=alert(1)>';
// TEST-NET-3 (RFC 5737). The harness trusts X-Forwarded-For from loopback, so
// the gateway logs this as the client.
const CLIENT = '203.0.113.41';

function logCard(page: Page): Locator {
  return page.locator('.mantine-Card-root').filter({ has: page.getByRole('heading', { name: 'Live Logs' }) });
}

/** The access-log line for one request, found by a path fragment unique to the test. */
function accessLine(card: Locator, marker: string): Locator {
  return card.locator('p').filter({ hasText: 'msg="access log"' }).filter({ hasText: marker });
}

/** Opens /logs and returns once the stream is connected and delivering lines. */
async function openLiveLogs(page: Page): Promise<Locator> {
  await page.goto('/logs');
  const card = logCard(page);
  await expect(card.getByText('LIVE', { exact: true }), 'the log stream never connected').toBeVisible();
  // The gateway sends its recent history first, and only after subscribing
  // this connection, so a line on screen means anything logged from now on
  // reaches this page as it happens.
  await expect(card.getByText(/level=(DEBUG|INFO|WARN|ERROR)/).first()).toBeVisible();
  return card;
}

/** A request Test Route serves: logged as a 200 from CLIENT. */
async function served(request: APIRequestContext, path: string): Promise<void> {
  const res = await request.get(`${PROXY}/test${path}`, { headers: { 'X-Forwarded-For': CLIENT } });
  expect(res.status(), `GET /test${path}`).toBe(200);
}

test.describe('Logs page', () => {
  test('streams lines as the gateway writes them, and shows what a client sent as text', async ({ page, playwright }) => {
    const dialogs: string[] = [];
    page.on('dialog', (d) => {
      dialogs.push(d.message());
      void d.dismiss();
    });
    const card = await openLiveLogs(page);

    // Sent after the page connected, so the line can only arrive live. The
    // WAF refuses it, which is the point: attack traffic is exactly what an
    // operator reads this page for. See attack-traffic.ts for why it is sent
    // from a client of its own.
    const marker = `logs-live-${Date.now()}`;
    const attacker = await attackerContext(playwright, 'logs-page');
    try {
      const res = await attacker.get(`${PROXY}/test/${marker}/${encodeURIComponent(HOSTILE)}`, {
        headers: { 'X-Forwarded-For': '203.0.113.42' },
      });
      expect(res.status(), 'the WAF let an XSS payload through').toBe(403);
    } finally {
      await attacker.dispose();
    }

    const line = accessLine(card, marker);
    await expect(line, 'the request made while the page was open never appeared').toHaveCount(1);
    // The client's own bytes, as characters. A line rendered as markup would
    // have produced an <img> whose onerror opens a dialog.
    await expect(line).toContainText(`path="/test/${marker}/${HOSTILE}"`);
    await expect(line).toContainText('status=403');
    await expect(page.locator('img[src="x"]')).toHaveCount(0);
    expect(dialogs, 'a logged string ran as script').toEqual([]);
  });

  test('filters by text, status, status class, route and client address', async ({ page, request }) => {
    const card = await openLiveLogs(page);
    const marker = `logs-filter-${Date.now()}`;
    const ok = accessLine(card, `/test/${marker}`);
    const denied = accessLine(card, `/blocked/${marker}`);

    await served(request, `/${marker}`);
    // Refused by the route's IP filter: a 403 on Blocked Route from 1.2.3.4.
    const refused = await request.get(`${PROXY}/blocked/${marker}`, { headers: { 'X-Forwarded-For': '1.2.3.4' } });
    expect(refused.status()).toBe(403);
    await expect(ok).toHaveCount(1);
    await expect(denied).toHaveCount(1);

    // Freeze the view: the dashboard's own API calls are logged too, and the
    // page keeps only the newest hundred lines.
    await card.getByRole('button', { name: 'Pause' }).click();
    await expect(card.getByText('PAUSED', { exact: true })).toBeVisible();

    const search = card.getByPlaceholder('Text search...');
    const status = card.getByPlaceholder('Status (e.g. 200, 5xx)');
    const client = card.getByPlaceholder('Client IP');

    await search.fill(marker);
    await expect(ok).toHaveCount(1);
    await expect(denied).toHaveCount(1);
    await search.fill('');

    await status.fill('403');
    await expect(denied, 'status 403 hides the 403').toHaveCount(1);
    await expect(ok, 'status 403 shows a 200').toHaveCount(0);

    await status.fill('4xx');
    await expect(denied, 'the 4xx class hides a 403').toHaveCount(1);
    await expect(ok).toHaveCount(0);

    await status.fill('2xx');
    await expect(ok, 'the 2xx class hides a 200').toHaveCount(1);
    await expect(denied).toHaveCount(0);
    await status.fill('');

    await client.fill(CLIENT);
    await expect(ok, `client ${CLIENT} hides its own request`).toHaveCount(1);
    await expect(denied).toHaveCount(0);
    await client.fill('');

    await card.getByPlaceholder('Route', { exact: true }).click();
    await page.getByRole('option', { name: 'Test Route', exact: true }).click();
    await expect(ok, 'the Test Route filter hides a Test Route request').toHaveCount(1);
    await expect(denied).toHaveCount(0);

    // A filter that matches nothing says so, whichever filter it is: the
    // empty view used to claim it was waiting for traffic unless the text
    // search was the one that emptied it.
    await status.fill('599');
    await expect(card.getByText('No logs match your filter. Change or clear the filter.')).toBeVisible();
    await expect(card.getByText('-- Waiting for incoming traffic --')).toHaveCount(0);
  });

  test('pause drops lines until resumed, and clear empties the view', async ({ page, request }) => {
    const card = await openLiveLogs(page);
    const marker = `logs-pause-${Date.now()}`;

    await card.getByRole('button', { name: 'Pause' }).click();
    await expect(card.getByText('PAUSED', { exact: true })).toBeVisible();
    await served(request, `/${marker}-while-paused`);
    await card.getByRole('button', { name: 'Resume' }).click();
    await expect(card.getByText('PAUSED', { exact: true })).toHaveCount(0);
    await served(request, `/${marker}-after-resume`);

    // The stream is ordered, so once the later line is here the earlier one
    // would have been too, had pausing kept it.
    await expect(accessLine(card, `${marker}-after-resume`)).toHaveCount(1);
    await expect(accessLine(card, `${marker}-while-paused`), 'a line logged while paused was shown').toHaveCount(0);

    await card.getByRole('button', { name: 'Clear logs' }).click();
    await expect(accessLine(card, `${marker}-after-resume`), 'Clear left the lines on screen').toHaveCount(0);
  });

  test('the log assistant analyses the lines on screen', async ({ page, request }) => {
    const card = await openLiveLogs(page);
    const marker = `logs-ai-${Date.now()}`;
    await served(request, `/${marker}`);
    await expect(accessLine(card, marker)).toHaveCount(1);
    await card.getByRole('button', { name: 'Pause' }).click();

    await card.getByRole('button', { name: 'AI Insight' }).click();
    const dialog = page.getByRole('dialog', { name: 'AI Log Assistant' });
    await expect(dialog).toBeVisible();
    await expect(dialog.getByText(`path=/test/${marker}`)).toBeVisible();

    const analysed = page.waitForResponse(
      (r) => new URL(r.url()).pathname === '/v1/AnalyzeLogs' && r.request().method() === 'POST',
    );
    await dialog.getByRole('button', { name: 'Analyze Now' }).click();
    const res = await analysed;
    expect(res.status(), 'POST /v1/AnalyzeLogs').toBe(200);
    const sent = res.request().postDataJSON() as { logs: string[] };
    expect(sent.logs.length).toBeGreaterThan(0);
    expect(sent.logs.length).toBeLessThanOrEqual(50);
    expect(sent.logs.some((l) => l.includes(`path=/test/${marker}`)), 'the analysed lines are not the ones on screen').toBe(true);

    const { analysis } = (await res.json()) as { analysis: string };
    expect(analysis).toMatch(new RegExp(`^Analyzed ${sent.logs.length} log lines: `));
    await expect(dialog.getByText('Analysis & Recommendations:')).toBeVisible();
    await expect(dialog.getByText(analysis, { exact: true })).toBeVisible();
  });
});
