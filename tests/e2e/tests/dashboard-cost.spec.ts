import { test, expect } from '@playwright/test';

test.setTimeout(120000);

const WINDOW_MS = 30000;

/**
 * The dashboard's request cost must not grow with the routing table.
 *
 * Every route on the dashboard draws a sparkline, and each one used to fetch its
 * own stats: one request per route, per refresh interval, from a tab nobody was
 * touching. Seven routes cost 21 requests every 30 seconds; fifty would cost
 * 150. gateon is sized for a 2-core host, so that is the gateway competing with
 * its own dashboard for the CPU it needs to serve traffic.
 *
 * Asserting on the *shape* of the requests rather than a total keeps this test
 * honest as the page gains and loses widgets: what must never come back is the
 * per-route fan-out.
 */
test('the dashboard never fetches route stats one route at a time', async ({ page }) => {
  const perRoute: string[] = [];
  let batched = 0;

  page.on('request', (r) => {
    let path: string;
    try {
      path = new URL(r.url()).pathname;
    } catch {
      return;
    }
    if (/^\/v1\/routes\/[^/]+\/stats$/.test(path)) perRoute.push(path);
    if (path === '/v1/routes/stats') batched++;
  });

  await page.goto('/', { waitUntil: 'load' });
  await page.waitForTimeout(WINDOW_MS);

  expect(
    perRoute,
    `the dashboard fetched route stats per route (${perRoute.length} requests); ` +
      `this cost grows with the number of routes and is what /v1/routes/stats exists to avoid`,
  ).toHaveLength(0);

  expect(batched, 'the dashboard fetched no route stats at all — the sparklines have no data').toBeGreaterThan(0);
});
