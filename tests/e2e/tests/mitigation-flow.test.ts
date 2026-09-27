// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test, expect } from '@playwright/test';

/**
 * Open the anomaly engine.
 *
 * It used to be the second half of the diagnostics page. Threats are acted on
 * in the Security Hub now — one place, one code path — so these flows go
 * through the hub's Anomaly Engine tab.
 */
async function gotoAnomalyEngine(page: any) {
  await page.goto('/security-center', { waitUntil: 'load' });
  await page.getByRole('tab', { name: /Anomaly Engine/i }).click();
}

// telemetry.RecordSecurityThreat drops anything whose source is loopback, on
// purpose: management traffic and local probes would otherwise flood the
// Security Hub. Playwright drives everything from 127.0.0.1, so a flow that
// asserts on a recorded threat has to present itself as a remote client or the
// threat is never stored and the test waits out its timeout against a UI that
// will stay empty.
//
// The harness sets GATEON_TRUSTED_PROXIES=127.0.0.1,::1, so X-Forwarded-For
// from the test runner is honoured. The address is from TEST-NET-3
// (RFC 5737), which is reserved for documentation and cannot collide with a
// real client. Every request in a flow must carry the same one, because
// mitigation is applied per source address.
const ATTACKER_IP = '203.0.113.11';
const asAttacker = { headers: { 'X-Forwarded-For': ATTACKER_IP } };

test.describe('Threat Mitigation E2E Flow', () => {
  test.setTimeout(180000);

  test('WAF False Positive Mitigation from Threat Explorer', async ({ page, request }) => {
    // 1. Trigger SQL Injection (Blocked by WAF)
    const sqliUrl = 'http://localhost:8081/test?sqli=1%20OR%201=1';
    for (let i = 0; i < 3; i++) {
        const sqliResp = await request.get(sqliUrl, asAttacker);
        expect(sqliResp.status()).toBe(403);
    }

    // 2. Go to Security Center -> Threat Explorer
    await page.goto('/security-center', { waitUntil: 'load' });
    
    // Give it time to be recorded and for the UI to fetch it.
    await page.waitForTimeout(10000);
    await page.reload({ waitUntil: 'load' });
    
    // Look for the WAF threat row
    const threatRow = page.locator('tr').filter({ hasText: /WAF/i }).first();
    await expect(threatRow).toBeVisible({ timeout: 20000 });
    
    // 3. Open Modal and Mark as False Positive
    //
    // Click the first cell, not the row. Playwright clicks an element's centre,
    // and the centre of this row lands in the Source IP cell — which carries its
    // own onClick that opens the trace visualiser and stops propagation. The row
    // click therefore opened "Visual Trace: <ip>" instead of the incident modal,
    // and which cell the centre falls in depends on how wide the rendered values
    // are, so it passed or failed with the data. The first cell is Event / Type
    // and has no nested handler.
    await threatRow.locator('td').first().click();
    await expect(page.getByText(/Security Incident Details/i)).toBeVisible({ timeout: 10000 });
    
    const fpBtn = page.getByRole('button', { name: /Mark as False Positive/i });
    await expect(fpBtn).toBeVisible();
    await fpBtn.click();
    
    // 4. Verify Success Notification
    await expect(page.getByText(/Applied/i)).toBeVisible({ timeout: 15000 });
    
    // 5. Verify Immediate Effect (Request should now be allowed)
    await page.waitForTimeout(3000);
    const sqliResp = await request.get(sqliUrl, asAttacker);
    expect(sqliResp.status()).not.toBe(403);
  });

  test('Unlisted Route Mitigation from Diagnostics', async ({ page, request }) => {
    // 1. Trigger Unlisted Route: a path no route serves, on the plain HTTP
    // entrypoint, whose only HTTP service is mock-service.
    const path = '/unlisted-path-' + Date.now();
    const unlistedUrl = 'http://localhost:8081' + path;
    const before = await request.get(unlistedUrl, asAttacker);
    expect(before.status(), 'the path has to start out unrouted').toBe(404);

    // 2. Go to Diagnostics
    await gotoAnomalyEngine(page);

    // Wait for the anomaly to appear.
    await page.waitForTimeout(10000);
    await gotoAnomalyEngine(page);

    // Scope to this path's card, not just the first Apply button on the page:
    // the list is ordered by time and score, and other findings -- including
    // other unlisted paths -- carry their own buttons.
    const unlistedCard = page
      .locator('[data-testid="anomaly-card"]')
      .filter({ hasText: /UNLISTED ROUTE/i })
      .filter({ hasText: path })
      .first();
    await expect(unlistedCard).toBeVisible({ timeout: 20000 });

    // 3. Apply Automatic Fix
    await unlistedCard.getByRole('button', { name: /Apply Automatic Fix/i }).click();
    await expect(page.getByText(/Recommendation Applied/i)).toBeVisible({ timeout: 10000 });

    // 4. The outcome, not the absence of a 403: the fix used to answer success
    // and change nothing, and a path nothing routes was never 403 to begin
    // with. There must now be exactly one route for this path -- an exact
    // Path rule, on the host the request named, on the entrypoint it arrived
    // at, pointed at the service that serves it -- and it must be paused.
    const rule = `Host(\`localhost\`) && Path(\`${path}\`)`;
    const listed = await page.request.get(`/v1/routes?pageSize=100&search=${encodeURIComponent(path)}`);
    expect(listed.ok(), `listing routes failed: ${listed.status()}`).toBe(true);
    const routes: Array<Record<string, unknown>> = (await listed.json()).routes ?? [];
    const created = routes.filter((r) => r.rule === rule);
    expect(created, `routes for ${path}: ${JSON.stringify(routes)}`).toHaveLength(1);
    expect(created[0]).toMatchObject({
      name: `unlisted localhost${path}`,
      disabled: true,
      entrypoints: ['http-plain'],
      serviceId: 'mock-service',
    });

    // Paused means exposed to nobody until an operator enables it.
    const after = await request.get(unlistedUrl, asAttacker);
    expect(after.status(), 'a paused route must not serve the path').toBe(404);

    // Applying the same finding again says the route exists; it adds nothing.
    await unlistedCard.getByRole('button', { name: /Apply Automatic Fix/i }).click();
    await expect(page.getByText(/already exists/i).first()).toBeVisible({ timeout: 10000 });
    const relisted = await page.request.get(`/v1/routes?pageSize=100&search=${encodeURIComponent(path)}`);
    const again: Array<Record<string, unknown>> = (await relisted.json()).routes ?? [];
    expect(again.filter((r) => r.rule === rule)).toHaveLength(1);
  });
});
