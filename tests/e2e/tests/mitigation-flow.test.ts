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
    await threatRow.click();
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
    // 1. Trigger Unlisted Route
    const unlistedUrl = 'http://localhost:8081/unlisted-path-' + Date.now();
    await request.get(unlistedUrl, asAttacker);
    
    // 2. Go to Diagnostics
    await gotoAnomalyEngine(page);
    
    // Wait for the anomaly to appear.
    await page.waitForTimeout(10000);
    await gotoAnomalyEngine(page);

    // Scope to the unlisted-route card, not just the first Apply button on the
    // page. Every non-mitigated anomaly renders its own "Apply Automatic Fix",
    // the list is ordered by score, and an unlisted route scores 0.5 against a
    // WAF block's 0.9 — so `.first()` reliably clicked the WAF anomaly instead.
    // ApplyRecommendation has no case for that type, so it answered
    // success=false, the UI showed "Fix Failed", and this test waited out its
    // timeout looking for "Recommendation Applied" on a fix it never asked for.
    const unlistedCard = page
      .locator('[data-testid="anomaly-card"]')
      .filter({ hasText: /UNLISTED ROUTE/i })
      .first();
    await expect(unlistedCard).toBeVisible({ timeout: 20000 });

    // 3. Apply Automatic Fix
    const blockBtn = unlistedCard.getByRole('button', { name: /Apply Automatic Fix/i });
    await blockBtn.click();
    
    await expect(page.getByText(/Recommendation Applied/i)).toBeVisible({ timeout: 10000 });
    
    // 4. Verify Immediate Effect (Route should now exist and not be unlisted)
    await page.waitForTimeout(3000);
    const resp = await request.get(unlistedUrl, asAttacker);
    expect(resp.status()).not.toBe(403);
  });
});
