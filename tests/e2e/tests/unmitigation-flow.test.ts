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

// See mitigation-flow.test.ts: threats from a loopback source are dropped by
// design, so these flows must present themselves as a remote client or the
// Security Hub stays empty and the test times out waiting on it.
const ATTACKER_IP = '203.0.113.12';
const asAttacker = { headers: { 'X-Forwarded-For': ATTACKER_IP } };

test.describe('Threat Unmitigation E2E Flow', () => {
  test.setTimeout(180000);

  test('Remove Mitigation from Security Hub (WAF)', async ({ page, request }) => {
    console.log('--- Starting WAF Unmitigation Test ---');
    
    // Unique ID to identify our threat
    const testId = 'unmitigate-waf-' + Date.now();
    const xssUrl = `http://localhost:8081/test?xss=<script>alert(1)</script>&tid=${testId}`;
    const normalUrl = `http://localhost:8081/test?tid=${testId}`;

    // 1. Trigger XSS (Blocked by WAF)
    console.log(`Triggering XSS with tid=${testId}...`);
    for (let i = 0; i < 3; i++) {
        const xssResp = await request.get(xssUrl, asAttacker);
        expect(xssResp.status()).toBe(403);
    }

    // 2. Go to Security Center -> Threat Explorer
    await page.goto('/security-center', { waitUntil: 'load' });
    
    console.log('Waiting for threat to appear...');
    await page.waitForTimeout(10000);
    await page.reload({ waitUntil: 'load' });
    
    // Look for WAF or Fast Path threat
    const threatRow = page.locator('tr').filter({ hasText: /WAF|FAST PATH/i }).first();
    await expect(threatRow).toBeVisible({ timeout: 20000 });
    
    // 3. Open Modal and Remove Mitigation
    //
    // The first cell, not the row: the row's centre is the Source IP cell, whose
    // own onClick opens the trace visualiser instead. See mitigation-flow.test.ts.
    await threatRow.locator('td').first().click();
    await expect(page.getByText(/Security Incident Details/i)).toBeVisible({ timeout: 10000 });
    
    // "Blocked", not "Mitigated". The modal's status badge reports what was
    // *done*: actionTaken "blocked"/"shunned"/"challenged" all render "Blocked",
    // and only a threat that is mitigated without having been stopped shows
    // "Mitigated". A WAF block is always the former, so this assertion could
    // never hold for the XSS above. The mitigation itself is still real — the
    // Remove Mitigation button below only renders when anomaly.mitigated is set.
    await expect(page.locator('span').filter({ hasText: /^Blocked$/ }).first()).toBeVisible();

    console.log('Clicking Remove Mitigation...');
    const removeBtn = page.getByRole('button', { name: /Remove Mitigation/i });
    await expect(removeBtn).toBeVisible();
    await removeBtn.click();
    
    const confirmBtn = page.getByRole('button', { name: /Confirm Removal/i });
    await expect(confirmBtn).toBeVisible();
    await confirmBtn.click();
    
    // 4. Verify Immediate Effect (Normal request should pass)
    await page.waitForTimeout(3000);
    const normalResp = await request.get(normalUrl, asAttacker);
    expect(normalResp.status()).toBe(200);
    console.log('Verified: Normal request allowed after unmitigation.');

    // 5. Verify Bad request is still blocked (WAF still active)
    const xssResp = await request.get(xssUrl, asAttacker);
    expect(xssResp.status()).toBe(403);
    console.log('Verified: Bad request still blocked by WAF.');
  });

  test('Remove Mitigation from Diagnostics Tab', async ({ page, request }) => {
    console.log('--- Starting Diagnostics Unmitigation Test ---');
    
    const testId = 'unmitigate-diag-' + Date.now();
    const unlistedUrl = `http://localhost:8081/unlisted-path-${testId}`;
    const normalUrl = `http://localhost:8081/test?tid=${testId}`;

    // 1. Trigger Unlisted Route (multiple times to ensure detection)
    console.log(`Triggering Unlisted Route with tid=${testId}...`);
    for (let i = 0; i < 5; i++) {
        await request.get(unlistedUrl, asAttacker);
        await page.waitForTimeout(500); // Small delay
    }

    // 2. Go to Diagnostics -> Active tab
    await gotoAnomalyEngine(page);
    
    console.log('Waiting for anomaly to appear in Diagnostics (Analysis Engine needs time)...');
    // Analysis engine runs every 5-10 seconds.
    for (let i = 0; i < 6; i++) {
        await page.waitForTimeout(5000);
        await gotoAnomalyEngine(page);
        const text = await page.innerText('body');
        if (text.includes('UNLISTED')) break;
        console.log(`Still waiting for UNLISTED anomaly... (${(i+1)*5}s)`);
    }

    console.log('Checking Diagnostics for anomaly...');
    const anomaly = page.getByTestId('anomaly-card').filter({ hasText: /UNLISTED/i }).last();
    await expect(anomaly).toBeVisible({ timeout: 20000 });
    
    // 3. Apply Block IP (Manual mitigation)
    console.log('Applying Block IP...');
    // We click the card to open the modal
    await anomaly.click({ force: true });
    // The modal's content, not its root. data-testid lands on Mantine's Modal
    // root wrapper, which has no layout box of its own, so Playwright reports it
    // hidden even while the dialog is plainly on screen. The title is inside it.
    await expect(page.getByText(/Security Incident Details/i)).toBeVisible({ timeout: 10000 });
    
    const blockBtn = page.getByRole('button', { name: /Block IP/i });
    await expect(blockBtn).toBeVisible();
    await blockBtn.click();
    
    await expect(page.getByText(/Applied|Blocked/i)).toBeVisible({ timeout: 15000 });
    
    // Verify IP is blocked now even for normal requests
    await page.waitForTimeout(3000);
    const blockedResp = await request.get(normalUrl, asAttacker);
    expect(blockedResp.status()).toBe(403);
    console.log('Verified: IP is blocked.');

    // 4. Go to Mitigated tab
    console.log('Navigating to Mitigated tab...');
    // Close modal if still open
    await page.keyboard.press('Escape');
    await page.getByRole('tab', { name: /Mitigated/i }).click();
    
    console.log('Waiting for anomaly to appear in Mitigated tab...');
    for (let i = 0; i < 6; i++) {
        await page.waitForTimeout(3000);
        const text = await page.innerText('body');
        if (text.includes('UNLISTED')) break;
        console.log(`Still waiting for UNLISTED in Mitigated tab... (${(i+1)*3}s)`);
    }

    const mitigatedAnomaly = page.getByTestId('anomaly-card').filter({ hasText: /UNLISTED/i }).last();
    await expect(mitigatedAnomaly).toBeVisible({ timeout: 10000 });
    
    // 5. Open details and Remove Mitigation
    await mitigatedAnomaly.click({ force: true });
    // The modal's content, not its root. data-testid lands on Mantine's Modal
    // root wrapper, which has no layout box of its own, so Playwright reports it
    // hidden even while the dialog is plainly on screen. The title is inside it.
    await expect(page.getByText(/Security Incident Details/i)).toBeVisible({ timeout: 10000 });
    
    console.log('Clicking Remove Mitigation...');
    const removeBtn = page.getByRole('button', { name: /Remove Mitigation/i });
    await expect(removeBtn).toBeVisible();
    await removeBtn.click();
    
    const confirmBtn = page.getByRole('button', { name: /Confirm Removal/i });
    await expect(confirmBtn).toBeVisible();
    await confirmBtn.click();
    
    // 6. Verify Effect
    await page.waitForTimeout(3000);
    const allowedResp = await request.get(normalUrl, asAttacker);
    expect(allowedResp.status()).toBe(200);
    console.log('Verified: IP unblocked after unmitigation from Diagnostics.');
  });
});
