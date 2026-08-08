import { test, expect } from '@playwright/test';

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
    await page.goto('/diagnostics', { waitUntil: 'load' });
    
    // Wait for the anomaly to appear.
    await page.waitForTimeout(10000);
    await page.reload({ waitUntil: 'load' });

    const scanThreat = page.locator('text=/UNLISTED ROUTE/i').first();
    await expect(scanThreat).toBeVisible({ timeout: 20000 });
    
    // 3. Apply Automatic Fix
    const blockBtn = page.getByRole('button', { name: /Apply Automatic Fix/i }).first();
    await blockBtn.click();
    
    await expect(page.getByText(/Recommendation Applied/i)).toBeVisible({ timeout: 10000 });
    
    // 4. Verify Immediate Effect (Route should now exist and not be unlisted)
    await page.waitForTimeout(3000);
    const resp = await request.get(unlistedUrl, asAttacker);
    expect(resp.status()).not.toBe(403);
  });
});
