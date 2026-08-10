import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';

// AnomalyAnalysisEngine.Analyze drops every loopback-sourced trace before any
// detector sees it, on purpose: management and test traffic would otherwise
// dominate the anomaly list. Playwright drives everything from 127.0.0.1, so a
// request made without a forwarded-for header is recorded, analysed and then
// discarded — the UNLISTED ROUTE row this test waits for could never appear, and
// it waited out its 20s timeout on every run.
//
// The harness sets GATEON_TRUSTED_PROXIES=127.0.0.1,::1, so X-Forwarded-For from
// the runner is honoured. The address is TEST-NET-3 (RFC 5737), reserved for
// documentation, so it cannot collide with a real client. Every request in this
// flow uses the same one, because anomalies are grouped per source.
const ANOMALY_IP = '203.0.113.21';
const asRemote = { headers: { 'X-Forwarded-For': ANOMALY_IP } };

test.describe('Gateon Diagnostics E2E', () => {
  test.setTimeout(180000);

  test('Diagnostics Performance and Accuracy', async ({ page, request }) => {
    // 1. Initial navigation
    console.log('Navigating to Diagnostics...');
    const startTime = Date.now();
    await page.goto('/diagnostics', { waitUntil: 'load', timeout: 60000 });
    const loadTime = Date.now() - startTime;
    console.log(`Diagnostics initial load time: ${loadTime}ms`);
    
    // Requirement: Superfast load (e.g. < 3s for first load)
    expect(loadTime).toBeLessThan(3000);
    await expect(page.getByText(/Diagnostics & Connectivity/i).first()).toBeVisible({ timeout: 20000 });

    // 2. Trigger Anomalies
    console.log('Triggering security threats...');
    
    // Trigger SQL Injection - Should be caught by WAF
    const sqliResp = await request.get('http://localhost:8081/test?id=1%20OR%201=1', asRemote);
    expect(sqliResp.status()).toBe(403);

    // Trigger Directory Busting (multiple 404s)
    for (let i = 0; i < 5; i++) {
        await request.get(`http://localhost:8081/non-existent-${i}`, asRemote);
    }

    // Trigger unlisted route
    await request.get('http://localhost:8081/api/v1/unknown', asRemote);

    // Give it enough time for the traces to be flushed to store (2s)
    // AND for the background analysis loop to run (5s)
    console.log('Waiting for anomalies to be processed...');
    await page.waitForTimeout(10000);
    
    // Refresh Diagnostics
    await page.reload({ waitUntil: 'load' });
    
    // 3. Verify Anomalies
    console.log('Verifying detected anomalies...');
    
    // Check for UNLISTED ROUTE (from unknown path)
    await expect(page.getByText(/UNLISTED ROUTE/i).first()).toBeVisible({ timeout: 20000 });
    
    // Check for WAF VIOLATION (from SQLi) - should be at the top due to score sorting
    await expect(page.getByText(/WAF VIOLATION/i).first()).toBeVisible({ timeout: 20000 });

    // Verify "Apply Automatic Fix" is available for unlisted route
    const applyFixBtn = page.getByRole('button', { name: /Apply Automatic Fix/i }).first();
    await expect(applyFixBtn).toBeVisible();

    // Navigate to Mitigated tab for WAF BLOCKED
    console.log('Navigating to Mitigated tab...');
    await page.getByRole('tab', { name: /Mitigated/i }).click();

    // Check for WAF BLOCKED (from SQLi)
    await expect(page.getByText(/WAF BLOCKED/i).first()).toBeVisible({ timeout: 20000 });

    // 4. Verify Mitigation
    console.log('Verifying mitigation display...');
    // The IP 1.2.3.4 is blocked in tests/e2e/config/middlewares.json
    await request.get('http://localhost:8081/blocked', {
        headers: { 'X-Forwarded-For': '1.2.3.4' }
    });
    
    await page.waitForTimeout(2000);
    await page.reload({ waitUntil: 'load' });

    // The source 1.2.3.4 should appear in anomalies (if it was flagged before) 
    // or we can just check if any Mitigated badge is visible.
    // In our case, the blocked-route uses block-ip middleware which blocks 1.2.3.4.
    await expect(page.getByText(/Mitigated/i).first()).toBeVisible({ timeout: 10000 });
    
    console.log('Diagnostics E2E scenario completed successfully.');
  });
});
