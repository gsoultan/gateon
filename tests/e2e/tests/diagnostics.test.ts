// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

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

  // Release the JA4+ mitigation this spec earns, or every later spec gets a 403.
  //
  // Sending the SQLi from a routable address is what makes the WAF violation
  // above real: the threat is now recorded instead of dropped, which is the
  // whole point of the header. But a recorded block is not inert.
  // pathStatsStore.processThreat marks the *fingerprint* mitigated the moment a
  // threat comes back blocked — no threshold, no decay — and middleware's
  // UserMitigation check then rejects everything carrying it.
  //
  // Playwright's APIRequestContext is one Node HTTP client, so every
  // request.get() in the entire suite presents the same JA4+. One earned
  // mitigation therefore 403s every subsequent spec, and the failures surface
  // far from here, looking like unrelated breakage in whatever ran next.
  //
  // There is no way to both leave the mitigation in place and keep using the
  // runner: the fingerprint is shared, so it is all-or-nothing. The spec that
  // earns it has to hand it back. MarkUserUnmitigated also records a 24h
  // marker that processThreat honours, so this holds for the rest of the run
  // rather than being re-applied by the next blocked request.
  test.afterAll(async ({ playwright }) => {
    const api = await playwright.request.newContext({
      baseURL: 'http://localhost:8080',
      storageState: 'tests/.auth/admin.json',
    });
    try {
      const res = await api.get('/v1/diag/security-threats?limit=200');
      if (!res.ok()) {
        console.warn(`Mitigation teardown: threat list returned ${res.status()}; skipping.`);
        return;
      }
      const body = await res.json();
      // protojson omits empty strings, so read defensively and fall back to
      // composing JA4+ the way the store does when only the parts are present.
      const prints = new Set<string>();
      for (const t of body.threats ?? []) {
        const fp = t.ja4plus || (t.ja4 && t.ja4h ? `${t.ja4}_${t.ja4h}` : '');
        if (fp) prints.add(fp);
      }
      for (const fp of prints) {
        const removed = await api.post('/v1/diagnostics/remove-mitigation', { data: { source: fp } });
        console.log(`Mitigation teardown: released ${fp} -> ${removed.status()}`);
      }
      if (prints.size === 0) console.warn('Mitigation teardown: no fingerprints found on any threat.');
    } finally {
      await api.dispose();
    }
  });

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
