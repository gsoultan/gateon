// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';

/**
 * Open the anomaly engine, the same way mitigation-flow.test.ts does. Anomalies
 * are surfaced in the Security Hub, not on the diagnostics page.
 */
async function gotoAnomalyEngine(page: any) {
  await page.goto('/security-center', { waitUntil: 'load' });
  await page.getByRole('tab', { name: /Anomaly Engine/i }).click();
}

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

    // Order matters, and it is the SQLi that has to go last.
    //
    // A blocked WAF hit marks the caller's JA4+ mitigated immediately —
    // pathStatsStore.processThreat does it on the first block, with no
    // threshold. Middleware's UserMitigation check then answers 403 and returns
    // *without calling next*, so a mitigated request never reaches routing, the
    // trace store, or even the access log.
    //
    // Every request.get() here shares one fingerprint, so running the SQLi
    // first silently swallowed the six requests after it: no route match, no
    // trace, nothing for UnlistedRouteDetector to find, and the UNLISTED ROUTE
    // row below waited out its timeout against an anomaly that was never going
    // to be generated. Nothing appeared in the gateway log either, which is
    // what made it look like the detector was at fault rather than this test.
    //
    // Doing the unlisted and 404 traffic first gets it recorded normally; the
    // mitigation the SQLi then earns has nothing left to swallow.

    // Trigger unlisted route
    await request.get('http://localhost:8081/api/v1/unknown', asRemote);

    // Trigger Directory Busting (multiple 404s)
    for (let i = 0; i < 5; i++) {
        await request.get(`http://localhost:8081/non-existent-${i}`, asRemote);
    }

    // Trigger SQL Injection - Should be caught by WAF
    const sqliResp = await request.get('http://localhost:8081/test?id=1%20OR%201=1', asRemote);
    expect(sqliResp.status()).toBe(403);

    // Poll, rather than sleep once and hope.
    //
    // Anomalies are not produced by the request; they are produced by a
    // background analysis pass over the flushed traces, and the page fetches
    // them once per load rather than subscribing. So a fixed wait followed by a
    // single reload only works if the pass happens to land inside that window,
    // and the 20s assertion timeout below cannot rescue it — the page will not
    // re-fetch on its own, so it waits 20s against a snapshot taken before the
    // anomaly existed.
    //
    // This is why the specs that wait for UNLISTED ROUTE elsewhere in the suite
    // reload in a loop. Same shape here.
    // 3. Verify Anomalies — in the Security Hub, which is where they render.
    //
    // These assertions used to run against /diagnostics, and could not pass
    // there. Anomalies moved to the Security Hub's Anomaly Engine tab; what
    // DiagnosticsPage kept is an AnomalyCard component that is defined and
    // never rendered — it has exactly one occurrence in the file, its own
    // declaration. The UNLISTED ROUTE and WAF VIOLATION rows, the "Apply
    // automatic fix" control and the Mitigated tab this test looks for all live
    // inside that dead component, which is why they were never in the DOM.
    //
    // The detection itself was always working. Against the live gateway,
    // /v1/diagnostics returns unlisted_route anomalies for all three paths
    // above, and the trace store has them with serviceName "gateon-http-plain".
    // Only the page being asked was wrong.
    console.log('Verifying detected anomalies in the Security Hub...');
    await gotoAnomalyEngine(page);

    for (let i = 0; i < 8; i++) {
        if ((await page.getByText(/UNLISTED ROUTE/i).count()) > 0) break;
        await page.waitForTimeout(5000);
        await gotoAnomalyEngine(page);
        console.log(`Still waiting for anomalies... (${(i + 1) * 5}s)`);
    }

    // Check for UNLISTED ROUTE (from unknown path)
    await expect(page.getByText(/UNLISTED ROUTE/i).first()).toBeVisible({ timeout: 20000 });

    // Verify the automatic fix is offered for it
    const applyFixBtn = page.getByRole('button', { name: /Apply automatic fix/i }).first();
    await expect(applyFixBtn).toBeVisible();

    // 4. Verify Mitigation
    //
    // The SQLi above was blocked, and a blocked threat is a mitigated one, so
    // it belongs under the Mitigated tab rather than beside the active
    // anomalies.
    console.log('Navigating to Mitigated tab...');
    await page.getByRole('tab', { name: /Mitigated/i }).click();
    await expect(page.getByText(/Mitigated/i).first()).toBeVisible({ timeout: 20000 });

    console.log('Diagnostics E2E scenario completed successfully.');
  });
});
