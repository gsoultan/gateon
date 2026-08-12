// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test, expect } from '@playwright/test';

test.describe('TraceRoute E2E', () => {
  test.setTimeout(120000);

  test('TraceRoute Performance', async ({ page, request }) => {
    // 1. Trigger an anomaly from a specific public IP
    const testIP = '1.2.3.9'; 
    console.log(`Triggering anomaly for IP: ${testIP}`);
    
    // Trigger a WAF violation from this IP. Any attack class will do — this test
    // only needs the address to show up in Diagnostics so the visualiser has a
    // row to act on.
    //
    // Deliberately not SQLi. mitigation-flow.test.ts marks a SQLi detection on
    // /test as a false positive and never removes the exception, and it runs
    // earlier in the file order, so by the time this test runs the WAF correctly
    // allows `id=1 OR 1=1` and the 403 below never arrives. That cost three
    // full attempts and looked like a WAF regression; it was one test's leftover
    // allowlist. XSS is not allowlisted by anything in the suite.
    const resp = await request.get('http://localhost:8081/test?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E', {
      headers: {
        'X-Forwarded-For': testIP
      }
    });
    expect(resp.status()).toBe(403);

    // 2. Find the threat in the Security Hub, not on Diagnostics.
    //
    // This searched /diagnostics for a table row carrying the source IP. That
    // page has no source-IP table: the AnomalyCard it still declares is never
    // mounted, so the row could not exist and the loop below could only ever
    // run out its retries. The threat itself was always recorded — the gateway
    // logs the WAF blocking this request under rule 3010, and
    // /v1/diag/security-threats returns it with source "1.2.3.9", score 100.
    //
    // Threat Explorer is where threat rows live, each with an ActionIcon
    // tooltipped "Trace Visualizer" that opens the visualiser for that source.
    //
    // "Historical Logs", not the default tab: Threat Explorer opens on "Active
    // Threats", which queries status=detected, and a WAF block is recorded as
    // mitigated. Asking the API directly makes the split plain — status=all
    // returns this threat, status=detected returns nothing. Historical Logs is
    // status=all, and it does not depend on whether the mitigation landed
    // against the user fingerprint or the IP.
    //
    // The settle wait matters: selecting the tab starts a fresh query, and
    // reading the row count in the same tick reports the empty table that was
    // rendered before it resolved.
    console.log('Opening the Security Hub threat explorer...');
    const gotoExplorer = async () => {
      await page.goto('/security-center', { waitUntil: 'load' });
      await page.getByRole('tab', { name: /Threat Explorer/i }).click();
      await page.getByRole('tab', { name: /Historical Logs/i }).click();
      await page.waitForTimeout(2000);
    };

    console.log('Waiting for the threat to appear...');
    let found = false;
    for (let i = 0; i < 6; i++) {
        await gotoExplorer();
        if ((await page.getByText(testIP).count()) > 0) {
            found = true;
            break;
        }
        console.log(`Retry ${i+1}: IP ${testIP} not found yet...`);
        await page.waitForTimeout(5000);
    }
    expect(found).toBe(true);

    // The row's trace button, scoped to the row so it cannot pick up a control
    // belonging to a different threat.
    console.log('Searching for the trace button in the row...');
    const visualizeBtn = page.locator('tr').filter({ hasText: testIP })
      .getByRole('button').first();
    await expect(visualizeBtn).toBeVisible({ timeout: 10000 });
    
    // 3. Click the button to trigger TraceRoute Visualizer
    console.log('Clicking Visualize button...');
    const startTime = Date.now();
    await visualizeBtn.click();
    
    // 4. Verify visualizer opens and shows hops
    //
    // The dialog is titled "Visual Trace: <ip>". "Trace Visualizer" is the
    // tooltip on the button that opens it, not the dialog, and hops render as
    // their own IP and location — there is no "Hop 1" label anywhere, so
    // waiting for one could only time out. Completion is the loading state
    // clearing, which is also the thing this test means to time.
    console.log('Waiting for Trace Visualizer to open...');
    await expect(page.getByText(`Visual Trace: ${testIP}`)).toBeVisible({ timeout: 15000 });
    
    // Wait for the hops to load.
    console.log('Waiting for hops data...');
    await expect(page.getByText(/Tracing route across the globe/i)).toBeHidden({ timeout: 15000 });
    
    const duration = Date.now() - startTime;
    console.log(`TraceRoute visualizer took ${duration}ms to show data.`);
    
    // It should definitely be less than 5 seconds now (was much slower before)
    expect(duration).toBeLessThan(5000);
  });
});
