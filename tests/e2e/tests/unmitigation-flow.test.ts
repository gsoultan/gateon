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

  test('Manual IP mitigation from Threat Explorer, and releasing it', async ({ page, request }) => {
    // This used to drive the anomaly modal and click "Block IP". No such
    // control exists: the anomaly modal offers "Apply automatic fix", which for
    // an unlisted route flags the path rather than blocking anyone. Manual
    // blocking lives in Threat Explorer behind "Add Mitigation", which opens
    // ManualMitigationModal — so the capability was never retired, it moved,
    // and the spec kept asking the old place. That is the seventh instance of
    // the same pattern in this suite.
    //
    // The flow it always meant to cover is unchanged: block a source, prove the
    // block bites, release it, prove the release lands.
    const blockedIP = '203.0.113.77';
    const probeUrl = `http://localhost:8081/test?tid=manual-${Date.now()}`;
    const asBlocked = { headers: { 'X-Forwarded-For': blockedIP } };

    // Control first. If this address is already blocked the assertions below
    // prove nothing, and a blanket 403 would satisfy every one of them.
    const before = await request.get(probeUrl, asBlocked);
    expect(before.status(), 'control request was refused before anything was mitigated')
      .toBe(200);

    const gotoExplorer = async () => {
      await page.goto('/security-center', { waitUntil: 'load' });
      await page.getByRole('tab', { name: /Threat Explorer/i }).click();
      await page.waitForTimeout(1500);
    };

    // 1. Block the address.
    await gotoExplorer();
    await page.getByRole('button', { name: /Add Mitigation/i }).click();
    await expect(page.getByText(/Add Manual Mitigation/i)).toBeVisible({ timeout: 10000 });
    await page.getByLabel(/Source \(IP or Fingerprint\)/i).fill(blockedIP);
    await page.getByRole('button', { name: /Block Source/i }).click();

    // 2. It has to actually bite.
    await page.waitForTimeout(3000);
    const blocked = await request.get(probeUrl, asBlocked);
    expect(blocked.status(), `${blockedIP} was mitigated but its traffic is still served`)
      .toBe(403);

    // 3. Release it from the Mitigated tab.
    await gotoExplorer();
    // "IP Mitigations", because the Mitigated tab opens on User Mitigations and
    // this is an IP block — the sub-tab selects userMitigated vs ipMitigated in
    // the query, so the default view genuinely does not contain it.
    await page.getByRole('tab', { name: /^Mitigated/ }).click();
    await page.getByRole('tab', { name: /IP Mitigations/i }).click();
    await page.waitForTimeout(2000);

    const row = page.locator('tr').filter({ hasText: blockedIP }).first();
    await expect(row, 'the address does not appear under Mitigated after being blocked')
      .toBeVisible({ timeout: 20000 });
    await row.getByRole('button', { name: /^Allow$/ }).click();

    // 4. And the release has to land. Asserted against the control plane rather
    // than by replaying the request: every request.get() in this suite shares
    // one JA4+, and the spec above earns a fingerprint mitigation on it, so a
    // 403 here would not tell us whether the IP release worked.
    await page.waitForTimeout(3000);
    await gotoExplorer();
    // "IP Mitigations", because the Mitigated tab opens on User Mitigations and
    // this is an IP block — the sub-tab selects userMitigated vs ipMitigated in
    // the query, so the default view genuinely does not contain it.
    await page.getByRole('tab', { name: /^Mitigated/ }).click();
    await page.getByRole('tab', { name: /IP Mitigations/i }).click();
    await page.waitForTimeout(2000);

    await expect(
      page.locator('tr').filter({ hasText: blockedIP }),
      'the address is still listed as mitigated after Allow was clicked',
    ).toHaveCount(0);
  });
});
