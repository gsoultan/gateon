// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test, expect, type Page } from '@playwright/test';

/**
 * The Security Hub tabs no spec opened: Incidents, Analytics & Trends and AI
 * Advisory. Each is checked against the gateway's own answer -- what the page
 * renders has to be what the endpoint returned -- and against a failing
 * endpoint. Incidents and attack sources are traffic-derived, so each gets one
 * source that is markup, which has to render as text.
 */

const HOSTILE = '<img src=x onerror=alert(1)>';

async function openTab(page: Page, tab: RegExp) {
  await page.goto('/security-center');
  await page.getByRole('tab', { name: tab }).click();
}

function trapDialogs(page: Page): string[] {
  const dialogs: string[] = [];
  page.on('dialog', (d) => {
    dialogs.push(d.message());
    void d.dismiss();
  });
  return dialogs;
}

test.describe('Security Hub: Incidents', () => {
  test("shows the gateway's incident totals and its posture", async ({ page }) => {
    const incidents = page.waitForResponse((r) => new URL(r.url()).pathname === '/v1/security/incidents');
    const posture = page.waitForResponse((r) => new URL(r.url()).pathname === '/v1/security/posture');
    await openTab(page, /^Incidents$/);
    const inc = await incidents;
    expect(inc.status(), 'GET /v1/security/incidents').toBe(200);
    const body = (await inc.json()) as { totalSeen?: number; retained?: number; incidents?: unknown[] };
    await expect(page.getByText(`${body.totalSeen ?? 0} total · ${body.retained ?? 0} retained`)).toBeVisible();
    if ((body.incidents ?? []).length === 0) {
      await expect(page.getByText('No correlated incidents')).toBeVisible();
    }

    const pos = (await (await posture).json()) as Posture;
    await expect(page.getByText(expectedWafLabel(pos)).first()).toBeVisible();
    const sig = pos.signatures;
    await expect(
      page.getByText(sig.enabled ? `${sig.ruleCount} rules on ${sig.routes} route` : 'Not running').first(),
    ).toBeVisible();
  });

  test('says so when the protection status cannot be loaded', async ({ page }) => {
    await page.route('**/v1/security/posture', (route) =>
      route.fulfill({ status: 500, contentType: 'application/json', body: '{"error":"posture unavailable"}' }),
    );
    await openTab(page, /^Incidents$/);
    await expect(page.getByText('The protection status could not be loaded.')).toBeVisible({ timeout: 15_000 });
  });
});

test.describe('Security Hub: Overview posture', () => {
  test("shows the gateway's posture percentage, not one computed from traffic", async ({ page }) => {
    const posture = page.waitForResponse((r) => new URL(r.url()).pathname === '/v1/security/posture');
    await page.goto('/security-center');
    const pos = (await (await posture).json()) as Posture;
    expect(pos.score.controls.reduce((sum, c) => sum + c.weight, 0), 'control weights').toBe(100);
    const card = page.locator('.mantine-Card-root').filter({ hasText: 'Security Posture' });
    await expect(card).toContainText(`${pos.score.percent}%`);
  });
});

type Posture = {
  waf: {
    mode: 'enforce' | 'detect' | 'off';
    routes: { total: number; enforcing: number; detecting: number; unprotected: number };
  };
  signatures: { enabled: boolean; routes: number; ruleCount: number };
  score: { percent: number; controls: { weight: number }[] };
};

/** The WAF card's words for the report, as postureView.wafStatus chooses them. */
function expectedWafLabel(pos: Posture): string {
  const r = pos.waf.routes;
  if (r.total === 0) {
    return { enforce: 'Blocking', detect: 'Detecting only (audit)', off: 'Disabled' }[pos.waf.mode];
  }
  if (r.unprotected === r.total) return 'Disabled';
  if (r.enforcing === 0) return 'Detecting only (audit)';
  if (r.enforcing === r.total) return 'Blocking on all';
  return `Blocking on ${r.enforcing} of ${r.total}`;
}

test.describe('Security Hub: Incidents list', () => {

  test('an incident is listed with its signals, techniques and score, and its source as text', async ({ page }) => {
    const dialogs = trapDialogs(page);
    await page.route('**/v1/security/incidents*', (route) =>
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          totalSeen: 7,
          retained: 1,
          generatedAt: new Date().toISOString(),
          incidents: [
            {
              id: 'inc-e2e-1',
              sourceKey: HOSTILE,
              sourceIp: '',
              firstSeen: new Date(Date.now() - 60_000).toISOString(),
              lastSeen: new Date().toISOString(),
              severity: 'critical',
              score: 87.5,
              signalCount: 4,
              signalTypes: ['sql_injection', 'path_traversal'],
              techniques: [{ id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' }],
              countries: ['NL'],
            },
          ],
        }),
      }),
    );
    await openTab(page, /^Incidents$/);
    await expect(page.getByText('7 total · 1 retained')).toBeVisible();
    const row = page.getByRole('row').filter({ hasText: 'T1190' });
    await expect(row).toContainText('critical');
    await expect(row).toContainText(HOSTILE);
    await expect(row).toContainText('4 signals');
    await expect(row).toContainText('sql injection');
    await expect(row).toContainText('path traversal');
    await expect(row).toContainText('87.5');
    await expect(row).toContainText('NL');
    await expect(page.locator('img[src="x"]')).toHaveCount(0);
    expect(dialogs, 'an incident source ran as script').toEqual([]);
  });

  test('says so when the incidents cannot be loaded', async ({ page }) => {
    await page.route('**/v1/security/incidents*', (route) =>
      route.fulfill({ status: 500, contentType: 'application/json', body: '{"error":"correlator unavailable"}' }),
    );
    await openTab(page, /^Incidents$/);
    await expect(page.getByText('Failed to load incidents.')).toBeVisible({ timeout: 15_000 });
    await expect(page.getByText('No correlated incidents')).toHaveCount(0);
  });
});

test.describe('Security Hub: Analytics & Trends', () => {
  test("lists the snapshot's top attack sources, and a source that is markup as text", async ({ page }) => {
    const dialogs = trapDialogs(page);
    // Pushed snapshots would replace the one below; hold the stream.
    await page.route('**/v1/watch*', (route) => route.abort());
    let served: { label: string; value: number }[] = [];
    await page.route('**/v1/diag/metrics?*', async (route) => {
      const res = await route.fetch();
      const snap = (await res.json()) as { security?: { topThreatSources?: { label: string; value: number; subtext?: string }[] } };
      snap.security = snap.security ?? {};
      snap.security.topThreatSources = [
        { label: HOSTILE, value: 42, subtext: 'AS64496' },
        ...(snap.security.topThreatSources ?? []),
      ];
      served = snap.security.topThreatSources;
      await route.fulfill({ response: res, json: snap });
    });

    await openTab(page, /Analytics & Trends/);
    const sources = page.locator('.mantine-Card-root').filter({ has: page.getByRole('heading', { name: 'Top Attack Sources' }) });
    await expect(sources.getByRole('row')).toHaveCount(served.length);
    const hostile = sources.getByRole('row').filter({ hasText: HOSTILE });
    await expect(hostile).toContainText('42');
    await expect(hostile).toContainText('ASN: AS64496');
    for (const s of served.slice(1)) {
      await expect(sources.getByRole('row').filter({ hasText: s.label })).toContainText(String(s.value));
    }
    await expect(page.locator('img[src="x"]')).toHaveCount(0);
    expect(dialogs, 'an attack source ran as script').toEqual([]);
  });
});

test.describe('Security Hub: AI Advisory', () => {
  test("renders the gateway's analysis: its summary and every recommendation", async ({ page }) => {
    const analysed = page.waitForResponse(
      (r) => new URL(r.url()).pathname === '/v1/AnalyzeConfig' && r.request().method() === 'POST',
    );
    await openTab(page, /AI Advisory/);
    const res = await analysed;
    expect(res.status(), 'POST /v1/AnalyzeConfig').toBe(200);
    const body = (await res.json()) as { summary: string; insights: { title: string; severity: string; recommendation: string }[] };
    expect(body.insights.length, 'the fixture configuration raised no recommendation').toBeGreaterThan(0);

    await expect(page.getByText('Executive Summary')).toBeVisible();
    await expect(page.getByText(body.summary, { exact: true })).toBeVisible();
    for (const insight of body.insights) {
      await expect(page.getByText(insight.title, { exact: true }).first(), `insight "${insight.title}"`).toBeVisible();
      await expect(page.getByText(insight.recommendation, { exact: true }).first()).toBeVisible();
    }
    if (body.summary.includes('Smart Engine')) {
      await expect(page.getByText(/Local Mode/).first()).toBeVisible();
    }
  });

  test('a failed analysis says so without showing what the server wrote', async ({ page }) => {
    await page.route('**/v1/AnalyzeConfig', (route) =>
      route.fulfill({ status: 500, contentType: 'text/html', body: '<h1>stack trace: panic at analyzer.go:42</h1>' }),
    );
    await openTab(page, /AI Advisory/);
    const alert = page.getByRole('alert').filter({ hasText: 'Analysis Error' });
    await expect(alert).toBeVisible();
    await expect(alert).toContainText('The analysis could not be completed. Try again in a moment.');
    await expect(page.getByText(/stack trace|analyzer\.go/)).toHaveCount(0);
  });
});
