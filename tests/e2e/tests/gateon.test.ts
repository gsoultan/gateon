// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test, expect, type APIResponse } from '@playwright/test';
import { execSync } from 'child_process';

test.describe('Gateon Comprehensive E2E', () => {
  test.setTimeout(120000);

  test('UI Dashboard Features', async ({ page }) => {
    // Retry goto with a small delay if it fails due to network reset
    const navigate = async (url: string) => {
        for (let i = 0; i < 3; i++) {
            try {
                await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 60000 });
                return;
            } catch (e: any) {
                if (i === 2) throw e;
                console.log(`Navigation to ${url} failed, retrying in 2s...`);
                await page.waitForTimeout(2000);
            }
        }
    };

    await navigate('/');
    await expect(page.getByText(/System Health/i)).toBeVisible({ timeout: 30000 });
    await expect(page.getByText(/TRAFFIC METRICS/i)).toBeVisible();

    // Security Hub
    console.log('Navigating to Security Hub...');
    try {
        await page.getByRole('link', { name: /Security Hub/i }).click();
        await expect(page.getByText(/Security Hub/i).first()).toBeVisible({ timeout: 40000 });
    } catch (e) {
        console.warn('Security Hub Navigation via click failed, trying goto...');
        await page.goto('/security-center', { waitUntil: 'domcontentloaded', timeout: 40000 });
        await expect(page.getByText(/Security Hub/i).first()).toBeVisible({ timeout: 20000 });
    }
    
    // Diagnostics
    console.log('Navigating to Diagnostics...');
    try {
        await page.getByRole('link', { name: /Diagnostics/i }).click();
        await expect(page.getByText(/Diagnostics & Connectivity/i).first()).toBeVisible({ timeout: 30000 });
    } catch (e) {
        await navigate('/diagnostics');
        await expect(page.getByText(/Diagnostics & Connectivity/i).first()).toBeVisible({ timeout: 20000 });
    }

    // Traces
    console.log('Navigating to Traces...');
    try {
        await page.getByRole('link', { name: /Traces/i }).click();
        await expect(page.getByText(/Distributed Tracing/i).first()).toBeVisible({ timeout: 30000 });
    } catch (e) {
        await navigate('/traces');
        await expect(page.getByText(/Distributed Tracing/i).first()).toBeVisible({ timeout: 20000 });
    }
  });

  test('HTTP Proxying and Middlewares', async ({ request }) => {
    // Wait for services to be ready
    execSync('go run wait_for_port/main.go localhost:8081');
    execSync('go run wait_for_port/main.go localhost:8082');

    // Wait a bit more for proxy engine to fully initialize routes
    await new Promise(r => setTimeout(r, 2000));

    // Positive case with Header and CORS
    const resp1 = await request.get('http://localhost:8081/test', {
      headers: { 'Origin': 'http://localhost:3000' }
    });
    expect(resp1.status()).toBe(200);
    // Response headers should contain our custom header
    expect(resp1.headers()['x-test-gateon']).toBe('true');
    expect(resp1.headers()['access-control-allow-origin']).toBe('*');

    // Negative case (IP Filter)
    const resp2 = await request.get('http://localhost:8081/blocked', {
      headers: { 'X-Forwarded-For': '1.2.3.4' }
    });
    expect(resp2.status()).toBe(403);

    // Rate limiting. /ratelimit carries ratelimit-strict: 10 requests a minute
    // with a burst of 20, keyed by client address. This used to send 16
    // requests, which fit inside the burst, and only logged the status of the
    // last one, so it passed whether or not the limiter was on the route. The
    // fixture also set "average", a key the limiter never reads.
    //
    // Keep asking until refused, and bound how many were served first: the
    // burst plus at most one token refilled while the loop runs (one every six
    // seconds). Counting served-before-refusal rather than asserting the first
    // request succeeds keeps a CI retry honest: a retry meets the bucket this
    // attempt drained, and is refused sooner, which is the limit working.
    let served = 0;
    let refusal: APIResponse | undefined;
    for (let i = 0; i < 40 && !refusal; i++) {
        const resp = await request.get('http://localhost:8081/ratelimit');
        if (resp.status() === 429) refusal = resp;
        else {
            expect(resp.status(), `request ${i + 1} to /ratelimit`).toBe(200);
            served++;
        }
    }
    expect(refusal, `40 requests against a burst of 20: none was refused (${served} served)`).toBeDefined();
    expect(served).toBeLessThanOrEqual(21);
    expect(refusal!.headers()['retry-after']).toBe('1');
    expect((await refusal!.json()).error).toBe('too many requests');
  });

  test('WAF Security Threat Detection', async ({ page, request }) => {
    // Simulate SQL Injection
    const sqliResp = await request.get('http://localhost:8081/test?id=1%20OR%201=1');
    expect(sqliResp.status()).toBe(403);

    // Simulate XSS
    const xssResp = await request.get('http://localhost:8081/test?q=<script>alert(1)</script>');
    expect(xssResp.status()).toBe(403);

    // Verify threats appear in Security Hub
    await page.goto('/security-center');
    await page.reload();
    // We expect some threats to be logged. Depending on how fast they are processed
    // it might take a few seconds.
    await page.waitForTimeout(5000);
    // Check if threat count is > 0 or specific text is visible
    // This depends on the UI implementation of Security Hub
  });

  test('gRPC Proxying', async () => {
    execSync('go run wait_for_port/main.go localhost:8085');
    execSync('go run wait_for_port/main.go localhost:8083');
    // Use the Go test client
    try {
        const output = execSync('go run ./grpc_test_client 2>&1', { encoding: 'utf-8', timeout: 30000, env: { ...process.env, GODEBUG: "http2debug=2" } });
        console.log('gRPC Client Output:', output);
        expect(output).toContain('Response: Echo: Gateon Test');
    } catch (e: any) {
        console.error('gRPC Client Error:', e.stdout || e.message);
        throw e;
    }
  });

  test('TCP Proxying', async () => {
    execSync('go run wait_for_port/main.go localhost:8086');
    execSync('go run wait_for_port/main.go localhost:8084');
    // Use the Go test client
    try {
        const output = execSync('go run ./tcp_test_client 2>&1', { encoding: 'utf-8', timeout: 30000 });
        console.log('TCP Client Output:', output);
        expect(output).toContain('Response: TCP Echo: Gateon TCP Test');
    } catch (e: any) {
        console.error('TCP Client Error:', e.stdout || e.message);
        throw e;
    }
  });

  test('Dashboard Realtime and Accuracy', async ({ page, request }) => {
    // The "Requests / 24h" card shows the metrics snapshot: fetched once when
    // the page loads, then pushed over /v1/watch on every telemetry refresh.
    // This used to check that a chart surface existed, which it does with no
    // traffic at all, so it passed whether or not anything on the page moved.
    // Now the same page -- never reloaded -- has to show traffic sent after it
    // loaded.
    const firstSnapshot = page.waitForResponse(
      (r) => r.url().includes('/v1/diag/metrics') && r.request().method() === 'GET');
    await page.goto('/', { waitUntil: 'load' });
    const loaded = Number((await (await firstSnapshot).json()).goldenSignals?.requestsToday ?? 0);
    const card = page.getByText('Requests / 24h', { exact: true })
      .locator('xpath=following-sibling::*[1]');
    const shown = async () => Number((await card.innerText()).replaceAll(',', ''));
    // The card reads 0 until that snapshot renders; a baseline taken earlier
    // would let the initial load itself pass for a live update. Nothing but
    // the push moves it after this: the query has no refetch interval.
    await expect.poll(shown, { timeout: 20000 }).toBeGreaterThanOrEqual(loaded);
    const before = await shown();
    // From 1000 on the card reads "1.2K", which five requests cannot move.
    expect(before, 'the card is too coarse for this check from 1000 on').toBeLessThan(995);

    for (let i = 0; i < 5; i++) {
        expect((await request.get('http://localhost:8081/test')).status()).toBe(200);
    }
    await expect.poll(shown, {
      message: `the dashboard never showed the 5 requests sent after it loaded (it showed ${before} before them)`,
      timeout: 45000,
    }).toBeGreaterThanOrEqual(before + 5);
  });
});
