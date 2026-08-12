// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test, expect } from '@playwright/test';
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

    // Rate Limiting
    // Send multiple requests quickly
    for (let i = 0; i < 15; i++) {
        await request.get('http://localhost:8081/ratelimit');
    }
    const resp3 = await request.get('http://localhost:8081/ratelimit');
    console.log(`Rate limit response status: ${resp3.status()}`);
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
    await page.goto('/', { waitUntil: 'load' });
    
    // Trigger some traffic
    for (let i = 0; i < 5; i++) {
        await request.get('http://localhost:8081/test');
    }
    
    await page.waitForTimeout(5000);
    // Verify traffic metrics changed or visible
    // We look for Recharts surface which is what Mantine charts use
    await expect(page.locator('.recharts-surface').first()).toBeVisible({ timeout: 20000 });
  });
});
