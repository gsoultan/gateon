import { test, expect } from '@playwright/test';

test.describe('TraceRoute E2E', () => {
  test.setTimeout(120000);

  test('TraceRoute Performance', async ({ page, request }) => {
    // 1. Trigger an anomaly from a specific public IP
    const testIP = '1.2.3.9'; 
    console.log(`Triggering anomaly for IP: ${testIP}`);
    
    // Trigger a WAF violation (SQLi) from this IP
    const resp = await request.get('http://localhost:8081/test?id=1%20OR%201=1', {
      headers: {
        'X-Forwarded-For': testIP
      }
    });
    expect(resp.status()).toBe(403);

    // 2. Navigate to Diagnostics and wait for the anomaly
    console.log('Navigating to Diagnostics...');
    await page.goto('/diagnostics', { waitUntil: 'load', timeout: 60000 });
    
    console.log('Waiting for the anomaly to appear...');
    let found = false;
    for (let i = 0; i < 6; i++) {
        await page.waitForTimeout(5000);
        await page.reload({ waitUntil: 'load' });
        const count = await page.getByText(testIP).count();
        if (count > 0) {
            found = true;
            break;
        }
        console.log(`Retry ${i+1}: IP ${testIP} not found yet...`);
    }
    expect(found).toBe(true);

    // Find the row with the IP and click the "Visualize IP Route" button
    console.log('Searching for visualize button in the table...');
    const visualizeBtn = page.locator('tr').filter({ hasText: testIP }).locator('button').first();
    await expect(visualizeBtn).toBeVisible({ timeout: 10000 });
    
    // 3. Click the button to trigger TraceRoute Visualizer
    console.log('Clicking Visualize button...');
    const startTime = Date.now();
    await visualizeBtn.click();
    
    // 4. Verify visualizer opens and shows hops
    console.log('Waiting for Trace Visualizer to open...');
    await expect(page.getByText(/Trace Visualizer/i)).toBeVisible({ timeout: 15000 });
    
    // Wait for the hops to load.
    console.log('Waiting for hops data...');
    await expect(page.getByText(/Hop 1/i)).toBeVisible({ timeout: 15000 });
    
    const duration = Date.now() - startTime;
    console.log(`TraceRoute visualizer took ${duration}ms to show data.`);
    
    // It should definitely be less than 5 seconds now (was much slower before)
    expect(duration).toBeLessThan(5000);
  });
});
