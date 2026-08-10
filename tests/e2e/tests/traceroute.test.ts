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
