import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';

test.describe('Advanced Security & Global WAF E2E', () => {
  test.setTimeout(120000);

  test.beforeEach(async ({ page }) => {
    // Wait for gateon to be ready
    execSync('go run wait_for_port/main.go localhost:8080');
    await page.goto('/settings', { waitUntil: 'load' });
  });

  test.afterEach(async ({ page }) => {
    // Ensure all security settings are disabled after each test to avoid side effects
    try {
        await page.goto('/settings', { waitUntil: 'domcontentloaded', timeout: 30000 });
        
        // 1. Reset Global WAF & Anomaly Threshold
        const wafSwitchInput = page.getByLabel('Protect all routes');
        const wafSwitchLabel = page.locator('label').filter({ hasText: 'Protect all routes' });
        
        if (await wafSwitchLabel.isVisible()) {
            const isChecked = await wafSwitchInput.isChecked();
            if (isChecked) {
                await wafSwitchLabel.click();
                const saveWafBtn = page.getByRole('button', { name: 'Save WAF Settings' });
                if (await saveWafBtn.isVisible()) {
                    await saveWafBtn.click();
                    await expect(page.getByText(/Saved/i)).toBeVisible();
                }
            }
        }

        // 2. Disable Advanced Security features (Honeypots, Tarpit).
        // These switches are rendered by SecurityAdvancedSettingsCard on the
        // settings page we are already on. This used to navigate to
        // /security-center and click an "Advanced" tab, which never existed
        // there — the click timed out, the cleanup was skipped, and every
        // later test in the file inherited whatever state the previous one
        // left behind.
        let needsSave = false;
        // Disable Deception
        const deceptionSwitchInput = page.locator('input#deception-enabled-switch');
        const deceptionSwitchLabel = page.locator('label[for="deception-enabled-switch"]');
        if (await deceptionSwitchLabel.isVisible() && (await deceptionSwitchInput.isChecked())) {
            await deceptionSwitchLabel.click();
            needsSave = true;
        }

        // Disable Tarpit
        const tarpitSwitchInput = page.locator('input#tarpit-enabled-switch');
        const tarpitSwitchLabel = page.locator('label[for="tarpit-enabled-switch"]');
        if (await tarpitSwitchLabel.isVisible() && (await tarpitSwitchInput.isChecked())) {
            await tarpitSwitchLabel.click();
            needsSave = true;
        }

        if (needsSave) {
            const saveGlobalBtn = page.getByRole('button', { name: 'Save Global Configuration' });
            if (await saveGlobalBtn.isVisible()) {
                await saveGlobalBtn.click();
                await expect(page.getByText(/Saved/i)).toBeVisible();
            }
        }
    } catch (e) {
        console.warn('Cleanup failed', e);
    }
  });

  test('Global WAF Management', async ({ page, request }) => {
    // 1. Enable Global WAF in settings
    const wafSwitchLabel = page.locator('label').filter({ hasText: 'Protect all routes' });
    const wafSwitchInput = page.getByLabel('Protect all routes');
    await expect(wafSwitchLabel).toBeVisible({ timeout: 20000 });
    
    const isChecked = await wafSwitchInput.isChecked();
    if (!isChecked) {
        await wafSwitchLabel.click();
    }

    // The WAF detail fields live behind two gates — `config.waf.enabled` and
    // `config.waf.useCrs` — and both read state that arrives from /v1/global
    // *after* first paint. The "Protect all routes" switch sits outside those
    // gates, so it appears immediately and is not evidence the config has
    // loaded. Waiting a fixed second was a race the loaded page usually lost.
    // The CRS switch is inside the first gate, so its presence is the signal.
    await expect(page.getByLabel('Use OWASP Core Rule Set (CRS)')).toBeVisible({ timeout: 20000 });

    // Set Anomaly Threshold to 1 for easy testing
    const thresholdInput = page.getByLabel('Global Anomaly Threshold');
    await expect(thresholdInput).toBeVisible({ timeout: 20000 });
    await thresholdInput.fill('1');

    const saveBtn = page.getByRole('button', { name: 'Save WAF Settings' });
    await saveBtn.scrollIntoViewIfNeeded();
    await saveBtn.click();
    await expect(page.getByText(/Saved/i)).toBeVisible();

    // 2. Verify Global WAF blocks attack on ANY route
    await new Promise(r => setTimeout(r, 2000));
    const sqliResp = await request.get('http://localhost:8081/test?id=1%20OR%201=1');
    expect(sqliResp.status()).toBe(403);
    
    // A different route
    const sqliResp2 = await request.get('http://localhost:8081/ratelimit?id=1%20OR%201=1');
    expect(sqliResp2.status()).toBe(403);
  });

  test('Advanced Protection - Deception (Honeypots)', async ({ page, request }) => {
    // 1. Enable Deception
    const deceptionSwitchLabel = page.locator('label[for="deception-enabled-switch"]');
    await expect(deceptionSwitchLabel).toBeAttached({ timeout: 20000 });
    
    // Check if already checked
    const deceptionSwitchInput = page.locator('input#deception-enabled-switch');
    if (!(await deceptionSwitchInput.isChecked())) {
        await deceptionSwitchLabel.click();
    }
    await page.waitForTimeout(2000);
    
    // Wait for the TagsInput to appear (it's conditional on deception.enabled)
    const honeyPathInput = page.locator('input[placeholder="/.env, /wp-admin, /_backup"]');
    await expect(honeyPathInput).toBeVisible({ timeout: 30000 });
    await honeyPathInput.fill('/secret-admin');
    await honeyPathInput.press('Enter');

    const saveBtn = page.getByRole('button', { name: 'Save Global Configuration' });
    await saveBtn.scrollIntoViewIfNeeded();
    await saveBtn.click();
    await expect(page.getByText(/Saved/i)).toBeVisible();

    // 2. Verify Honeypot path is blocked/intercepted
    // Wait for config reload
    await new Promise(r => setTimeout(r, 5000));
    
    const honeyResp = await request.get('http://localhost:8081/secret-admin');
    expect(honeyResp.status()).toBe(403);

    // 3. Cleanup: Disable Deception
    await deceptionSwitchLabel.click();
    await saveBtn.click();
    await expect(page.getByText(/Saved/i)).toBeVisible();
  });

  test('Advanced Protection - Tarpit', async ({ page, request }) => {
    // 1. Enable Tarpit
    const tarpitSwitchLabel = page.locator('label[for="tarpit-enabled-switch"]');
    await expect(tarpitSwitchLabel).toBeAttached({ timeout: 20000 });
    
    const tarpitSwitchInput = page.locator('input#tarpit-enabled-switch');
    if (!(await tarpitSwitchInput.isChecked())) {
        await tarpitSwitchLabel.click();
    }
    await page.waitForTimeout(2000);
    
    const saveBtn = page.getByRole('button', { name: 'Save Global Configuration' });
    await saveBtn.scrollIntoViewIfNeeded();
    await saveBtn.click();
    await expect(page.getByText(/Saved/i)).toBeVisible();

    // Verify it doesn't break normal traffic
    const normalResp = await request.get('http://localhost:8081/test');
    expect(normalResp.status()).toBe(200);

    // Cleanup: Disable Tarpit
    await tarpitSwitchLabel.click();
    await saveBtn.click();
    await expect(page.getByText(/Saved/i)).toBeVisible();
  });
});
