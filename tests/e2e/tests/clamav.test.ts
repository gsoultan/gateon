import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';
import fs from 'fs';

test.describe('ClamAV Security E2E', () => {
  test.setTimeout(180000);

  test.beforeAll(async () => {
    // Cleanup mock state
    if (fs.existsSync('/tmp/clamav_apt_installed')) fs.unlinkSync('/tmp/clamav_apt_installed');
    if (fs.existsSync('/tmp/clamav_docker_running')) fs.unlinkSync('/tmp/clamav_docker_running');
    if (fs.existsSync('/tmp/mock.log')) fs.unlinkSync('/tmp/mock.log');
  });

  test.beforeEach(async ({ page }) => {
    await page.goto('/security-center', { waitUntil: 'networkidle' });
    await expect(page.getByText(/Security Hub/i).first()).toBeVisible({ timeout: 20000 });
  });

  test('ClamAV Installation and Uninstallation', async ({ page }) => {
    // 1. Initial cleanup if needed
    const uninstallBtn = page.getByRole('button', { name: 'Uninstall ClamAV' });
    if (await uninstallBtn.isVisible()) {
        await uninstallBtn.click();
        const sudoDialog = page.getByRole('heading', { name: 'Administrative Privileges Required' });
        if (await sudoDialog.isVisible({ timeout: 5000 })) {
            await page.getByPlaceholder('Your password').fill('password123');
            await page.getByRole('button', { name: 'Confirm', exact: true }).click();
        }
        await expect(page.getByRole('button', { name: 'Install Now' })).toBeVisible({ timeout: 60000 });
    }

    // 2. Install
    await page.getByRole('button', { name: 'Install Now' }).click();
    await page.getByRole('menuitem', { name: 'Local' }).click();
    
    // Handle sudo dialog
    const sudoDialog = page.getByRole('heading', { name: 'Administrative Privileges Required' });
    await expect(sudoDialog).toBeVisible({ timeout: 10000 });
    await page.getByPlaceholder('Your password').fill('password123');
    // Use dialog context to avoid strict mode violation with "Install Now" button
    await page.getByRole('dialog').getByRole('button', { name: /Confirm|Install/i, exact: true }).click();
    
    // Wait for Uninstall button to appear (meaning installed)
    await expect(page.getByRole('button', { name: 'Uninstall ClamAV' })).toBeVisible({ timeout: 60000 });
    expect(fs.existsSync('/tmp/clamav_apt_installed')).toBe(true);

    // 3. Uninstall
    await page.getByRole('button', { name: 'Uninstall ClamAV' }).click();
    
    // Sudo dialog should appear for uninstallation now
    const sudoDialogUninstall = page.getByRole('heading', { name: 'Administrative Privileges Required' });
    await expect(sudoDialogUninstall).toBeVisible({ timeout: 10000 });
    await page.getByPlaceholder('Your password').fill('password123');
    await page.getByRole('dialog').getByRole('button', { name: /Confirm|Uninstall/i, exact: true }).click();

    // Wait for Install Now button to reappear
    await expect(page.getByRole('button', { name: 'Install Now' })).toBeVisible({ timeout: 60000 });
    expect(fs.existsSync('/tmp/clamav_apt_installed')).toBe(false);
  });

  test('ClamAV Scanning', async ({ page }) => {
    // Ensure installed
    if (!await page.getByRole('button', { name: 'Uninstall ClamAV' }).isVisible()) {
        const installNow = page.getByRole('button', { name: 'Install Now' });
        if (await installNow.isVisible()) {
            await installNow.click();
            await page.getByRole('menuitem', { name: 'Local' }).click();
            const sudoDialog = page.getByRole('heading', { name: 'Administrative Privileges Required' });
            if (await sudoDialog.isVisible({ timeout: 5000 })) {
                await page.getByPlaceholder('Your password').fill('password123');
                await page.getByRole('dialog').getByRole('button', { name: /Confirm|Install/i, exact: true }).click();
            }
            await expect(page.getByRole('button', { name: 'Uninstall ClamAV' })).toBeVisible({ timeout: 60000 });
        }
    }

    // 1. Run a clean scan
    const scanButton = page.getByRole('button', { name: 'Deep Scan' });
    await expect(scanButton).toBeEnabled({ timeout: 30000 });
    await scanButton.click();
    
    // Wait for the scan to finish
    await expect(scanButton).toBeEnabled({ timeout: 60000 });
    await expect(page.locator('p:has-text("Last scan:")')).toBeVisible();
  });
});
