import { test as setup, expect } from '@playwright/test';
import { execSync } from 'child_process';

const operatorFile = 'tests/.auth/operator.json';

setup('authenticate operator', async ({ page }) => {
  setup.setTimeout(120000);
  // Wait for gateon to be ready
  execSync('go run wait_for_port/main.go localhost:8080');
  
  await page.goto('/login');
  await page.getByPlaceholder('Enter your username').fill('operator');
  await page.getByPlaceholder('••••••••').fill('password123');
  await page.getByRole('button', { name: /Continue to Dashboard/i }).click();

  // Wait for dashboard to load
  await expect(page.getByRole('heading', { name: /System Overview/i })).toBeVisible({ timeout: 60000 });

  // Ensure localStorage is persisted
  await page.waitForFunction(() => {
    const auth = localStorage.getItem('gateon-auth');
    if (!auth) return false;
    const { state } = JSON.parse(auth);
    return state && state.token !== null && state.user !== null;
  }, { timeout: 10000 });

  await page.context().storageState({ path: operatorFile });
});
