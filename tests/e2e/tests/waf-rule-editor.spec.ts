// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test, expect, type APIRequestContext, type Page } from '@playwright/test';
import { attackerContext } from './attack-traffic';

/**
 * The WAF rule editor in the Security Hub: a typed rule definition written in
 * the form, checked where it matters -- on the proxy. A rule that names a
 * marker must refuse requests carrying it, stop when disabled, and be deleted
 * only after a confirmation that names it.
 */

const PROXY = 'http://localhost:8081';
const stamp = Date.now();
const NAME = `E2E rule ${stamp}`;
const MARKER = `e2e-waf-marker-${stamp}`;

type Playwright = { request: { newContext: (o: object) => Promise<APIRequestContext> } };

async function openRules(page: Page) {
  await page.goto('/security-center');
  await page.getByRole('tab', { name: /WAF Rules/i }).click();
  await expect(page.getByRole('heading', { name: 'WAF Security Rules' })).toBeVisible();
}

function ruleSave(page: Page, method: 'POST' | 'PUT') {
  return page.waitForResponse((r) => new URL(r.url()).pathname === '/v1/waf/rules' && r.request().method() === method);
}

test.describe('WAF rule editor', () => {
  test.setTimeout(120_000);
  let ruleId = '';

  test.afterAll(async ({ playwright }) => {
    if (!ruleId) return;
    const api = await (playwright as Playwright).request.newContext({
      baseURL: 'http://localhost:8080',
      storageState: 'tests/.auth/admin.json',
    });
    try {
      await api.delete(`/v1/waf/rules/${encodeURIComponent(ruleId)}`);
    } finally {
      await api.dispose();
    }
  });

  test('a rule written in the editor blocks what it names, stops when disabled, and is deleted by name', async ({
    page,
    playwright,
  }) => {
    // Blocks count toward mitigating the sender's fingerprint; see
    // attack-traffic.ts. This spec earns at most one.
    const attacker = await attackerContext(playwright, 'waf-rule-editor');
    const probe = async () =>
      (await attacker.get(`${PROXY}/test/waf-editor?probe=${MARKER}`, { headers: { 'X-Forwarded-For': '203.0.113.51' } })).status();
    try {
      expect(await probe(), 'the marker is refused before any rule names it').toBe(200);

      await openRules(page);
      await page.getByRole('button', { name: 'Add Rule' }).click();
      const dialog = page.getByRole('dialog', { name: 'Add New WAF Rule' });
      await dialog.getByLabel('Rule Name').fill(NAME);
      await dialog.getByLabel('Value').fill(MARKER);
      await dialog.getByLabel('Message').fill(`Blocked by the e2e rule ${stamp}`);
      const created = ruleSave(page, 'POST');
      await dialog.getByRole('button', { name: 'Save Rule' }).click();
      const createdRes = await created;
      expect(createdRes.status(), `POST /v1/waf/rules: ${await createdRes.text()}`).toBe(201);
      ruleId = ((await createdRes.json()) as { rule: { id: string } }).rule.id;
      await expect(page.getByRole('alert').filter({ hasText: 'WAF Rule created successfully' })).toBeVisible();
      await expect(dialog).toBeHidden();

      await page.getByPlaceholder('Search rules...').fill(NAME);
      // By id: the empty-state row repeats the search text.
      const row = page.getByRole('row').filter({ hasText: `ID: ${ruleId}` });
      await expect(row).toContainText(NAME);
      await expect(row).toContainText('Enabled');
      await expect.poll(probe, { message: 'the saved rule does not refuse its marker', timeout: 15_000 }).toBe(403);

      // Disabled, it lets the marker through again.
      await page.getByRole('button', { name: `Edit WAF rule ${NAME}` }).click();
      const edit = page.getByRole('dialog', { name: 'Edit WAF Rule' });
      await expect(edit.getByLabel('Rule Name')).toHaveValue(NAME);
      await edit.getByRole('switch', { name: 'Rule Enabled' }).uncheck();
      const updated = ruleSave(page, 'PUT');
      await edit.getByRole('button', { name: 'Save Rule' }).click();
      expect((await updated).status()).toBe(200);
      await expect(page.getByRole('alert').filter({ hasText: 'WAF Rule updated successfully' })).toBeVisible();
      await expect(row).toContainText('Disabled');
      await expect.poll(probe, { message: 'a disabled rule still refuses its marker', timeout: 15_000 }).toBe(200);

      // Delete asks first, naming the rule; dismissing deletes nothing.
      const deletes: string[] = [];
      page.on('request', (r) => {
        if (r.method() === 'DELETE' && new URL(r.url()).pathname.startsWith('/v1/waf/rules/')) deletes.push(r.url());
      });
      let asked = '';
      page.once('dialog', (d) => {
        asked = d.message();
        void d.dismiss();
      });
      await page.getByRole('button', { name: `Delete WAF rule ${NAME}` }).click();
      await expect.poll(() => asked).toContain(`"${NAME}" (${ruleId})`);
      expect(deletes, 'dismissing the question deleted the rule').toEqual([]);

      page.once('dialog', (d) => void d.accept());
      const deleted = page.waitForResponse(
        (r) => r.request().method() === 'DELETE' && new URL(r.url()).pathname === `/v1/waf/rules/${ruleId}`,
      );
      await page.getByRole('button', { name: `Delete WAF rule ${NAME}` }).click();
      expect((await deleted).status()).toBe(200);
      await expect(page.getByRole('alert').filter({ hasText: 'WAF Rule deleted successfully' })).toBeVisible();
      await expect(row).toHaveCount(0);
      await expect(page.getByText(`No rules matching "${NAME}"`)).toBeVisible();
      ruleId = '';
    } finally {
      await attacker.dispose();
    }
  });

  test('a rule the gateway refuses is reported as refused, and the editor stays open', async ({ page }) => {
    const refusedName = `${NAME} refused`;
    await openRules(page);
    await page.getByRole('button', { name: 'Add Rule' }).click();
    const dialog = page.getByRole('dialog', { name: 'Add New WAF Rule' });
    await dialog.getByLabel('Rule Name').fill(refusedName);
    await dialog.getByLabel('Match using').and(page.locator('input')).click();
    await page.getByRole('option', { name: 'regex — RE2 pattern (@rx)' }).click();
    // Lookaround: RE2 cannot compile it, and the gateway says so.
    await dialog.getByLabel('Pattern (RE2)').fill('(?=never)');
    await dialog.getByLabel('Message').fill('never stored');
    const created = ruleSave(page, 'POST');
    await dialog.getByRole('button', { name: 'Save Rule' }).click();
    const res = await created;
    expect(res.status(), 'the gateway accepted a pattern RE2 cannot compile').toBeGreaterThanOrEqual(400);

    // One report, carrying the gateway's reason -- and, once it is up, no
    // success message beside it.
    const refused = page.getByRole('alert').filter({ hasText: /regexp|RE2|pattern|operator/i });
    await expect(refused, 'the refusal was not reported').toHaveCount(1);
    await expect(refused).toContainText('Error');
    await expect(
      page.getByRole('alert').filter({ hasText: 'WAF Rule created successfully' }),
      'a refused rule was announced as created',
    ).toHaveCount(0);
    await expect(dialog, 'the editor closed on a refused rule').toBeVisible();
    await expect(dialog.getByLabel('Rule Name')).toHaveValue(refusedName);
  });
});
