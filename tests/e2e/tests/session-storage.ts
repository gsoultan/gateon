// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { expect, type Page } from '@playwright/test';

/**
 * Wait for a login to settle, then prove the session is held the way the
 * dashboard promises: in the HttpOnly `gateon_session` cookie and nowhere a
 * script on the page can read it (CLAUDE.md invariant 2, useAuthStore).
 *
 * The setups used to wait for `state.token !== null` in the persisted store.
 * The store never persists the token -- it keeps only the user -- so that read
 * `undefined`, which is not `null`, and the check passed without looking at
 * anything. It would have passed just the same with the real token written to
 * localStorage, which is the regression it appeared to guard.
 */
export async function expectSessionOnlyInCookie(page: Page): Promise<void> {
  // The persisted user is what the shell paints from after a reload.
  await page.waitForFunction(() => {
    const auth = localStorage.getItem('gateon-auth');
    return auth !== null && JSON.parse(auth)?.state?.user != null;
  }, undefined, { timeout: 10000 });

  const session = (await page.context().cookies()).find((c) => c.name === 'gateon_session');
  expect(session, 'login set no gateon_session cookie').toBeDefined();
  expect(session!.httpOnly, 'gateon_session is readable by script').toBe(true);

  const webStorage = await page.evaluate(() => {
    const entries: string[] = [];
    for (const store of [localStorage, sessionStorage]) {
      for (let i = 0; i < store.length; i++) {
        const key = store.key(i) ?? '';
        entries.push(key, store.getItem(key) ?? '');
      }
    }
    return entries.join('\n');
  });
  expect(webStorage.includes(session!.value), 'the session token is readable from web storage').toBe(false);
}
