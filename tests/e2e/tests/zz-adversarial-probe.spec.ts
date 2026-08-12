// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { test, expect, APIRequestContext } from '@playwright/test';

/**
 * Adversarial probe: the gateway under attack by someone who has read its docs.
 *
 * Everything else in this suite drives the happy path and checks the dashboard
 * reflects it. This file does the opposite — it assumes the operator's own WAF
 * is the thing on trial, and tries the moves an attacker reaches for once the
 * obvious payload comes back 403: re-encode it, claim a different source, ask
 * the data plane for the control plane, walk out of the path prefix.
 *
 * The bar for each test is "the gateway did not become a worse gateway",
 * expressed as narrowly as possible so a pass means something. Where a defence
 * is deliberately absent, the test says so in a comment rather than asserting
 * a weaker thing and looking green.
 *
 * The filename sorts last on purpose. These probes earn WAF blocks, and a WAF
 * block marks the caller's JA4+ mitigated for the rest of the run — every
 * request.get() in the suite shares one fingerprint, so running this early
 * would 403 unrelated specs. The teardown below hands the mitigation back, and
 * the ordering is belt and braces.
 */

const PROXY = 'http://localhost:8081';

// TEST-NET-3 (RFC 5737): reserved for documentation, cannot collide with a real
// client. The harness sets GATEON_TRUSTED_PROXIES=127.0.0.1,::1, so
// X-Forwarded-For from the runner is honoured — which is itself one of the
// things under test here.
const ATTACKER = '203.0.113.90';
const as = (ip: string) => ({ headers: { 'X-Forwarded-For': ip } });

async function releaseMitigations(api: APIRequestContext) {
  const res = await api.get('/v1/diag/security-threats?limit=200&status=all');
  if (!res.ok()) return;
  const prints = new Set<string>();
  for (const t of (await res.json()).threats ?? []) {
    const fp = t.ja4plus || (t.ja4 && t.ja4h ? `${t.ja4}_${t.ja4h}` : '');
    if (fp) prints.add(fp);
  }
  for (const fp of prints) {
    await api.post('/v1/diagnostics/remove-mitigation', { data: { source: fp } });
  }
}

test.describe('Adversarial probe', () => {
  test.setTimeout(120000);

  test.afterAll(async ({ playwright }) => {
    const api = await playwright.request.newContext({
      baseURL: 'http://localhost:8080',
      storageState: 'tests/.auth/admin.json',
    });
    try {
      await releaseMitigations(api);
    } finally {
      await api.dispose();
    }
  });

  // Every probe below asserts some form of "not 200". That is trivially true of
  // a client the gateway has already mitigated, and one WAF block is enough to
  // mitigate this one — the whole suite shares a single JA4+. Without this
  // hook, the first test to trip the WAF would make every later test pass by
  // being blocked wholesale, which is the most expensive kind of green.
  //
  // So each test starts from a released fingerprint and proves it: a benign
  // request must come back 200 before any assertion about a hostile one means
  // anything.
  test.beforeEach(async ({ playwright, request }) => {
    const api = await playwright.request.newContext({
      baseURL: 'http://localhost:8080',
      storageState: 'tests/.auth/admin.json',
    });
    try {
      await releaseMitigations(api);
    } finally {
      await api.dispose();
    }

    const control = await request.get(`${PROXY}/test`, as('203.0.113.99'));
    expect(
      control.status(),
      'control request was not allowed, so this client is blanket-blocked and ' +
      'every "not 200" assertion below would pass without testing anything',
    ).toBe(200);
  });

  // The control plane must not be reachable through the data plane. The
  // management API listens on 8080 and is authenticated; 8081 is the proxy, and
  // nothing there should route to it. A gateway that proxies its own admin API
  // hands over configuration to anyone who can reach a published port.
  test('the proxy entrypoint does not serve the management API', async ({ request }) => {
    const managementPaths = [
      '/v1/routes',
      '/v1/global',
      '/v1/users',
      '/v1/config/export',
      '/v1/security/clamav/scan-status',
    ];

    for (const path of managementPaths) {
      const res = await request.get(`${PROXY}${path}`, as(ATTACKER));
      expect(
        res.status(),
        `${path} answered ${res.status()} on the proxy port; the management API must not be routable from the data plane`,
      ).not.toBe(200);
    }
  });

  // Traversal and normalisation. The proxy routes by path prefix, so anything
  // that lets a path escape its prefix after the routing decision is a way into
  // a route the client was not matched to.
  test('path traversal and separator tricks do not escape the route prefix', async ({ request }) => {
    const traversals = [
      '/test/../v1/global',
      '/test/..%2fv1%2fglobal',
      '/test/..%252fv1%252fglobal',
      '/test/..;/v1/global',
      '/test/%2e%2e/%2e%2e/v1/global',
      '/test/./../../v1/routes',
    ];

    for (const path of traversals) {
      const res = await request.get(`${PROXY}${path}`, as(ATTACKER));
      const body = await res.text().catch(() => '');
      expect(
        res.status() === 200 && /"routes"|"entryPoints"|"waf"/.test(body),
        `${path} returned management configuration through the proxy`,
      ).toBe(false);
    }
  });

  // Two further probes are deliberately absent, not forgotten.
  //
  // "rotating the claimed source IP does not shed an earned mitigation" and
  // "a forged Host header does not select a different route" both need the
  // client to start un-mitigated, and releasing a JA4+ between tests is not
  // reliable yet: remove-mitigation returns 200, but the control request that
  // follows it still comes back 403, so something re-applies or outlives the
  // release. Written naively they passed — and passed for the worst possible
  // reason, because a blanket-403 client satisfies every "not 200" assertion
  // in this file. They are worth having once a fingerprint can be reset on
  // demand; they are worth nothing until then.

  // Oversized header sets are a cheap memory-exhaustion probe. The gateway
  // should refuse rather than buffer whatever arrives.
  test('an oversized header set is refused rather than absorbed', async ({ request }) => {
    const headers: Record<string, string> = { 'X-Forwarded-For': ATTACKER };
    for (let i = 0; i < 200; i++) headers[`X-Probe-${i}`] = 'A'.repeat(1024);

    let status = 0;
    try {
      status = (await request.get(`${PROXY}/test`, { headers })).status();
    } catch {
      // A refused or reset connection is a valid way to say no.
      status = 431;
    }
    expect(status, 'the gateway accepted ~200KB of request headers').not.toBe(200);
  });
  // The WAF-evasion probe is written and deliberately not landed here.
  //
  // It fires re-encoded SQLi and XSS (mixed case, inline comment, double
  // url-encoding, fullwidth unicode, null byte, svg vector) and asserts none
  // reach the backend with a 200. The trouble is that it needs a client the
  // gateway has not already mitigated, and by the time it runs the traversal
  // probe above has tripped the WAF — one block is enough, and the fingerprint
  // is shared by every request.get() in the suite. remove-mitigation answers
  // 200 but the control request after it still comes back 403, so the release
  // does not hold.
  //
  // Landed as-is it went green, and green meant nothing: a blanket-403 client
  // satisfies every "not 200" assertion in this file. That is the failure mode
  // the beforeEach above exists to catch, and it caught this. The probe belongs
  // here the moment a fingerprint can be reset on demand.
});
