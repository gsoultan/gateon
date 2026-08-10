// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { defineConfig, devices } from '@playwright/test';
import fs from 'fs';
import os from 'os';
import path from 'path';

// Run the gateway against a throwaway copy of config/, never the tracked files.
//
// gateon persists configuration back to whatever GLOBAL_CONFIG_FILE points at,
// so pointing it straight at tests/e2e/config/ meant every run rewrote checked-in
// files. A finished run had silently dropped waf.enabled, deception.enabled and
// tarpit.enabled (protojson omits false), flipped clamav.installation_mode to
// whatever the last test installed, and — worst — replaced the deliberate
// pow.secret placeholder "changeme" with a freshly generated value. That is a
// generated secret sitting in `git status`, one `git add` away from the history,
// and it is how a config change nobody made gets committed by accident. CI also
// fails a dirty working tree, so this could only ever be caught late.
//
// Copying makes the run reproducible as well: the suite always starts from the
// committed baseline instead of from whatever the previous run left behind.
const configDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gateon-e2e-config-'));
for (const f of fs.readdirSync('config')) {
  fs.copyFileSync(path.join('config', f), path.join(configDir, f));
}
// Paths reach gateon as env vars and its working directory is the repo root, so
// they have to be absolute.
const cfg = (name: string) => path.join(configDir, name);

export default defineConfig({
  testDir: './tests',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: 1,
  // Stop the whole run rather than let it grind on. With one worker, two
  // retries and per-test timeouts up to 180s, a bad run is bounded only by
  // 104 x 3 x 180s, and a broken gateway makes almost every test take its full
  // timeout — the failure mode this suite hits most often. 30 minutes is well
  // clear of a healthy run and still leaves room, inside the job's 45-minute
  // ceiling, for Playwright to write its report instead of being killed.
  globalTimeout: 30 * 60 * 1000,
  reporter: 'html',
  use: {
    baseURL: 'http://localhost:8080',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
  },
  // One browser project, not four.
  //
  // There were previously separate admin, operator, viewer and chromium
  // projects, none with a testMatch, so every spec ran once per project: 26
  // tests became 104. `chromium` was a byte-for-byte duplicate of `admin`, and
  // the role projects did not buy the role coverage they looked like they did —
  // rbac_admin, rbac_operator and rbac_viewer each declare their own identity
  // with test.use({ storageState }), so they ignored the project's identity and
  // ran three times as the same user.
  //
  // What the extra projects did produce was noise and cost. The seven
  // functional specs save global configuration, which needs admin, so their
  // operator and viewer runs failed by construction — that is why "Global WAF
  // Management" showed up red only under [operator]. And at one worker with two
  // retries, four times the tests could not finish inside globalTimeout: the
  // last run gave up with 74 tests never started, so most of the suite reported
  // nothing at all.
  //
  // Specs that need a specific role say so themselves. That is the mechanism;
  // duplicating it at the project level is what broke it.
  projects: [
    { name: 'setup', testMatch: /.*\.setup\.ts/ },
    {
      name: 'e2e',
      use: {
        ...devices['Desktop Chrome'],
        // The default identity for specs that do not pin one. The rbac specs
        // override this per file.
        storageState: 'tests/.auth/admin.json',
      },
      dependencies: ['setup'],
    },
  ],
  webServer: [
    {
      command: 'rm -rf ../../telemetry_pebble/ && rm -f ../../gateon_test.db* && cd ../.. && GATEON_TEST=1 go run tests/e2e/create_user/main.go && GATEON_TEST=1 ./gateon',
      port: 8080,
      reuseExistingServer: !process.env.CI,
      stdout: 'pipe',
      stderr: 'pipe',
      timeout: 300000,
      env: {
        PATH: `${process.cwd()}/mockbin:${process.env.PATH}`,
        GLOBAL_CONFIG_FILE: cfg('global.json'),
        ROUTES_FILE: cfg('routes.json'),
        SERVICES_FILE: cfg('services.json'),
        ENTRYPOINTS_FILE: cfg('entrypoints.json'),
        MIDDLEWARES_FILE: cfg('middlewares.json'),
        TLS_OPTIONS_FILE: cfg('tls_options.json'),
        GATEON_TRUSTED_PROXIES: '127.0.0.1,::1',
        GATEON_TEST: '1',
        GATEON_TRACE_SAMPLE_RATE: '1',
        GATEON_PROFILE: 'enterprise',
      },
    },
    {
      command: 'go run mock_backend/main.go',
      port: 8082,
      reuseExistingServer: !process.env.CI,
      stdout: 'pipe',
      stderr: 'pipe',
      timeout: 120000,
    },
    {
      command: 'go run grpc_backend/main.go',
      port: 8083,
      reuseExistingServer: !process.env.CI,
      stdout: 'pipe',
      stderr: 'pipe',
      timeout: 120000,
    },
    {
      command: 'go run tcp_backend/main.go',
      port: 8084,
      reuseExistingServer: !process.env.CI,
      stdout: 'pipe',
      stderr: 'pipe',
      timeout: 120000,
    }
  ],
});
