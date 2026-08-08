import { defineConfig, devices } from '@playwright/test';

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
  projects: [
    { name: 'setup', testMatch: /.*\.setup\.ts/ },
    {
      name: 'admin',
      use: { 
        ...devices['Desktop Chrome'],
        storageState: 'tests/.auth/admin.json',
      },
      dependencies: ['setup'],
    },
    {
      name: 'operator',
      use: { 
        ...devices['Desktop Chrome'],
        storageState: 'tests/.auth/operator.json',
      },
      dependencies: ['setup'],
    },
    {
      name: 'viewer',
      use: { 
        ...devices['Desktop Chrome'],
        storageState: 'tests/.auth/viewer.json',
      },
      dependencies: ['setup'],
    },
    {
      name: 'chromium',
      use: { 
        ...devices['Desktop Chrome'],
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
        GLOBAL_CONFIG_FILE: 'tests/e2e/config/global.json',
        ROUTES_FILE: 'tests/e2e/config/routes.json',
        SERVICES_FILE: 'tests/e2e/config/services.json',
        ENTRYPOINTS_FILE: 'tests/e2e/config/entrypoints.json',
        MIDDLEWARES_FILE: 'tests/e2e/config/middlewares.json',
        TLS_OPTIONS_FILE: 'tests/e2e/config/tls_options.json',
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
