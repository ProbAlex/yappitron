import { defineConfig } from '@playwright/test';

// The gateway (serving the built web app) must already be running; `just e2e` starts one.
export default defineConfig({
  testDir: './tests',
  timeout: 90_000,
  expect: { timeout: 15_000 },
  workers: 1,
  reporter: [['list']],
  use: {
    baseURL: process.env.E2E_URL ?? 'http://127.0.0.1:18090',
    // Flutter draws to a canvas; the accessibility tree is what we drive.
    viewport: { width: 1000, height: 800 },
  },
});
