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
    // Optional, for testing a deployment from the same LAN before public DNS/TLS is ready:
    //   E2E_HOST_MAP="yap.example.com=192.168.1.41"  maps the name to that address in the browser
    //   only (no system files touched), and treats the plain-HTTP origin as secure (the web app's
    //   key storage needs a secure context, which real HTTPS provides).
    // The new headless mode (`channel: 'chromium'`) is needed for the secure-origin flag.
    channel: process.env.E2E_HOST_MAP ? 'chromium' : undefined,
    launchOptions: {
      args: process.env.E2E_HOST_MAP
        ? (() => {
            const [host, ip] = process.env.E2E_HOST_MAP!.split('=');
            return [`--host-resolver-rules=MAP ${host} ${ip}`, `--unsafely-treat-insecure-origin-as-secure=http://${host}`];
          })()
        : [],
    },
  },
});
