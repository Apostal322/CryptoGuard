import { defineConfig, devices } from "@playwright/test";

// Browser end-to-end tests: the real backend (tests/e2e/server.py: uvicorn + the CryptoGuard
// API + a deterministic fake Ethereum node) behind the real production frontend build
// (vite preview, which proxies /api like the dev server). Three isolated profiles, each
// with its own temporary database. Nothing touches a real network or the developer's data.
//
// Run: npm run e2e   (builds first). Debug headed: npx playwright test --headed

const env = (globalThis as { process?: { env: Record<string, string | undefined>; platform?: string } }).process;
const python =
  env?.env.CRYPTOGUARD_E2E_PYTHON ??
  (env?.platform === "win32" ? "..\\..\\.venv\\Scripts\\python.exe" : "../../.venv/bin/python");

export const PROFILES = {
  default: { api: 8765, ui: 4173 },
  shadow: { api: 8766, ui: 4174 },
  degraded: { api: 8767, ui: 4175 },
} as const;

const backends = Object.entries(PROFILES).map(([profile, ports]) => ({
  command: `${python} ../../tests/e2e/server.py --port ${ports.api} --profile ${profile}`,
  // Ready = the API answers *and* has verified its chain through the RPC provider. /health
  // alone left the first test to absorb the cold start (a 15 s timeout on a loaded machine).
  url: `http://127.0.0.1:${ports.api}/api/v1/status`,
  reuseExistingServer: false,
  timeout: 180_000,
  stdout: "pipe" as const,
  stderr: "pipe" as const,
}));
const frontends = Object.values(PROFILES).map((ports) => ({
  command: `npx vite preview --port ${ports.ui} --strictPort`,
  url: `http://127.0.0.1:${ports.ui}`,
  env: { CRYPTOGUARD_API_URL: `http://127.0.0.1:${ports.api}` },
  reuseExistingServer: false,
  timeout: 60_000,
}));

export default defineConfig({
  testDir: "./e2e",
  outputDir: "./e2e-results",
  fullyParallel: false,
  workers: 1, // one browser at a time: the suite must stay usable on an 8 GB machine
  retries: 0,
  timeout: 60_000,
  expect: { timeout: 15_000 },
  reporter: [["list"], ["html", { open: "never", outputFolder: "./e2e-report" }]],
  use: {
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    actionTimeout: 15_000,
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: [...backends, ...frontends],
});
