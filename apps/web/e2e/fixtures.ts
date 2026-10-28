import { expect, test as base, type Page } from "@playwright/test";

import { PROFILES } from "../playwright.config";

export type Profile = keyof typeof PROFILES;

export interface Scenarios {
  profile: Profile;
  approvals: string;
  poison: string;
  lookalike: string;
  real_payee: string;
  attacker_signer: string;
  campaign: string[];
  campaign_signer: string;
  quiet: string;
  never: string;
  evil_symbol: string;
  uniswap_router: string;
  eoa_spender: string;
  token_usd: string;
  token_evil: string;
  token_broken: string;
  secret_fragment: string;
}

export const uiUrl = (profile: Profile, path = "/") => `http://127.0.0.1:${PROFILES[profile].ui}${path}`;
export const apiUrl = (profile: Profile, path: string) => `http://127.0.0.1:${PROFILES[profile].api}${path}`;

/** Fails the test on any uncaught page error or console error (minus expected API errors). */
export function watchConsole(page: Page, allow: RegExp[] = []) {
  const problems: string[] = [];
  page.on("pageerror", (error) => problems.push(`pageerror: ${error.message}`));
  page.on("console", (message) => {
    if (message.type() !== "error") return;
    const text = message.text();
    // The browser logs failed fetches (4xx/5xx) on its own; those are asserted explicitly.
    if (/Failed to load resource/.test(text) || allow.some((r) => r.test(text))) return;
    problems.push(`console: ${text}`);
  });
  return problems;
}

export const test = base.extend<{ scenarios: (profile: Profile) => Promise<Scenarios> }>({
  scenarios: async ({ request }, use) => {
    await use(async (profile) => {
      const response = await request.get(apiUrl(profile, "/__e2e__/scenarios"));
      expect(response.ok()).toBeTruthy();
      return (await response.json()) as Scenarios;
    });
  },
});

export { expect };

export async function openWallet(page: Page, profile: Profile, address: string, tab?: string) {
  await page.goto(uiUrl(profile, `/wallet/${address}${tab ? `?tab=${tab}` : ""}`));
  await expect(page.getByRole("tablist", { name: "Wallet views" })).toBeVisible();
}
