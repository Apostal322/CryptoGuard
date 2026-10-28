// Real user journeys: browser -> production UI build -> real API over HTTP -> fake chain.
import { apiUrl, expect, openWallet, test, uiUrl, watchConsole } from "./fixtures";

test.describe("journeys (default profile: experimental features off)", () => {
  test("1. startup: dashboard loads and reaches the backend", async ({ page, scenarios }) => {
    const s = await scenarios("default");
    const problems = watchConsole(page);
    const status = page.waitForResponse((r) => r.url().endsWith("/api/v1/status"));
    await page.goto(uiUrl("default"));
    expect((await status).status()).toBe(200);
    await expect(page.getByRole("heading", { name: "Wallet security, with the evidence" })).toBeVisible();
    await expect(page.getByText("Verified via eth_chainId")).toBeVisible();
    await expect(page.getByText("1,300", { exact: true })).toBeVisible(); // head block of the fixture chain
    await expect(page.locator("body")).not.toContainText(s.secret_fragment); // provider URL is redacted
    expect(problems).toEqual([]);
  });

  test("2. wallet search: validation, then a real inspection", async ({ page, scenarios }) => {
    const s = await scenarios("default");
    const problems = watchConsole(page);
    await page.goto(uiUrl("default"));
    const input = page.getByLabel("Public Ethereum address");
    await input.fill("0x1234");
    await page.getByRole("button", { name: "Analyze address" }).click();
    await expect(page.getByText("Enter a full 0x-prefixed address of 40 hexadecimal characters.")).toBeVisible();
    await expect(input).toHaveAttribute("aria-invalid", "true");

    await input.fill(s.quiet);
    const analyze = page.waitForRequest((r) => r.url().endsWith("/api/v1/analyze/address") && r.method() === "POST");
    await page.getByRole("button", { name: "Analyze address" }).click();
    const request = await analyze;
    expect(request.headers()["content-type"]).toContain("application/json");
    await expect(page).toHaveURL(new RegExp(`/wallet/${s.quiet}$`));
    await expect(page.getByText("Ethereum Mainnet (id 1, verified via eth_chainId)")).toBeVisible();
    await expect(page.getByText(/Single snapshot at block 1300/)).toBeVisible(); // coverage is stated
    await expect(page.getByText("Real data").first()).toBeVisible();
    expect(problems).toEqual([]);
  });

  test("3. approval inspection: labels, unlimited allowance, unknowns, hostile metadata", async ({ page, scenarios }) => {
    const s = await scenarios("default");
    const problems = watchConsole(page);
    await openWallet(page, "default", s.approvals, "approvals");
    await page.getByLabel("Lookback (blocks)").fill("1000");
    await page.getByRole("button", { name: "Scan approvals" }).click();
    await expect(page.getByRole("heading", { name: /Token permissions \(\d+ active\)/ })).toBeVisible();
    const panel = page.getByRole("tabpanel");
    await expect(panel.getByText("Uniswap V2: Router 02").first()).toBeVisible();
    await expect(panel.getByText(s.uniswap_router).first()).toBeVisible();
    await expect(panel.getByText(s.eoa_spender).first()).toBeVisible();
    await expect(panel.getByText(/unlimited/i).first()).toBeVisible();
    await expect(panel.getByText(/unknown|could not be read|unverifiable/i).first()).toBeVisible();
    // An unlimited allowance is exposure, not evidence of compromise.
    await expect(panel).not.toContainText(/compromised|stolen|hacked/i);
    // Hostile token metadata is inert text.
    await expect(panel.getByText(/img src=x onerror/).first()).toBeVisible();
    expect(await page.evaluate(() => (window as { __xss?: number }).__xss)).toBeUndefined();
    expect(await page.locator("img[src='x']").count()).toBe(0);
    // Evidence: the approval transaction links to the block explorer for chain 1 only.
    const txLink = panel.locator("a[href^='https://etherscan.io/tx/0x']").first();
    await expect(txLink).toHaveAttribute("rel", /noopener/);
    expect(problems).toEqual([]);
  });

  test("4. address poisoning: warning, escalation, superseded (not resolved), evidence", async ({ page, scenarios }) => {
    const s = await scenarios("default");
    const problems = watchConsole(page);
    await openWallet(page, "default", s.poison, "findings");
    const title = `Possible address poisoning: 0xabcD…eF12 imitates ${s.real_payee}`;
    await expect(page.getByText(title).first()).toBeVisible();
    await expect(page.getByText("Critical evidence").first()).toBeVisible();
    await page.getByRole("button", { name: "All", exact: true }).click();
    await expect(page.getByText("Superseded").first()).toBeVisible();
    await expect(page.getByText(/superseded at block 1,100/)).toBeVisible();
    await expect(page.getByText(/resolved at block|^Resolved$/)).toHaveCount(0);

    await page.getByText(title).first().click();
    await expect(page.getByText(s.lookalike).first()).toBeVisible();
    await expect(page.locator("a[href^='https://etherscan.io/tx/0x']").first()).toBeVisible();

    await page.getByRole("tab", { name: "Timeline" }).click();
    await expect(page.getByRole("heading", { name: "Security timeline (3 snapshots)" })).toBeVisible();
    await expect(page.getByText("new → superseded")).toBeVisible();
    await expect(page.getByText("No change in allowances, delegation or account code between these blocks. Findings changed:").first()).toBeVisible();
    expect(problems).toEqual([]);
  });

  test("6a. experimental sections are absent by default", async ({ page, request, scenarios }) => {
    const s = await scenarios("default");
    await openWallet(page, "default", s.poison, "graph");
    await expect(page.getByText(/Snapshot #\d+ at block/)).toBeVisible();
    await expect(page.getByText("Additional context")).toHaveCount(0);
    await page.getByRole("tab", { name: "Address poisoning" }).click();
    await expect(page.getByRole("button", { name: "Check for poisoning" })).toBeVisible();
    await expect(page.getByText("Related suspicious activity")).toHaveCount(0);
    const disabled = await request.get(apiUrl("default", `/api/v1/wallets/${s.poison}/related-activity`));
    expect(disabled.status()).toBe(409);
  });

  test("7. empty and never-observed wallets never get a safety verdict", async ({ page, scenarios }) => {
    const s = await scenarios("default");
    await openWallet(page, "default", s.never, "timeline");
    await expect(page.getByText(/No snapshot/i).first()).toBeVisible();
    await page.getByRole("tab", { name: "Threat graph" }).click();
    await expect(page.getByText(/No snapshot yet/)).toBeVisible();
    await page.getByRole("tab", { name: "Findings" }).click();
    await expect(page.getByRole("tabpanel")).not.toContainText(/\bsafe\b|no risk|all clear/i);

    await openWallet(page, "default", s.quiet, "findings");
    await expect(page.getByRole("tabpanel")).not.toContainText(/\bsafe\b|no risk|all clear/i);
    await page.getByRole("tab", { name: "Threat graph" }).click();
    await expect(page.getByText(/No relationships were observed/)).toBeVisible();
  });
});

test.describe("journeys (shadow profile)", () => {
  test("5. campaign context: shared signer, evidence, no ownership claim", async ({ page, request, scenarios }) => {
    const s = await scenarios("shadow");
    const problems = watchConsole(page);
    await openWallet(page, "shadow", s.campaign[0]!, "poisoning");
    const section = page.getByRole("region", { name: "Related suspicious activity" });
    await expect(section).toBeVisible();
    await expect(section.getByText("Experimental · shadow mode")).toBeVisible();
    await expect(section.getByText(/share planting infrastructure with attempts on 1 other wallet/)).toBeVisible();
    await expect(section.getByText("Strongly supported link")).toBeVisible();
    await section.getByRole("button", { name: "Show evidence" }).click();
    await expect(section.getByText("These attempts share a verified planting signer.")).toBeVisible();
    await expect(section.getByText(s.campaign_signer).first()).toBeVisible();
    await expect(section).not.toContainText(/same (hacker|attacker|person)|criminal|belong to|confirmed operator/i);

    // The unrelated wallet (other signer) is not linked.
    await openWallet(page, "shadow", s.campaign[2]!, "poisoning");
    await expect(page.getByText(/none shares planting infrastructure/)).toBeVisible();

    // Campaign analysis never creates findings: same findings as with everything off.
    for (const wallet of s.campaign) {
      const on = await (await request.get(apiUrl("shadow", `/api/v1/wallets/${wallet}/findings?status=all`))).json();
      const off = await (await request.get(apiUrl("default", `/api/v1/wallets/${wallet}/findings?status=all`))).json();
      const shape = (r: { items: { rule_id: string; status: string; severity: string }[] }) =>
        r.items.map((f) => `${f.rule_id}:${f.status}:${f.severity}`).sort();
      expect(shape(on)).toEqual(shape(off));
    }
    expect(problems).toEqual([]);
  });

  test("6b. experimental context appears in shadow mode", async ({ page, scenarios }) => {
    const s = await scenarios("shadow");
    await openWallet(page, "shadow", s.poison, "graph");
    const context = page.getByRole("region", { name: "Experimental context" });
    await expect(context).toBeVisible();
    await expect(context.getByText("Experimental · shadow mode")).toBeVisible();
    await expect(context).not.toContainText(/eigen|laplacian/i);
  });
});

test.describe("journeys (degraded profile)", () => {
  test("6c. missing optional numerical dependencies give a clear unavailable state", async ({ page, scenarios }) => {
    const s = await scenarios("degraded");
    await openWallet(page, "degraded", s.quiet, "graph");
    await expect(page.getByText("The server lacks the optional analytics dependencies.").first()).toBeVisible();
  });

  test("7b. provider without history: coverage gaps are stated, not hidden", async ({ page, scenarios }) => {
    const s = await scenarios("degraded");
    await openWallet(page, "degraded", s.quiet, "timeline");
    await page.getByText("Coverage").first().click();
    await expect(page.getByText(/historical state|could not be located|unknown/i).first()).toBeVisible();
  });

  test("8a. RPC outage: clear error, no demo substitution, app stays usable", async ({ page, request, scenarios }) => {
    const s = await scenarios("degraded");
    await request.post(apiUrl("degraded", "/__e2e__/rpc"), { data: { down: true } });
    try {
      await openWallet(page, "degraded", s.quiet);
      await expect(page.getByText("Request failed").first()).toBeVisible();
      const body = page.locator("body");
      await expect(body).not.toContainText(/Traceback|\.py"|E2E-PLACEHOLDER/);
      await expect(body).not.toContainText(/Demo \(simulated\)|SIMULATED DATA/);
      await page.getByRole("tab", { name: "Findings" }).click(); // stored data still navigable
      await expect(page.getByRole("heading", { name: "Findings" })).toBeVisible();
    } finally {
      await request.post(apiUrl("degraded", "/__e2e__/rpc"), { data: { down: false } });
    }
  });
});

test.describe("API error handling in the UI", () => {
  test("8b. a running snapshot gives a clear 409, then works", async ({ page, request, scenarios }) => {
    const s = await scenarios("default");
    await request.post(apiUrl("default", "/__e2e__/hold-snapshot-lease"), { data: { wallet: s.quiet } });
    try {
      await openWallet(page, "default", s.quiet, "timeline");
      await page.getByRole("button", { name: "Take snapshot" }).click();
      await expect(page.getByText(/already running/i)).toBeVisible();
    } finally {
      await request.post(apiUrl("default", "/__e2e__/hold-snapshot-lease"), { data: { wallet: s.quiet, release: true } });
    }
    await page.getByRole("button", { name: "Take snapshot" }).click();
    await expect(page.getByText(/Snapshot (recorded|already existed)/)).toBeVisible();
  });

  test("8c. invalid input: client-side check first, then the server's readable 422", async ({ page, scenarios }) => {
    const s = await scenarios("default");
    await openWallet(page, "default", s.quiet, "approvals");
    const token = page.getByLabel("Token contracts");
    let sent = 0;
    page.on("request", (r) => r.url().includes("/approvals/scan") && sent++);
    await token.fill("not-a-token");
    await page.getByRole("button", { name: "Scan approvals" }).click();
    await expect(page.getByText("Each token must be a full 0x-prefixed contract address.")).toBeVisible();
    expect(sent).toBe(0); // rejected before any request
    // Well-formed but with a wrong EIP-55 checksum: only the server can tell.
    await token.fill("0xDAC17F958D2ee523a2206206994597C13D831ec7");
    await page.getByRole("button", { name: "Scan approvals" }).click();
    await expect(page.getByText("Request failed").first()).toBeVisible();
    await expect(page.getByText(/checksum/i).first()).toBeVisible();
    await expect(page.locator("body")).not.toContainText(/Traceback|pydantic|\.py"/);
  });

  for (const [status, code] of [
    [429, "rate_limited"],
    [500, "internal_error"],
    [503, "rpc_unavailable"],
  ] as const) {
    test(`8d. injected HTTP ${status} on status is shown and recoverable`, async ({ page }) => {
      let fail = true;
      await page.route("**/api/v1/status", (route) =>
        fail
          ? route.fulfill({
              status,
              contentType: "application/json",
              body: JSON.stringify({ error: { code, message: `Injected ${status} for the test.`, details: {} } }),
            })
          : route.continue(),
      );
      await page.goto(uiUrl("default"));
      await expect(page.getByText(`Injected ${status} for the test.`, { exact: true })).toBeVisible();
      await expect(page.getByRole("heading", { name: "Wallet security, with the evidence" })).toBeVisible();
      fail = false;
      await page.getByRole("button", { name: /retry/i }).first().click();
      await expect(page.getByText("Verified via eth_chainId")).toBeVisible();
    });
  }
});
