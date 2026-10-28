// Browser-relevant security properties, against the real API over HTTP.
import { apiUrl, expect, openWallet, test, uiUrl } from "./fixtures";

const ATTACKER = "http://attacker.e2e.test";

test("a hostile page cannot make the local API do work (CSRF, no preflight)", async ({ page, request, scenarios }) => {
  const s = await scenarios("default");
  const target = apiUrl("default", `/api/v1/wallets/${s.never}/snapshots`);
  // Serve an "attacker" page from another origin; it fires the classic preflight-free POSTs.
  await page.route(`${ATTACKER}/**`, (route) =>
    route.fulfill({ contentType: "text/html", body: "<!doctype html><title>attacker</title><p>hi</p>" }),
  );
  await page.goto(`${ATTACKER}/`);
  await page.evaluate(async (url) => {
    const shots = [
      fetch(url, { method: "POST", mode: "no-cors", headers: { "Content-Type": "text/plain" }, body: "{}" }),
      fetch(url, { method: "POST", mode: "no-cors", body: new URLSearchParams({ a: "1" }) }),
    ];
    await Promise.allSettled(shots);
  }, target);
  // Whatever the browser let through, the server did nothing: no snapshot exists.
  const timeline = await request.get(apiUrl("default", `/api/v1/wallets/${s.never}/timeline`));
  expect((await timeline.json()).total).toBe(0);
});

test("API refuses foreign origins, non-JSON POSTs and rebound hostnames; JSON still works", async ({ request, scenarios }) => {
  const s = await scenarios("default");
  const url = apiUrl("default", `/api/v1/wallets/${s.never}/snapshots`);
  const foreign = await request.post(url, { data: {}, headers: { Origin: "https://evil.example" } });
  expect(foreign.status()).toBe(403);
  expect((await foreign.json()).error.code).toBe("origin_not_allowed");
  const plain = await request.post(url, { data: "{}", headers: { "Content-Type": "text/plain" } });
  expect(plain.status()).toBe(415);
  const rebound = await request.get(apiUrl("default", "/api/v1/status"), { headers: { Host: "evil.example" } });
  expect(rebound.status()).toBe(400);
  expect((await rebound.json()).error.code).toBe("invalid_host");
  const own = await request.get(apiUrl("default", "/api/v1/status"));
  expect(own.status()).toBe(200);
});

test("external links go only to the chain's explorer, with safe link behaviour", async ({ page, scenarios }) => {
  const s = await scenarios("default");
  const hrefs: string[] = [];
  for (const [wallet, tab] of [
    [s.approvals, "timeline"],
    [s.poison, "timeline"],
    [s.poison, "findings"],
    [s.poison, "graph"],
  ] as const) {
    await openWallet(page, "default", wallet, tab);
    await expect(page.getByRole("tabpanel")).not.toBeEmpty();
    await page.waitForLoadState("networkidle");
    for (const link of await page.locator("a[target='_blank']").all()) {
      await expect(link).toHaveAttribute("rel", /noopener/);
      await expect(link).toHaveAttribute("rel", /noreferrer/);
      hrefs.push((await link.getAttribute("href")) ?? "");
    }
  }
  expect(hrefs.length).toBeGreaterThan(3);
  for (const href of hrefs) {
    expect(href).toMatch(/^https:\/\/etherscan\.io\/(tx\/0x[0-9a-fA-F]{64}|address\/0x[0-9a-fA-F]{40}|block\/\d+)$/);
  }
});

test("no RPC credential reaches the bundle, the page or the console", async ({ page, request, scenarios }) => {
  const s = await scenarios("default");
  const logs: string[] = [];
  page.on("console", (m) => logs.push(m.text()));
  await page.goto(uiUrl("default"));
  await expect(page.getByText("Verified via eth_chainId")).toBeVisible();
  const html = await (await request.get(uiUrl("default"))).text();
  const scripts = [...html.matchAll(/src="(\/assets\/[^"]+\.js)"/g)].map((m) => m[1]!);
  expect(scripts.length).toBeGreaterThan(0);
  for (const path of scripts) {
    const js = await (await request.get(uiUrl("default", path))).text();
    expect(js).not.toContain(s.secret_fragment);
    expect(js).not.toContain("rpc.e2e.invalid");
  }
  const status = await (await request.get(apiUrl("default", "/api/v1/status"))).text();
  expect(status).not.toContain(s.secret_fragment);
  expect(await page.locator("body").innerText()).not.toContain(s.secret_fragment);
  expect(logs.join("\n")).not.toContain(s.secret_fragment);
});

test("hostile token metadata never executes in any view", async ({ page, scenarios }) => {
  const s = await scenarios("default");
  for (const tab of ["timeline", "findings", "graph"]) {
    await openWallet(page, "default", s.approvals, tab);
    await page.waitForLoadState("networkidle");
    expect(await page.evaluate(() => (window as { __xss?: number }).__xss)).toBeUndefined();
    expect(await page.locator("img[src='x'], script:not([src])").count()).toBe(0);
  }
});
