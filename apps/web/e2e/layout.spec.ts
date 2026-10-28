// Layout and accessibility checks on the real rendered app, plus documentation screenshots.
// Screenshots show the E2E fixture chain (fictional data), never live Ethereum analysis.
import { expect, openWallet, test, uiUrl, type Scenarios } from "./fixtures";

const SHOTS = "../../docs/screenshots";

/** Every documentation screenshot carries a visible label: it shows the E2E fixture chain. */
async function stamp(page: import("@playwright/test").Page) {
  await page.evaluate(() => {
    const banner = document.createElement("div");
    banner.textContent =
      "TEST FIXTURE DATA: fictional chain from the CryptoGuard E2E harness, not live Ethereum analysis";
    banner.setAttribute(
      "style",
      "position:fixed;top:0;left:0;right:0;z-index:9999;padding:6px 12px;background:#7c2d12;color:#fff;" +
        "font:600 13px system-ui;text-align:center",
    );
    document.body.appendChild(banner);
  });
}

async function noHorizontalOverflow(page: import("@playwright/test").Page, view: string) {
  const { scroll, width, culprits } = await page.evaluate(() => {
    const width = window.innerWidth;
    // Innermost elements that stick out on the right, to say *what* overflows.
    const culprits = [...document.querySelectorAll("body *")]
      .filter((el) => el.getBoundingClientRect().right > width + 1)
      .filter((el) => ![...el.children].some((c) => c.getBoundingClientRect().right > width + 1))
      .slice(0, 5)
      .map((el) => `${el.tagName.toLowerCase()}.${el.className}`.slice(0, 80));
    return { scroll: document.documentElement.scrollWidth, width, culprits };
  });
  expect(scroll, `${view} must not scroll sideways; overflowing: ${culprits.join(" | ")}`).toBeLessThanOrEqual(
    width + 1,
  );
}

const views = (s: Scenarios) =>
  [
    ["dashboard", "/"],
    ["overview", `/wallet/${s.poison}?tab=overview`],
    ["findings", `/wallet/${s.poison}?tab=findings`],
    ["timeline", `/wallet/${s.poison}?tab=timeline`],
    ["graph", `/wallet/${s.poison}?tab=graph`],
    ["campaign", `/wallet/${s.campaign[0]}?tab=poisoning`],
  ] as const;

for (const viewport of [
  { name: "desktop", width: 1280, height: 900 },
  { name: "mobile", width: 375, height: 812 },
  // The narrowest common phone. Also catches overflow that only wider fonts cause at 375 px
  // (Linux's DejaVu Sans overflowed the header where Windows' Segoe UI still fitted).
  { name: "small mobile", width: 320, height: 640 },
]) {
  test(`no sideways scrolling on any main view (${viewport.name})`, async ({ page, scenarios }) => {
    const s = await scenarios("shadow");
    await page.setViewportSize({ width: viewport.width, height: viewport.height });
    for (const [view, path] of views(s)) {
      await page.goto(uiUrl("shadow", path));
      await page.waitForLoadState("networkidle");
      await noHorizontalOverflow(page, view);
    }
  });
}

test("keyboard: search field, tabs with arrow keys, visible focus", async ({ page, scenarios }) => {
  const s = await scenarios("default");
  await page.goto(uiUrl("default"));
  const input = page.getByLabel("Public Ethereum address");
  await input.focus();
  await page.keyboard.type(s.poison);
  await page.keyboard.press("Enter");
  await expect(page.getByRole("tablist", { name: "Wallet views" })).toBeVisible();
  const overview = page.getByRole("tab", { name: "Overview" });
  await overview.focus();
  await page.keyboard.press("ArrowRight");
  const permissions = page.getByRole("tab", { name: "Permissions" });
  await expect(permissions).toBeFocused();
  await expect(permissions).toHaveAttribute("aria-selected", "true");
  const outline = await permissions.evaluate((el) => {
    const style = getComputedStyle(el);
    return `${style.outlineStyle} ${style.outlineWidth} ${style.boxShadow}`;
  });
  expect(outline, "focused tab must show a focus indicator").not.toMatch(/^none 0px none$/);
});

test("forms and buttons have accessible names; headings are present", async ({ page, scenarios }) => {
  const s = await scenarios("default");
  for (const [, path] of views(s).slice(0, 5)) {
    await page.goto(uiUrl("default", path));
    await page.waitForLoadState("networkidle");
    await expect(page.getByRole("heading").first()).toBeVisible();
    for (const button of await page.getByRole("button").all()) {
      const name = ((await button.getAttribute("aria-label")) ?? (await button.innerText())).trim();
      expect(name.length, "every button needs a name").toBeGreaterThan(0);
    }
    for (const field of await page.locator("input:not([type=hidden]), select, textarea").all()) {
      const id = await field.getAttribute("id");
      const labelled =
        (await field.getAttribute("aria-label")) ||
        (await field.getAttribute("aria-labelledby")) ||
        (id && (await page.locator(`label[for="${id}"]`).count())) ||
        (await field.evaluate((el) => !!el.closest("label")));
      expect(labelled, "every field needs a label").toBeTruthy();
    }
  }
});

test.describe("screenshots", () => {
  // Only so the injected fixture banner can be styled; the app's own CSP stays in force elsewhere.
  test.use({ bypassCSP: true });

  test("documentation screenshots (fixture data)", async ({ page, scenarios }) => {
  test.skip(!process.env.CRYPTOGUARD_SCREENSHOTS, "set CRYPTOGUARD_SCREENSHOTS=1 to refresh docs/screenshots");
  const s = await scenarios("shadow");
  await page.setViewportSize({ width: 1280, height: 900 });
  await openWallet(page, "shadow", s.poison, "overview");
  await stamp(page);
  await page.screenshot({ path: `${SHOTS}/wallet-overview.png`, fullPage: true });
  await openWallet(page, "shadow", s.poison, "findings");
  await page.getByText(/Possible address poisoning/).first().click();
  await page.waitForLoadState("networkidle");
  await stamp(page);
  await page.screenshot({ path: `${SHOTS}/security-finding.png`, fullPage: true });
  await openWallet(page, "shadow", s.poison, "timeline");
  await stamp(page);
  await page.screenshot({ path: `${SHOTS}/security-timeline.png`, fullPage: true });
  await openWallet(page, "shadow", s.campaign[0]!, "poisoning");
  await page.getByRole("button", { name: "Show evidence" }).click();
  await expect(page.getByText("These attempts share a verified planting signer.")).toBeVisible();
  await stamp(page);
  await page.screenshot({ path: `${SHOTS}/campaign-investigation.png`, fullPage: true });
  await page.setViewportSize({ width: 375, height: 812 });
  await page.goto(uiUrl("shadow"));
  await page.waitForLoadState("networkidle");
  await stamp(page);
  await page.screenshot({ path: `${SHOTS}/mobile-dashboard.png`, fullPage: true });
});
});
