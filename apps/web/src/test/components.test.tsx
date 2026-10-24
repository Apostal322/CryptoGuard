import { render, screen, waitFor } from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import { StatusProvider } from "../app/status";
import { routes } from "../main";
import { ApprovalReport } from "../pages/wallet/ApprovalsPanel";
import { AffixAddress, CaseCard } from "../pages/wallet/PoisoningPanel";
import { TX, entry, poisoningReport, report, status } from "./fixtures";

afterEach(() => vi.unstubAllGlobals());

function stubApi(handlers: Record<string, unknown>) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      const path = url.replace("/api/v1", "").split("?")[0]!;
      if (!(path in handlers)) {
        return new Response(JSON.stringify({ error: { code: "not_found", message: "nope", details: {} } }), { status: 404 });
      }
      return new Response(JSON.stringify(handlers[path]), { status: 200 });
    }),
  );
}

function renderAt(path: string) {
  const router = createMemoryRouter(routes, { initialEntries: [path] });
  return render(
    <StatusProvider>
      <RouterProvider router={router} />
    </StatusProvider>,
  );
}

describe("approval inspector", () => {
  it("renders untrusted token metadata as plain text", () => {
    const hostile = '<img src=x onerror="alert(1)">';
    const { container } = render(<ApprovalReport report={report([entry({ token: { ...entry().token, symbol: hostile } })])} />);
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getByText(hostile)).toBeInTheDocument();
  });

  it("shows unknown values explicitly and never as zero", () => {
    const unknown = { status: "unknown" as const, raw: null, formatted: null, unknown_reason: "call_reverted" };
    render(
      <ApprovalReport
        report={report([
          entry({
            current_allowance: unknown,
            allowance_level: "unknown",
            active: null,
            exposure_upper_bound: { ...unknown, unknown_reason: "allowance_or_balance_unknown" },
          }),
        ])}
      />,
    );
    expect(screen.getByText("Unknown (Call reverted)")).toBeInTheDocument();
    expect(screen.getByText(/Unknown \(Allowance or balance unknown\)/)).toBeInTheDocument();
  });

  it("labels unlimited approvals and shows full addresses", () => {
    render(<ApprovalReport report={report([entry({ allowance_level: "unlimited" })])} />);
    expect(screen.getByText("Unlimited (max uint256)")).toBeInTheDocument();
    expect(screen.getByText("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: new RegExp(TX) })).toHaveAttribute(
      "href",
      `https://etherscan.io/tx/${TX}`,
    );
  });

  it("never links simulated data to a real explorer", () => {
    render(<ApprovalReport report={report([entry()], { simulated: true, data_source: "demo_fixture" })} />);
    expect(screen.getByText("Simulated")).toBeInTheDocument();
    expect(screen.queryAllByRole("link")).toHaveLength(0);
  });

  it("warns about partial coverage", () => {
    const base = report([entry()]);
    render(
      <ApprovalReport
        report={{ ...base, coverage: { ...base.coverage, complete_for_requested_range: false, description: "blocks 1-50 NOT scanned" } }}
      />,
    );
    expect(screen.getByText("Partial coverage")).toBeInTheDocument();
  });

  it("hides inactive approvals by default", () => {
    render(<ApprovalReport report={report([entry({ active: false, allowance_level: "none" })])} />);
    expect(screen.getByText(/No active approvals/)).toBeInTheDocument();
  });
});

describe("poisoning view", () => {
  it("highlights shared characters of the full address", () => {
    const { container } = render(<AffixAddress address="0xa1b2c3111111d4e5f6" prefix={5} suffix={5} />);
    const marks = container.querySelectorAll("mark");
    expect([...marks].map((m) => m.textContent)).toEqual(["a1b2c", "4e5f6"]);
  });

  it("shows severity and confidence separately with the verification advice", () => {
    const data = poisoningReport();
    render(<CaseCard item={data.cases[0]!} report={data} />);
    expect(screen.getByText("Elevated risk")).toBeInTheDocument();
    expect(screen.getByText("High confidence")).toBeInTheDocument();
    expect(screen.getByText(/Compare the FULL address/)).toBeInTheDocument();
  });
});

describe("app shell", () => {
  it("shows a persistent banner in demo mode", async () => {
    stubApi({ "/status": status({ mode: "demo", simulated: true }), "/demo/addresses": { simulated: true, notice: "Fictional.", addresses: [] } });
    renderAt("/");
    expect(await screen.findByText(/Demo mode — simulated data/)).toBeInTheDocument();
  });

  it("explains when no RPC is configured instead of showing fake data", async () => {
    stubApi({ "/status": status({ rpc_configured: false, provider: null, chain_verified: null, head_block: null }) });
    renderAt("/");
    expect(await screen.findByText(/No Ethereum RPC endpoint is configured/)).toBeInTheDocument();
  });

  it("reports an unreachable API", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => Promise.reject(new TypeError("Failed to fetch"))));
    renderAt("/");
    expect(await screen.findByText(/The CryptoGuard API is unreachable/)).toBeInTheDocument();
  });

  it("rejects a malformed wallet URL", async () => {
    stubApi({ "/status": status() });
    renderAt("/wallet/0x123");
    expect(await screen.findByText("Not an address")).toBeInTheDocument();
  });

  it("supports arrow-key tab navigation", async () => {
    stubApi({ "/status": status() });
    renderAt(`/wallet/0x${"a".repeat(40)}?tab=findings`);
    const tab = await screen.findByRole("tab", { name: "Findings" });
    expect(tab).toHaveAttribute("aria-selected", "true");
    tab.focus();
    tab.dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowRight", bubbles: true }));
    await waitFor(() => expect(screen.getByRole("tab", { name: "Threat graph" })).toHaveAttribute("aria-selected", "true"));
  });
});
