import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { WalletGraph } from "../api/types";
import { GraphView } from "../pages/wallet/GraphPanel";
import { nodeLabel, ring } from "../pages/wallet/graphStyle";
import { OWNER, SPENDER, TOKEN, TX } from "./fixtures";

// jsdom has no canvas; the list and detail panel carry the same information.
vi.mock("../pages/wallet/GraphCanvas", () => ({ GraphCanvas: () => <div data-testid="canvas" /> }));

const LOOKALIKE = "0xA1b2C99999999999999999999999999994e5F6aa";

function graph(overrides: Partial<WalletGraph> = {}): WalletGraph {
  return {
    schema_version: "wallet-graph/1",
    wallet: OWNER,
    chain_id: 1,
    simulated: false,
    snapshot_id: 3,
    snapshot_block: 100,
    coverage: "test",
    nodes: [
      { id: OWNER, address: OWNER, kinds: ["wallet"], label: null, label_source: null, code_kind: "no_code", findings: [], hidden_count: null },
      { id: SPENDER, address: SPENDER, kinds: ["spender"], label: "Uniswap V2: Router 02", label_source: "known_contract", code_kind: "contract", findings: [], hidden_count: null },
      { id: TOKEN, address: TOKEN, kinds: ["token"], label: '<b onmouseover="x">USDC</b>', label_source: "token_symbol_untrusted", code_kind: null, findings: [], hidden_count: null },
      {
        id: LOOKALIKE, address: LOOKALIKE, kinds: ["counterparty"], label: null, label_source: null, code_kind: null, hidden_count: null,
        findings: [{ finding_id: "0x01", rule_id: "CG-POI-001", severity: "elevated_risk", confidence: "high", status: "new", title: "Possible address poisoning" }],
      },
    ],
    edges: [
      {
        id: "a", type: "APPROVED_SPENDER", source: OWNER, target: SPENDER, evidence_class: "observed_fact",
        explanation: "The wallet allows the router to spend USDC.", attributes: {},
        evidence: [{ kind: "approval_event", description: "Latest Approval event.", block_number: 90, transaction_hash: TX }],
      },
      {
        id: "r", type: "RESEMBLES", source: LOOKALIKE, target: SPENDER, evidence_class: "heuristic_signal",
        explanation: "Inferred, not an observed interaction: shares 5/5 characters.", attributes: {},
        evidence: [{ kind: "similarity", description: "Full-address comparison.", block_number: 95, transaction_hash: null }],
      },
    ],
    limits: { max_nodes: 60, nodes_before_limit: 4, hidden_counterparties: 0, hidden_approvals: 0 },
    limitations: [],
    ...overrides,
  };
}

describe("threat graph view", () => {
  it("lists every relationship accessibly and shows evidence on selection", () => {
    render(<GraphView graph={graph()} />);
    const list = screen.getByText(/All relationships as a list/).closest("details")!;
    const buttons = within(list).getAllByRole("button");
    expect(buttons).toHaveLength(2);
    fireEvent.click(buttons[0]!);
    expect(screen.getByText("Observed fact")).toBeInTheDocument();
    expect(screen.getByText("The wallet allows the router to spend USDC.")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: new RegExp(TX) })).toHaveAttribute("href", `https://etherscan.io/tx/${TX}`);
  });

  it("marks inferred edges as heuristic", () => {
    render(<GraphView graph={graph()} />);
    const list = screen.getByText(/All relationships as a list/).closest("details")!;
    fireEvent.click(within(list).getAllByRole("button")[1]!);
    expect(screen.getByText("Inferred (heuristic)")).toBeInTheDocument();
  });

  it("filters relationship types", () => {
    render(<GraphView graph={graph()} />);
    fireEvent.click(screen.getByRole("checkbox", { name: /Resembles/ }));
    const list = screen.getByText(/All relationships as a list \(1\)/).closest("details")!;
    expect(within(list).getAllByRole("button")).toHaveLength(1);
  });

  it("never links simulated evidence to an explorer", () => {
    render(<GraphView graph={graph({ simulated: true })} />);
    const list = screen.getByText(/All relationships as a list/).closest("details")!;
    fireEvent.click(within(list).getAllByRole("button")[0]!);
    expect(screen.queryByRole("link")).toBeNull();
  });
});

describe("graph styling helpers", () => {
  it("labels nodes without hiding which label is untrusted", () => {
    const g = graph();
    expect(nodeLabel(g.nodes[0]!, OWNER)).toBe("This wallet");
    expect(nodeLabel(g.nodes[1]!, OWNER)).toContain("Uniswap V2: Router 02");
    expect(nodeLabel(g.nodes[3]!, OWNER)).toBe(`${LOOKALIKE.slice(0, 6)}…${LOOKALIKE.slice(-4)}`);
  });

  it("places the wallet in the centre ring", () => {
    const g = graph();
    expect(ring(g.nodes[0]!)).toBeGreaterThan(ring(g.nodes[1]!));
    expect(ring(g.nodes[1]!)).toBeGreaterThan(ring(g.nodes[3]!));
  });
});
