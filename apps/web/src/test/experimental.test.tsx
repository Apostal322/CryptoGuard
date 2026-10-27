import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { WalletAnalysis } from "../api/types";
import { ExperimentalContextView } from "../pages/wallet/ExperimentalContext";
import { OWNER, TX } from "./fixtures";

const SIGNER = "0x517DC8E50b8bf03A1D69c84d27bF96dC5A911Db2";
const LOOKALIKE = "0xd9A1C3788D81257612E2581A6ea0aDa244853a91";

function analysis(overrides: Partial<WalletAnalysis> = {}): WalletAnalysis {
  return {
    analytics_version: "0.1.0",
    wallet: OWNER,
    chain_id: 1,
    simulated: false,
    cutoff_block: 100,
    experimental: true,
    coverage: ["ERC-20 transfers observed in blocks 1-100."],
    network: { status: "disabled", statement: null, flagged_addresses: [], related: [], parameters: {}, notes: [] },
    activity: { status: "disabled", statement: null, anomalies: [], bins: {}, parameters: {}, notes: [] },
    structure: { status: "disabled", features: {}, notes: [] },
    notes: ["No unusual pattern in the observed data is not evidence that the wallet is safe."],
    ...overrides,
  };
}

describe("ExperimentalContextView", () => {
  it("renders nothing when every analysis is off (the default)", () => {
    const { container } = render(<ExperimentalContextView analysis={analysis()} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("shows related addresses with their evidence path and labels the section experimental", () => {
    render(
      <ExperimentalContextView
        analysis={analysis({
          network: {
            status: "ok",
            statement: "Indirect links to a previously flagged address were identified.",
            flagged_addresses: [LOOKALIKE],
            related: [
              {
                address: SIGNER,
                roles: ["signer"],
                hops: 1,
                linked_to: LOOKALIKE,
                score: 0.2,
                path: [{ source: SIGNER, target: LOOKALIKE, relation: "caused", events: 1, example_transaction: TX, example_block: 90 }],
              },
            ],
            parameters: {},
            notes: [],
          },
        })}
      />,
    );
    expect(screen.getByText("Experimental · shadow mode")).toBeInTheDocument();
    expect(screen.getByText("Indirect links to a previously flagged address were identified.")).toBeInTheDocument();
    expect(screen.getByText(SIGNER)).toBeInTheDocument();
    expect(screen.getByText(/signed the transaction behind a transfer to/)).toBeInTheDocument();
    expect(screen.queryByText(/eigen|laplacian/i)).toBeNull();
  });

  it("says when there is not enough data instead of implying safety", () => {
    render(
      <ExperimentalContextView
        analysis={analysis({
          activity: { status: "insufficient_data", statement: null, anomalies: [], bins: {}, parameters: {}, notes: [] },
        })}
      />,
    );
    expect(screen.getByText("Not enough observed data to say anything here.")).toBeInTheDocument();
  });
});
