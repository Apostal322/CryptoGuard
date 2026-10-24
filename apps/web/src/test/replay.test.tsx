import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ReplayCaseView, ReplayResult } from "../api/types";
import { safeCuratedUrl } from "../lib/explorer";
import { Replay } from "../pages/Replay";

afterEach(() => vi.unstubAllGlobals());

const CASE: ReplayCaseView = {
  recorded: true,
  fixture_sha256: "ab".repeat(32),
  recorded_with: "https://eth.drpc.org",
  recorded_at: "2026-10-24T00:00:00+00:00",
  transfers_in_fixture: 340,
  manifest: {
    case_id: "case-1",
    title: "Test incident",
    category: "address_poisoning",
    chain_id: 1,
    summary: "Summary.",
    first_public_report: "2024-05-03",
    public_sources: [
      { publisher: "Good", title: "Report", url: "https://news.example/report", accessed: "2026-10-24", used_for: "addresses" },
      { publisher: "Bad", title: "Script", url: "javascript:alert(1)", accessed: "2026-10-24", used_for: "nothing" },
    ],
    victim: "0x1E227979f0b5BC691a70DEAed2e0F39a6F538FD5",
    intended_recipient: "0xd9A1b0B1e1aE382DbDc898Ea68012FfcB2853a91",
    harm: {
      transaction_hash: "0x" + "33".repeat(32),
      block_number: 100,
      recipient: "0xd9A1C3788D81257612E2581A6ea0aDa244853a91",
      token: "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599",
      value_base_units: "1",
      description: "Sent to the lookalike.",
    },
    evaluation: { from_block: 1, to_block: 100, rationale: "Fixed window." },
    onchain_verification: ["Verified something."],
    ground_truth_limitations: ["Limited."],
  },
};

const RESULT: ReplayResult = {
  case_id: "case-1",
  title: "Test incident",
  detector_version: "1.0.0",
  ruleset_version: "1.1.0",
  fixture_sha256: "ab".repeat(32),
  recorded_with: "https://eth.drpc.org",
  recorded_at: "2026-10-24T00:00:00+00:00",
  window_from_block: 1,
  window_to_block: 100,
  harm_block: 100,
  harm_transaction: "0x" + "33".repeat(32),
  harm_timestamp: 1200,
  transfers_in_fixture: 340,
  wallet_transactions_in_fixture: 2,
  results: [
    {
      visibility: "erc20_only", description: "ERC-20 only.", outcome: "not_detected", first_warning: null,
      lead_time_blocks: null, lead_time_seconds: null, at_harm_block: null,
      other_addresses_flagged_before_harm: 0, checkpoints_evaluated: 112, explanation: "Never learns the reference.",
    },
    {
      visibility: "erc20_plus_wallet_transactions", description: "Plus wallet txs.", outcome: "early_warning",
      first_warning: { block_number: 60, timestamp: 720, rule_id: "CG-POI-001", severity: "elevated_risk", confidence: "high", signals: ["spoofed_outgoing_transfer"], explanation: "x" },
      lead_time_blocks: 40, lead_time_seconds: 480, at_harm_block: null,
      other_addresses_flagged_before_harm: 0, checkpoints_evaluated: 113, explanation: "Warned early.",
    },
  ],
  leakage_checks: [{ check: "inputs_bounded_by_cutoff", passed: true, detail: "ok" }],
  runtime_ms: 12,
  peak_memory_kib: 100,
  rpc_requests_during_replay: 0,
  rpc_requests_when_recorded: 756,
  limitations: [],
};

describe("incident replay page", () => {
  it("links only https sources and shows both visibility outcomes after a run", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) =>
        new Response(JSON.stringify(url.endsWith("/replay/cases") ? { items: [CASE] } : RESULT), { status: 200 }),
      ),
    );
    render(<Replay />);
    expect(await screen.findByText("Test incident")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Good: Report/ })).toHaveAttribute("href", "https://news.example/report");
    expect(screen.queryByRole("link", { name: /Bad: Script/ })).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Run replay" }));
    expect(await screen.findByText("Not detected")).toBeInTheDocument();
    expect(screen.getByText("Early warning")).toBeInTheDocument();
    expect(screen.getByText(/40 blocks \(about 8 minutes\)/)).toBeInTheDocument();
    expect(screen.getByText("Pass")).toBeInTheDocument();
  });

  it("restricts curated links to https without credentials", () => {
    expect(safeCuratedUrl("https://news.example/a")).toBe("https://news.example/a");
    expect(safeCuratedUrl("http://news.example/a")).toBeNull();
    expect(safeCuratedUrl("https://u:p@news.example/a")).toBeNull();
    expect(safeCuratedUrl("javascript:alert(1)")).toBeNull();
  });
});
