import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { api } from "../api/client";
import type { CampaignDetail, RelatedActivity } from "../api/types";
import { RelatedActivityView } from "../pages/wallet/RelatedActivity";
import { OWNER, TX } from "./fixtures";

const SIGNER = "0x5555555555555555555555555555555555555555";

const summary = {
  campaign_id: "cmp-0123456789abcdef01234567",
  attempts: 3,
  targeted_wallets: 2,
  lookalikes: 2,
  signers: 1,
  first_block: 1000,
  last_block: 1010,
  structure: "shared_entity" as const,
  confidence: "strongly_supported" as const,
  explanation: "3 poisoning attempts on 2 wallet(s) 1 shared signer(s).",
};

function related(overrides: Partial<RelatedActivity> = {}): RelatedActivity {
  return {
    run: {
      run_id: 1, created: false, chain_id: 1, cutoff_block: 1100, algorithm_version: "campaign-cluster/1",
      attempt_model_version: "poisoning-attempt/1", input_sha256: "ab", attempts: 3, clusters: 1, unclustered: 1,
      wallets_analysed: 3, expansion_tasks_used: 0, coverage: [], experimental: true,
      limitations: ["A cluster means the attempts share planting infrastructure as shown."],
    },
    wallet: OWNER,
    status: "related_activity",
    attempts_on_wallet: 1,
    campaigns: [summary],
    statement: "Potentially related poisoning activity: attempts on this wallet share planting infrastructure with attempts on 1 other wallet(s).",
    ...overrides,
  };
}

const detail: CampaignDetail = {
  ...summary,
  evidence: [
    { kind: "signer", key: SIGNER, statement: "These attempts share a verified planting signer.", strength: "strongly_supported",
      attempts: 3, wallets: 2, lookalikes: 2, reason: "The same verified key signed each planting transaction.", merges: true },
  ],
  articulation_entities: [],
  articulation_attempts: [],
  members: [
    { attempt_id: "0x01", victim: OWNER, lookalike: "0xabcd999999999999999999999999999999ef12", imitated: null,
      event_type: "zero_value_transfer", transaction_hash: TX, block_number: 1000, log_index: 1,
      contract: "0xf000000000000000000000000000000000000001", log_from: OWNER,
      log_to: "0xabcd999999999999999999999999999999ef12", value: "0", signer: SIGNER, source: "wallet_scan", rule_id: "CG-POI-001" },
  ],
  members_total: 1,
};

afterEach(() => vi.restoreAllMocks());

describe("RelatedActivityView", () => {
  it("uses evidence language, labels the section experimental and makes no ownership claim", () => {
    render(<RelatedActivityView data={related()} />);
    expect(screen.getByText("Related suspicious activity")).toBeInTheDocument();
    expect(screen.getByText("Experimental · shadow mode")).toBeInTheDocument();
    expect(screen.getByText("Strongly supported link")).toBeInTheDocument();
    expect(screen.queryByText(/same hacker|criminal|belong to/i)).toBeNull();
  });

  it("loads the evidence on demand", async () => {
    vi.spyOn(api, "campaign").mockResolvedValue(detail);
    render(<RelatedActivityView data={related()} />);
    fireEvent.click(screen.getByText("Show evidence"));
    expect(await screen.findByText("These attempts share a verified planting signer.")).toBeInTheDocument();
    expect(screen.getByText("Links these attempts")).toBeInTheDocument();
  });

  it("marks tentative groupings", () => {
    render(<RelatedActivityView data={related({ campaigns: [{ ...summary, confidence: "tentative", structure: "chained" }] })} />);
    expect(screen.getByText("Tentative grouping")).toBeInTheDocument();
  });
});
