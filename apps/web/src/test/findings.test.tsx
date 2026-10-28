import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { FindingView } from "../api/types";
import { FindingItem } from "../pages/wallet/FindingsPanel";

function finding(overrides: Partial<FindingView> = {}): FindingView {
  return {
    finding_id: "0x01",
    rule_id: "CG-POI-001",
    ruleset_version: "1.1.0",
    category: "address_poisoning",
    status: "superseded",
    severity: "elevated_risk",
    confidence: "high",
    subject: "poisoning:0xabc",
    title: "Possible address poisoning",
    explanation: "Lookalike planted.",
    evidence: [],
    simulated: false,
    first_seen_block: 1000,
    last_seen_block: 1000,
    resolved_block: 1100,
    reopen_count: 0,
    ...overrides,
  };
}

describe("finding card", () => {
  // Regression: a superseded finding (a warning that escalated) was labelled "resolved at block".
  it("says superseded, not resolved, when a finding was superseded", () => {
    render(
      <ul>
        <FindingItem finding={finding()} chainId={1} onChanged={() => {}} />
      </ul>,
    );
    expect(screen.getByText(/superseded at block 1,100/)).toBeInTheDocument();
    expect(screen.queryByText(/resolved at block/)).toBeNull();
  });

  it("says resolved when it was resolved", () => {
    render(
      <ul>
        <FindingItem finding={finding({ status: "resolved", rule_id: "CG-APR-001" })} chainId={1} onChanged={() => {}} />
      </ul>,
    );
    expect(screen.getByText(/resolved at block 1,100/)).toBeInTheDocument();
  });
});
