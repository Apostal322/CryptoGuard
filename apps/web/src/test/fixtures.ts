import type { ApprovalEntry, ApprovalScanReport, PoisoningReport, StatusResponse } from "../api/types";

export const OWNER = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
export const TOKEN = "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB";
export const SPENDER = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D";
export const TX = "0x" + "cd".repeat(32);

export function status(overrides: Partial<StatusResponse> = {}): StatusResponse {
  return {
    version: "0.1.0",
    mode: "real",
    simulated: false,
    chain_id: 1,
    chain_name: "Ethereum Mainnet",
    rpc_configured: true,
    provider: "https://rpc.example/…",
    chain_verified: true,
    head_block: 100,
    provider_error: null,
    rpc_metrics: null,
    checked_at: "2026-10-24T00:00:00+00:00",
    ...overrides,
  };
}

export function entry(overrides: Partial<ApprovalEntry> = {}): ApprovalEntry {
  return {
    token: { address: TOKEN, symbol: "TKN", decimals: 18, code_kind: "contract" },
    spender: { address: SPENDER, code_kind: "contract", label: "Uniswap V2: Router 02", label_source: "docs" },
    latest_event: {
      value: "5",
      value_formatted: null,
      block_number: 90,
      block_hash: "0x" + "ee".repeat(32),
      transaction_hash: TX,
      log_index: 1,
      explorer_url: null,
    },
    events_in_range: 1,
    current_allowance: { status: "known", raw: "5", formatted: "0.000000000000000005", unknown_reason: null },
    allowance_level: "limited",
    active: true,
    owner_balance: { status: "known", raw: "10", formatted: "0.00000000000000001", unknown_reason: null },
    exposure_upper_bound: { status: "known", raw: "5", formatted: "0.000000000000000005", unknown_reason: null },
    signals: [],
    ...overrides,
  };
}

export function report(approvals: ApprovalEntry[], overrides: Partial<ApprovalScanReport> = {}): ApprovalScanReport {
  return {
    schema_version: "approval-scan/1",
    data_source: "rpc",
    simulated: false,
    provider: "https://rpc.example/…",
    owner: OWNER,
    chain_id: 1,
    chain_name: "Ethereum Mainnet",
    block_number: 100,
    block_hash: "0x" + "aa".repeat(32),
    block_timestamp: "2026-10-24T00:00:00+00:00",
    observed_at: "2026-10-24T00:00:01+00:00",
    coverage: {
      requested_from_block: 1,
      requested_to_block: 100,
      scanned_from_block: 1,
      scanned_to_block: 100,
      complete_for_requested_range: true,
      log_requests: 1,
      log_query_splits: 0,
      description: "Approval events were scanned in blocks 1 to 100.",
    },
    token_scope: null,
    log_counts: { erc20_approvals: approvals.length, erc721_shaped_approvals: 0, removed: 0, malformed: 0 },
    pairs_discovered: approvals.length,
    pairs_truncated: 0,
    approvals,
    exposure_model: "min(balance, allowance)",
    limitations: ["Only ERC-20 allowances are analyzed."],
    ...overrides,
  };
}

export function poisoningReport(overrides: Partial<PoisoningReport> = {}): PoisoningReport {
  return {
    detector_version: "1.0.0",
    data_source: "rpc",
    simulated: false,
    owner: OWNER,
    chain_id: 1,
    block_number: 100,
    block_hash: "0x" + "aa".repeat(32),
    observed_at: "2026-10-24T00:00:00+00:00",
    wallet_is_plain_eoa: true,
    scanned_from_block: 1,
    complete_for_requested_range: true,
    token_scope: null,
    transfers_analyzed: 2,
    sender_lookups: 1,
    sender_lookups_skipped: 0,
    cases: [
      {
        suspect: "0xA1B2C99999999999999999999999999999994E5F6".slice(0, 42),
        reference: "0xa1b2c31111111111111111111111111111d4e5f6",
        reference_confirmed: true,
        reference_first_used_block: 50,
        prefix_match: 5,
        suffix_match: 5,
        displayed_as: "0xa1b2c…4e5f6",
        random_match_odds: "1 in 1,099,511,627,776",
        signals: [{ code: "zero_value_transfer", description: "Zero-value transfer.", transaction_hash: TX, block_number: 60 }],
        rule_id: "CG-POI-001",
        severity: "elevated_risk",
        confidence: "high",
        explanation: "Lookalike planted with poisoning-style transfers.",
        recommended_action: "Compare the FULL address with a trusted source.",
        first_seen_block: 60,
      },
    ],
    limitations: [],
    ...overrides,
  };
}
