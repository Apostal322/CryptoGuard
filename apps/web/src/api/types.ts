// Response shapes of the CryptoGuard API (mirrors the backend's pydantic models).
// Integers that can exceed 2^53 (balances, allowances) are strings and must stay strings.

export type DataSource = "rpc" | "demo_fixture";
export type CodeKind = "no_code" | "eip7702_delegation" | "contract" | "malformed_delegation_prefix";
export type Severity =
  | "informational"
  | "review_recommended"
  | "elevated_risk"
  | "critical_evidence"
  | "unknown";
export type Confidence = "high" | "medium" | "low";
export type FindingStatus = "new" | "active" | "acknowledged" | "resolved" | "superseded";

export interface ErrorBody {
  code: string;
  message: string;
  details: Record<string, unknown>;
}

export interface StatusResponse {
  version: string;
  mode: "real" | "demo";
  simulated: boolean;
  chain_id: number;
  chain_name: string;
  rpc_configured: boolean;
  provider: string | null;
  chain_verified: boolean | null;
  head_block: number | null;
  provider_error: ErrorBody | null;
  rpc_metrics: {
    requests: number;
    failures: number;
    retries: number;
    requests_by_method: Record<string, number>;
    last_error_code: string | null;
    last_error_at: string | null;
  } | null;
  checked_at: string;
}

export interface DemoAddressList {
  simulated: true;
  notice: string;
  addresses: { label: string; description: string; address: string }[];
}

export interface AddressInspection {
  schema_version: string;
  evidence_class: "observed_fact";
  data_source: DataSource;
  simulated: boolean;
  provider: string;
  address: string;
  chain_id: number;
  chain_name: string;
  chain_verified: boolean;
  block: {
    number: number;
    hash: string;
    timestamp: string;
    finality: "finalized" | "not_finalized" | "unknown";
    finalized_block_number: number | null;
    head_block_number: number;
  };
  native_balance: { wei: string; formatted: string; symbol: string };
  account_code: {
    kind: CodeKind;
    code_size: number;
    code_hash: string;
    delegation: {
      target: string;
      target_code_kind: CodeKind;
      target_code_size: number;
      target_code_hash: string;
      notes: string[];
    } | null;
    explanation: string;
  };
  observed_at: string;
  coverage: string;
  limitations: string[];
  explorer: { address: string; block: string } | null;
}

export interface AnalyzeAddressResponse {
  inspection: AddressInspection;
  persistence: "stored" | "already_stored" | "failed";
}

export interface Reading {
  status: "known" | "unknown";
  raw: string | null;
  formatted: string | null;
  unknown_reason: string | null;
}

export type AllowanceLevel = "none" | "limited" | "effectively_unlimited" | "unlimited" | "unknown";

export interface ApprovalEntry {
  token: { address: string; symbol: string | null; decimals: number | null; code_kind: CodeKind };
  spender: { address: string; code_kind: CodeKind; label: string | null; label_source: string | null };
  latest_event: {
    value: string;
    value_formatted: string | null;
    block_number: number;
    block_hash: string;
    transaction_hash: string;
    log_index: number;
    explorer_url: string | null;
  };
  events_in_range: number;
  current_allowance: Reading;
  allowance_level: AllowanceLevel;
  active: boolean | null;
  owner_balance: Reading;
  exposure_upper_bound: Reading;
  signals: { code: string; evidence_class: "observed_fact" | "heuristic_signal"; explanation: string }[];
}

export interface ApprovalScanReport {
  schema_version: string;
  data_source: DataSource;
  simulated: boolean;
  provider: string;
  owner: string;
  chain_id: number;
  chain_name: string;
  block_number: number;
  block_hash: string;
  block_timestamp: string;
  observed_at: string;
  coverage: {
    requested_from_block: number;
    requested_to_block: number;
    scanned_from_block: number;
    scanned_to_block: number;
    complete_for_requested_range: boolean;
    log_requests: number;
    log_query_splits: number;
    description: string;
  };
  token_scope: string[] | null;
  log_counts: { erc20_approvals: number; erc721_shaped_approvals: number; removed: number; malformed: number };
  pairs_discovered: number;
  pairs_truncated: number;
  approvals: ApprovalEntry[];
  exposure_model: string;
  limitations: string[];
}

export interface ApprovalScanResponse {
  report: ApprovalScanReport;
  persistence: { report: "stored" | "already_stored" | "failed"; new_events: number };
}

export interface Change {
  kind: string;
  subject: string;
  token: string | null;
  spender: string | null;
  before: string | null;
  after: string | null;
  from_block_exclusive: number;
  to_block: number;
  cause: {
    kind: "approval_event" | "state_comparison";
    transaction_hash: string | null;
    block_number: number | null;
    log_index: number | null;
    explorer_url: string | null;
    note: string;
  };
  explanation: string;
  why_it_matters: string;
}

export interface FindingEvent {
  finding_id: string;
  rule_id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  from_status: FindingStatus | null;
  to_status: FindingStatus;
  reason: string;
}

export interface CoverageRange {
  from_block: number;
  to_block: number;
}

export interface SnapshotCoverage {
  scanned: CoverageRange[];
  gaps: CoverageRange[];
  unverified_pairs: number;
  description: string;
  transfers_scanned: CoverageRange[];
  transfer_gaps: CoverageRange[];
}

export interface SnapshotOutcome {
  snapshot_id: number;
  created: boolean;
  simulated: boolean;
  owner: string;
  chain_id: number;
  block_number: number;
  block_hash: string;
  block_timestamp: string;
  head_block_number: number;
  lag_blocks: number;
  is_baseline: boolean;
  previous_block: number | null;
  state_hash: string;
  coverage: SnapshotCoverage;
  changes: Change[];
  finding_events: FindingEvent[];
  findings_not_reverified: number;
  orphaned_snapshots: number;
  notes: string[];
}

export interface TimelineEntry {
  snapshot_id: number;
  block_number: number;
  block_hash: string;
  block_timestamp: string;
  created_at: string;
  previous_block: number | null;
  is_baseline: boolean;
  orphaned: boolean;
  simulated: boolean;
  state_hash: string;
  ruleset_version: string;
  changes: Change[];
  finding_events: FindingEvent[];
  coverage: SnapshotCoverage;
  explorer_block_url: string | null;
}

export interface TimelinePage {
  items: TimelineEntry[];
  total: number;
  limit: number;
  offset: number;
}

export interface Evidence {
  kind: "approval_state" | "approval_event" | "account_code" | "transfer_event";
  description: string;
  block_number: number;
  transaction_hash: string | null;
}

export interface FindingView {
  finding_id: string;
  rule_id: string;
  ruleset_version: string;
  category: string;
  status: FindingStatus;
  severity: Severity;
  confidence: Confidence;
  subject: string;
  title: string;
  explanation: string;
  evidence: Evidence[];
  simulated: boolean;
  first_seen_block: number;
  last_seen_block: number;
  resolved_block: number | null;
  reopen_count: number;
}

export interface FindingDetail {
  finding: FindingView;
  transitions: {
    from_status: FindingStatus | null;
    to_status: FindingStatus;
    reason: string;
    block_number: number | null;
    snapshot_id: number | null;
    created_at: string;
  }[];
}

export interface FindingList {
  items: FindingView[];
  total: number;
}

export interface PoisoningCase {
  suspect: string;
  reference: string;
  reference_confirmed: boolean;
  reference_first_used_block: number;
  prefix_match: number;
  suffix_match: number;
  displayed_as: string;
  random_match_odds: string;
  signals: { code: string; description: string; transaction_hash: string | null; block_number: number | null }[];
  rule_id: string;
  severity: Severity;
  confidence: Confidence;
  explanation: string;
  recommended_action: string;
  first_seen_block: number;
}

export interface PoisoningReport {
  detector_version: string;
  data_source: DataSource;
  simulated: boolean;
  owner: string;
  chain_id: number;
  block_number: number;
  block_hash: string;
  observed_at: string;
  wallet_is_plain_eoa: boolean;
  scanned_from_block: number;
  complete_for_requested_range: boolean;
  token_scope: string[] | null;
  transfers_analyzed: number;
  sender_lookups: number;
  sender_lookups_skipped: number;
  cases: PoisoningCase[];
  limitations: string[];
}

export interface RulesetView {
  ruleset_id: string;
  version: string;
  severities: Severity[];
  rules: { rule_id: string; category: string; description: string }[];
}
