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
  wallet_txs_scanned: CoverageRange[];
  wallet_txs_unlocated: number;
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
  wallet_transactions_located: number;
  wallet_transactions_unlocated: number | null;
  cases: PoisoningCase[];
  limitations: string[];
}

export type GraphNodeKind = "wallet" | "token" | "spender" | "delegation_target" | "counterparty" | "summary";
export type GraphEdgeType =
  | "APPROVED_SPENDER"
  | "HOLDS_TOKEN"
  | "DELEGATES_TO"
  | "TRANSFERRED_TO"
  | "RECEIVED_FROM"
  | "RESEMBLES"
  | "OTHER_COUNTERPARTIES";

export interface GraphNode {
  id: string;
  address: string | null;
  kinds: GraphNodeKind[];
  label: string | null;
  label_source: "known_contract" | "token_symbol_untrusted" | "summary" | null;
  code_kind: CodeKind | null;
  findings: {
    finding_id: string;
    rule_id: string;
    severity: Severity;
    confidence: Confidence;
    status: FindingStatus;
    title: string;
  }[];
  hidden_count: number | null;
}

export interface GraphEdge {
  id: string;
  type: GraphEdgeType;
  source: string;
  target: string;
  evidence_class: "observed_fact" | "heuristic_signal";
  explanation: string;
  attributes: Record<string, unknown>;
  evidence: {
    kind: string;
    description: string;
    block_number: number | null;
    transaction_hash: string | null;
  }[];
}

export interface WalletGraph {
  schema_version: string;
  wallet: string;
  chain_id: number;
  simulated: boolean;
  snapshot_id: number;
  snapshot_block: number;
  coverage: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  limits: { max_nodes: number; nodes_before_limit: number; hidden_counterparties: number; hidden_approvals: number };
  limitations: string[];
}

export interface ReplayManifest {
  case_id: string;
  title: string;
  category: string;
  chain_id: number;
  summary: string;
  first_public_report: string;
  public_sources: { publisher: string; title: string; url: string; accessed: string; used_for: string }[];
  victim: string;
  intended_recipient: string | null;
  harm: {
    transaction_hash: string;
    block_number: number;
    recipient: string;
    token: string;
    value_base_units: string;
    description: string;
  };
  evaluation: { from_block: number; to_block: number; rationale: string };
  onchain_verification: string[];
  ground_truth_limitations: string[];
}

export interface ReplayCaseView {
  manifest: ReplayManifest;
  recorded: boolean;
  fixture_sha256: string | null;
  recorded_with: string | null;
  recorded_at: string | null;
  transfers_in_fixture: number | null;
}

export interface ReplayDetection {
  block_number: number;
  timestamp: number | null;
  rule_id: string;
  severity: Severity;
  confidence: Confidence;
  signals: string[];
  explanation: string;
}

export interface ReplayVisibilityResult {
  visibility: "erc20_only" | "erc20_plus_wallet_transactions";
  description: string;
  outcome: "early_warning" | "post_incident_only" | "not_detected";
  first_warning: ReplayDetection | null;
  lead_time_blocks: number | null;
  lead_time_seconds: number | null;
  at_harm_block: ReplayDetection | null;
  other_addresses_flagged_before_harm: number;
  checkpoints_evaluated: number;
  explanation: string;
}

export interface ReplayResult {
  case_id: string;
  title: string;
  detector_version: string;
  ruleset_version: string;
  fixture_sha256: string;
  recorded_with: string;
  recorded_at: string;
  window_from_block: number;
  window_to_block: number;
  harm_block: number;
  harm_transaction: string;
  harm_timestamp: number | null;
  transfers_in_fixture: number;
  wallet_transactions_in_fixture: number;
  results: ReplayVisibilityResult[];
  leakage_checks: { check: string; passed: boolean; detail: string }[];
  runtime_ms: number;
  peak_memory_kib: number;
  rpc_requests_during_replay: number;
  rpc_requests_when_recorded: number;
  limitations: string[];
}

export interface RulesetView {
  ruleset_id: string;
  version: string;
  severities: Severity[];
  rules: { rule_id: string; category: string; description: string }[];
}

// Experimental analyses (shadow mode; off by default on the server).
export type AnalysisSectionStatus = "disabled" | "unavailable" | "insufficient_data" | "ok" | "skipped";

export interface AnalysisPathStep {
  source: string;
  target: string;
  relation: "transfer" | "native_transfer" | "caused" | "token_use";
  events: number;
  example_transaction: string | null;
  example_block: number | null;
}

export interface WalletAnalysis {
  analytics_version: string;
  wallet: string;
  chain_id: number;
  simulated: boolean;
  cutoff_block: number;
  experimental: boolean;
  coverage: string[];
  network: {
    status: AnalysisSectionStatus;
    statement: string | null;
    flagged_addresses: string[];
    related: { address: string; roles: string[]; hops: number; linked_to: string; path: AnalysisPathStep[]; score: number }[];
    parameters: Record<string, unknown>;
    notes: string[];
  };
  activity: {
    status: AnalysisSectionStatus;
    statement: string | null;
    anomalies: {
      statement: string;
      series: string;
      from_block: number;
      to_block: number;
      observed: number;
      expected: number;
      score: number;
      history_bins: number;
      transactions: string[];
    }[];
    bins: Record<string, number>;
    parameters: Record<string, unknown>;
    notes: string[];
  };
  structure: { status: AnalysisSectionStatus; features: Record<string, number | string | null>; notes: string[] };
  notes: string[];
}

// Experimental campaign analysis (shadow mode; off by default on the server).
export interface CampaignRunInfo {
  run_id: number;
  created: boolean;
  chain_id: number;
  cutoff_block: number;
  algorithm_version: string;
  attempt_model_version: string;
  input_sha256: string;
  attempts: number;
  clusters: number;
  unclustered: number;
  wallets_analysed: number;
  expansion_tasks_used: number;
  coverage: string[];
  limitations: string[];
  experimental: boolean;
}

export interface CampaignSummary {
  campaign_id: string;
  attempts: number;
  targeted_wallets: number;
  lookalikes: number;
  signers: number;
  first_block: number;
  last_block: number;
  structure: "shared_entity" | "multiply_connected" | "chained";
  confidence: "directly_observed" | "strongly_supported" | "tentative" | "insufficient";
  explanation: string;
}

export interface CampaignEvidence {
  kind: string;
  key: string;
  statement: string;
  strength: string;
  attempts: number;
  wallets: number;
  lookalikes: number;
  reason: string;
  merges: boolean;
}

export interface CampaignAttempt {
  attempt_id: string;
  victim: string;
  lookalike: string;
  imitated: string | null;
  event_type: string;
  transaction_hash: string;
  block_number: number;
  log_index: number;
  contract: string;
  log_from: string;
  log_to: string;
  value: string;
  signer: string | null;
  source: string;
  rule_id: string;
}

export interface CampaignDetail extends CampaignSummary {
  evidence: CampaignEvidence[];
  articulation_entities: string[];
  articulation_attempts: string[];
  members: CampaignAttempt[];
  members_total: number;
}

export interface RelatedActivity {
  run: CampaignRunInfo;
  wallet: string;
  status: "related_activity" | "attempts_without_links" | "no_attempts";
  attempts_on_wallet: number;
  campaigns: CampaignSummary[];
  statement: string;
}
