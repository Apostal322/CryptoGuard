import type {
  AnalyzeAddressResponse,
  ApprovalScanReport,
  ApprovalScanResponse,
  DemoAddressList,
  ErrorBody,
  FindingDetail,
  FindingList,
  PoisoningReport,
  ReplayCaseView,
  ReplayResult,
  RulesetView,
  SnapshotOutcome,
  StatusResponse,
  TimelinePage,
  WalletAnalysis,
  WalletGraph,
} from "./types";

const BASE = "/api/v1";
const TIMEOUT_MS = 120_000; // scans can take a while on rate-limited providers

/** An API error with the backend's stable code. Messages are already user-safe. */
export class ApiError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(status: number, body: ErrorBody) {
    super(body.message);
    this.code = body.code;
    this.status = status;
  }
}

function isErrorBody(value: unknown): value is { error: ErrorBody } {
  if (typeof value !== "object" || value === null || !("error" in value)) return false;
  const error = (value as { error: unknown }).error;
  return (
    typeof error === "object" &&
    error !== null &&
    typeof (error as ErrorBody).code === "string" &&
    typeof (error as ErrorBody).message === "string"
  );
}

export async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  let response: Response;
  try {
    response = await fetch(`${BASE}${path}`, {
      ...init,
      signal: controller.signal,
      headers: { Accept: "application/json", ...(init.body ? { "Content-Type": "application/json" } : {}) },
    });
  } catch (cause) {
    const timedOut = cause instanceof DOMException && cause.name === "AbortError";
    throw new ApiError(0, {
      code: timedOut ? "client_timeout" : "network_error",
      message: timedOut
        ? "The request took too long. The RPC provider may be slow or rate-limiting."
        : "Cannot reach the CryptoGuard API. Is the backend running (cryptoguard serve)?",
      details: {},
    });
  } finally {
    clearTimeout(timer);
  }
  let body: unknown = null;
  try {
    body = await response.json();
  } catch {
    // fall through: non-JSON bodies are treated as errors below
  }
  if (!response.ok) {
    if (isErrorBody(body)) throw new ApiError(response.status, body.error);
    throw new ApiError(response.status, {
      code: "unexpected_response",
      message: `The API answered with HTTP ${response.status}.`,
      details: {},
    });
  }
  if (body === null) {
    throw new ApiError(response.status, { code: "unexpected_response", message: "Empty API response.", details: {} });
  }
  return body as T;
}

const post = <T>(path: string, payload: object = {}) =>
  request<T>(path, { method: "POST", body: JSON.stringify(payload) });

const wallet = (address: string) => `/wallets/${encodeURIComponent(address)}`;

export const api = {
  status: () => request<StatusResponse>("/status"),
  demoAddresses: () => request<DemoAddressList>("/demo/addresses"),
  rules: () => request<RulesetView>("/rules"),
  analyze: (address: string) => post<AnalyzeAddressResponse>("/analyze/address", { address }),
  latestApprovals: (address: string) => request<ApprovalScanReport>(`${wallet(address)}/approvals`),
  scanApprovals: (address: string, options: { lookback_blocks?: number; tokens?: string[] }) =>
    post<ApprovalScanResponse>(`${wallet(address)}/approvals/scan`, options),
  snapshot: (address: string, options: { tokens?: string[]; lookback_blocks?: number }) =>
    post<SnapshotOutcome>(`${wallet(address)}/snapshots`, options),
  timeline: (address: string, offset = 0, limit = 20) =>
    request<TimelinePage>(`${wallet(address)}/timeline?limit=${limit}&offset=${offset}`),
  findings: (address: string, status: "open" | "all") =>
    request<FindingList>(`${wallet(address)}/findings?status=${status}`),
  finding: (id: string) => request<FindingDetail>(`/findings/${encodeURIComponent(id)}`),
  acknowledge: (id: string) => post<FindingDetail>(`/findings/${encodeURIComponent(id)}/acknowledge`),
  graph: (address: string, maxNodes: number, includeInactive: boolean) =>
    request<WalletGraph>(
      `${wallet(address)}/graph?max_nodes=${maxNodes}&include_inactive=${includeInactive ? "true" : "false"}`,
    ),
  analysis: (address: string) => request<WalletAnalysis>(`${wallet(address)}/analysis`),
  replayCases: () => request<{ items: ReplayCaseView[] }>("/replay/cases"),
  replayRun: (caseId: string) => post<ReplayResult>("/replay/runs", { case_id: caseId }),
  poisoningScan: (address: string, options: { lookback_blocks?: number; tokens?: string[] }) =>
    post<PoisoningReport>(`${wallet(address)}/poisoning/scan`, options),
};
