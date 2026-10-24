import { useState } from "react";

import { ApiError, api } from "../../api/client";
import type { AllowanceLevel, ApprovalEntry, ApprovalScanReport } from "../../api/types";
import { ScanForm, type ScanOptions } from "../../components/ScanForm";
import {
  Address,
  Badge,
  Callout,
  Card,
  Empty,
  ErrorView,
  KeyValues,
  Limitations,
  Loading,
  SimulatedBadge,
  TxLink,
} from "../../components/ui";
import { formatReading, formatUtc, humanize } from "../../lib/format";
import { useAsync } from "../../lib/useAsync";

const LEVEL_TONE: Record<AllowanceLevel, "neutral" | "info" | "review" | "elevated"> = {
  none: "neutral",
  limited: "info",
  effectively_unlimited: "review",
  unlimited: "review",
  unknown: "neutral",
};

function Allowance({ entry }: { entry: ApprovalEntry }) {
  if (entry.allowance_level === "unlimited") return <span>Unlimited (max uint256)</span>;
  return <span>{formatReading(entry.current_allowance, entry.token.symbol)}</span>;
}

export function ApprovalRow({ entry, report }: { entry: ApprovalEntry; report: ApprovalScanReport }) {
  const symbol = entry.token.symbol;
  return (
    <li className="flex flex-col gap-3 py-4">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={LEVEL_TONE[entry.allowance_level]}>{humanize(entry.allowance_level)}</Badge>
        <span className="text-sm font-medium">{symbol ?? "Unknown token"}</span>
        <span className="text-xs text-faint" title="Contract-supplied text; it can imitate other tokens">
          (untrusted symbol)
        </span>
      </div>
      <KeyValues
        items={[
          ["Token", <Address key="t" value={entry.token.address} />],
          ["Spender", <Address key="s" value={entry.spender.address} label={entry.spender.label} />],
          ["Spender code", humanize(entry.spender.code_kind)],
          ["Allowance", <Allowance key="a" entry={entry} />],
          ["Your balance", formatReading(entry.owner_balance, symbol)],
          [
            "Possible exposure",
            <span key="e">
              ≤ {formatReading(entry.exposure_upper_bound, symbol)}{" "}
              <span className="text-xs text-faint">(upper bound, not a loss estimate)</span>
            </span>,
          ],
          [
            "Last set",
            <span key="l">
              block {entry.latest_event.block_number.toLocaleString("en-US")} ·{" "}
              <TxLink chainId={report.chain_id} hash={entry.latest_event.transaction_hash} simulated={report.simulated} />
            </span>,
          ],
        ]}
      />
      {entry.signals.length > 0 && (
        <ul className="flex flex-col gap-1.5">
          {entry.signals.map((signal) => (
            <li key={signal.code} className="text-sm">
              <Badge tone={signal.evidence_class === "heuristic_signal" ? "elevated" : "info"}>
                {signal.evidence_class === "heuristic_signal" ? "Heuristic" : "Observed fact"}
              </Badge>{" "}
              <span className="text-muted">{signal.explanation}</span>
            </li>
          ))}
        </ul>
      )}
    </li>
  );
}

export function ApprovalReport({ report }: { report: ApprovalScanReport }) {
  const [showInactive, setShowInactive] = useState(false);
  const active = report.approvals.filter((entry) => entry.active !== false);
  const shown = showInactive ? report.approvals : active;
  return (
    <div className="flex flex-col gap-4">
      {!report.coverage.complete_for_requested_range && (
        <Callout tone="warn" title="Partial coverage">
          {report.coverage.description}
        </Callout>
      )}
      <Card
        title={`Token permissions (${active.length} active)`}
        actions={<SimulatedBadge simulated={report.simulated} />}
      >
        <p className="mb-3 text-sm text-muted">
          State at block {report.block_number.toLocaleString("en-US")} ({formatUtc(report.block_timestamp)}).{" "}
          {report.coverage.description}
        </p>
        {report.approvals.length === 0 ? (
          <Empty>No ERC-20 approvals were found in the scanned range.</Empty>
        ) : (
          <>
            <label className="flex items-center gap-2 text-sm text-muted">
              <input type="checkbox" checked={showInactive} onChange={(e) => setShowInactive(e.target.checked)} />
              Show revoked or spent approvals ({report.approvals.length - active.length})
            </label>
            {shown.length === 0 ? (
              <Empty>No active approvals. All observed approvals are now zero.</Empty>
            ) : (
              <ul className="divide-y divide-line">
                {shown.map((entry) => (
                  <ApprovalRow key={`${entry.token.address}:${entry.spender.address}`} entry={entry} report={report} />
                ))}
              </ul>
            )}
          </>
        )}
        {report.log_counts.erc721_shaped_approvals > 0 && (
          <p className="mt-3 text-xs text-faint">
            {report.log_counts.erc721_shaped_approvals} NFT-shaped approval log(s) were seen but are not analyzed yet.
          </p>
        )}
      </Card>
      <Limitations items={report.limitations} />
    </div>
  );
}

export function ApprovalsPanel({ address }: { address: string }) {
  const latest = useAsync(async () => {
    try {
      return await api.latestApprovals(address);
    } catch (error) {
      if (error instanceof ApiError && error.code === "no_approval_scan") return null;
      throw error;
    }
  }, [address]);
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState<ApiError | null>(null);
  const [fresh, setFresh] = useState<ApprovalScanReport | null>(null);

  const scan = async (options: ScanOptions) => {
    setScanning(true);
    setScanError(null);
    try {
      setFresh((await api.scanApprovals(address, options)).report);
    } catch (error) {
      setScanError(error instanceof ApiError ? error : null);
    } finally {
      setScanning(false);
    }
  };

  const report = fresh ?? latest.data;
  return (
    <div className="flex flex-col gap-4">
      <Card title="Scan approvals">
        <p className="mb-3 text-sm text-muted">
          Finds Approval events in a bounded block window, then reads each allowance and balance at
          one block. Approvals granted before the window are not found.
        </p>
        <ScanForm submitLabel="Scan approvals" busy={scanning} onSubmit={scan} />
      </Card>
      {scanError && <ErrorView error={scanError} />}
      {latest.loading && !report && <Loading />}
      {latest.error && <ErrorView error={latest.error} onRetry={latest.run} />}
      {!latest.loading && !latest.error && !report && <Empty>No approval scan has been run for this wallet yet.</Empty>}
      {report && <ApprovalReport report={report} />}
    </div>
  );
}
