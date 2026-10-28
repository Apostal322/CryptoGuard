import { useState } from "react";

import { ApiError, api } from "../../api/client";
import type { FindingDetail, FindingView } from "../../api/types";
import { useStatus } from "../../app/status";
import {
  Badge,
  Button,
  Card,
  Empty,
  ErrorView,
  Loading,
  SeverityBadges,
  SimulatedBadge,
  TxLink,
} from "../../components/ui";
import { CONFIDENCE_ORDER, SEVERITY_ORDER, formatUtc, humanize } from "../../lib/format";
import { useAsync } from "../../lib/useAsync";

function Detail({ id, chainId, onChanged }: { id: string; chainId: number; onChanged: () => void }) {
  const detail = useAsync(() => api.finding(id), [id]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [override, setOverride] = useState<FindingDetail | null>(null);

  const acknowledge = async () => {
    setBusy(true);
    setError(null);
    try {
      setOverride(await api.acknowledge(id));
      onChanged();
    } catch (cause) {
      setError(cause instanceof ApiError ? cause : null);
    } finally {
      setBusy(false);
    }
  };

  const data = override ?? detail.data;
  if (detail.loading && !data) return <Loading />;
  if (detail.error) return <ErrorView error={detail.error} onRetry={detail.run} />;
  if (!data) return null;
  const { finding, transitions } = data;
  const canAcknowledge = finding.status === "new" || finding.status === "active";
  return (
    <div className="mt-4 flex flex-col gap-4 border-t border-line pt-4">
      <p className="text-sm">{finding.explanation}</p>
      <div>
        <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">Evidence</h4>
        <ul className="flex flex-col gap-2">
          {finding.evidence.map((item, index) => (
            <li key={index} className="rounded-lg bg-surface-2 px-3 py-2 text-sm">
              <p>{item.description}</p>
              <p className="mt-1 text-xs text-muted">
                {humanize(item.kind)} · block {item.block_number.toLocaleString("en-US")}
                {item.transaction_hash && (
                  <>
                    {" · "}
                    <TxLink chainId={chainId} hash={item.transaction_hash} simulated={finding.simulated} />
                  </>
                )}
              </p>
            </li>
          ))}
        </ul>
      </div>
      <div>
        <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">History</h4>
        <ol className="flex flex-col gap-1 text-sm">
          {transitions.map((t, index) => (
            <li key={index} className="flex flex-wrap gap-x-3 text-muted">
              <span className="text-ink">
                {t.from_status ?? "—"} → {t.to_status}
              </span>
              <span>{t.reason}</span>
              <span className="text-xs text-faint">
                {t.block_number !== null ? `block ${t.block_number.toLocaleString("en-US")} · ` : ""}
                {formatUtc(t.created_at)}
              </span>
            </li>
          ))}
        </ol>
      </div>
      <p className="text-xs text-faint">
        Rule {finding.rule_id} · ruleset {finding.ruleset_version} · id <code className="break-all">{finding.finding_id}</code>
      </p>
      {error && <ErrorView error={error} />}
      {canAcknowledge && (
        <div>
          <Button onClick={acknowledge} disabled={busy}>
            {busy ? "Saving…" : "Acknowledge"}
          </Button>
          <p className="mt-1 text-xs text-faint">
            Acknowledging records that you reviewed it. It stays visible while the condition holds.
          </p>
        </div>
      )}
    </div>
  );
}

export function FindingItem({ finding, chainId, onChanged }: { finding: FindingView; chainId: number; onChanged: () => void }) {
  const [open, setOpen] = useState(false);
  return (
    <li className="py-4">
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        className="flex w-full flex-col items-start gap-2 text-left"
      >
        <span className="flex flex-wrap items-center gap-2">
          <SeverityBadges severity={finding.severity} confidence={finding.confidence} />
          <Badge>{humanize(finding.status)}</Badge>
          {finding.simulated && <SimulatedBadge simulated />}
        </span>
        <span className="text-sm font-medium">{finding.title}</span>
        <span className="text-xs text-muted">
          {humanize(finding.category)} · first seen block {finding.first_seen_block.toLocaleString("en-US")} · last
          seen block {finding.last_seen_block.toLocaleString("en-US")}
          {/* resolved_block is where the finding closed: "superseded" (the condition changed
              stage, e.g. a poisoning warning escalated) must never read as "resolved". */}
          {finding.resolved_block !== null &&
            ` · ${finding.status === "superseded" ? "superseded" : "resolved"} at block ${finding.resolved_block.toLocaleString("en-US")}`}
        </span>
      </button>
      {open && <Detail id={finding.finding_id} chainId={chainId} onChanged={onChanged} />}
    </li>
  );
}

export function FindingsPanel({ address }: { address: string }) {
  const { data: status } = useStatus();
  const [filter, setFilter] = useState<"open" | "all">("open");
  const findings = useAsync(() => api.findings(address, filter), [address, filter]);
  const sorted = [...(findings.data?.items ?? [])].sort(
    (a, b) =>
      SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
      CONFIDENCE_ORDER[a.confidence] - CONFIDENCE_ORDER[b.confidence] ||
      b.first_seen_block - a.first_seen_block,
  );
  return (
    <Card
      title="Findings"
      actions={
        <div role="group" aria-label="Filter findings" className="flex gap-1">
          {(["open", "all"] as const).map((value) => (
            <Button key={value} onClick={() => setFilter(value)} variant={filter === value ? "primary" : "secondary"}>
              {value === "open" ? "Open" : "All"}
            </Button>
          ))}
        </div>
      }
    >
      <p className="mb-2 text-sm text-muted">
        Findings come from snapshots. Severity (how much it matters if true) and confidence (how
        strong the evidence is) are shown separately.
      </p>
      {findings.loading && !findings.data && <Loading />}
      {findings.error && <ErrorView error={findings.error} onRetry={findings.run} />}
      {findings.data && sorted.length === 0 && (
        <Empty>
          {filter === "open" ? "No open findings." : "No findings yet."} Findings appear after you take a
          snapshot on the Timeline tab.
        </Empty>
      )}
      {sorted.length > 0 && (
        <ul className="divide-y divide-line">
          {sorted.map((finding) => (
            <FindingItem key={finding.finding_id} finding={finding} chainId={status?.chain_id ?? 1} onChanged={findings.run} />
          ))}
        </ul>
      )}
    </Card>
  );
}
