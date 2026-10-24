import { useState } from "react";

import { ApiError, api } from "../../api/client";
import type { Change, FindingEvent, SnapshotOutcome, TimelineEntry } from "../../api/types";
import { useStatus } from "../../app/status";
import { ScanForm, type ScanOptions } from "../../components/ScanForm";
import {
  Badge,
  Button,
  Callout,
  Card,
  Empty,
  ErrorView,
  ExternalLink,
  Loading,
  SeverityBadges,
  SimulatedBadge,
  TxLink,
} from "../../components/ui";
import { formatUtc, humanize } from "../../lib/format";
import { useAsync } from "../../lib/useAsync";

export function ChangeItem({ change, chainId, simulated }: { change: Change; chainId: number; simulated: boolean }) {
  return (
    <li className="flex flex-col gap-1.5 rounded-lg border border-line bg-surface-2 px-4 py-3">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone="info">{humanize(change.kind)}</Badge>
        <span className="text-xs text-faint">
          between blocks {change.from_block_exclusive.toLocaleString("en-US")} and{" "}
          {change.to_block.toLocaleString("en-US")}
        </span>
      </div>
      <p className="text-sm">{change.explanation}</p>
      <p className="text-sm text-muted">
        <span className="font-medium text-ink">Why it matters: </span>
        {change.why_it_matters}
      </p>
      <p className="text-xs text-muted">
        <span className="font-medium text-ink">Cause: </span>
        {change.cause.kind === "approval_event" ? (
          <>
            Approval event in transaction <TxLink chainId={chainId} hash={change.cause.transaction_hash} simulated={simulated} />
          </>
        ) : (
          <>no single transaction identified — {change.cause.note}</>
        )}
      </p>
    </li>
  );
}

function FindingEventItem({ event }: { event: FindingEvent }) {
  return (
    <li className="flex flex-wrap items-center gap-2 text-sm">
      <SeverityBadges severity={event.severity} confidence={event.confidence} />
      <span>{event.title}</span>
      <span className="text-xs text-faint">
        {event.from_status ?? "—"} → {event.to_status}
      </span>
    </li>
  );
}

function Entry({ entry, chainId }: { entry: TimelineEntry; chainId: number }) {
  return (
    <li className="relative border-l border-line pb-8 pl-6 last:pb-0">
      <span className="absolute -left-[5px] top-1.5 size-2.5 rounded-full bg-accent" aria-hidden />
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="text-sm font-semibold">
          <ExternalLink href={entry.explorer_block_url}>Block {entry.block_number.toLocaleString("en-US")}</ExternalLink>
        </h3>
        <span className="text-xs text-muted">{formatUtc(entry.block_timestamp)}</span>
        {entry.is_baseline && <Badge>Baseline</Badge>}
        {entry.orphaned && <Badge tone="critical">Orphaned by reorg</Badge>}
        <SimulatedBadge simulated={entry.simulated} />
      </div>
      <p className="mt-1 text-xs text-faint">
        {entry.is_baseline
          ? "First snapshot: current conditions appear as new findings; no changes are computed."
          : `Compared with block ${entry.previous_block?.toLocaleString("en-US") ?? "?"}.`}
      </p>
      {entry.changes.length > 0 ? (
        <ul className="mt-3 flex flex-col gap-2">
          {entry.changes.map((change, index) => (
            <ChangeItem key={index} change={change} chainId={chainId} simulated={entry.simulated} />
          ))}
        </ul>
      ) : (
        !entry.is_baseline && <p className="mt-2 text-sm text-muted">No security-relevant change observed.</p>
      )}
      {entry.finding_events.length > 0 && (
        <ul className="mt-3 flex flex-col gap-1.5">
          {entry.finding_events.map((event, index) => (
            <FindingEventItem key={index} event={event} />
          ))}
        </ul>
      )}
      <details className="mt-2 text-xs text-muted">
        <summary className="cursor-pointer">Coverage</summary>
        <p className="mt-1">{entry.coverage.description}</p>
      </details>
    </li>
  );
}

function SnapshotResult({ outcome }: { outcome: SnapshotOutcome }) {
  return (
    <Callout tone={outcome.findings_not_reverified ? "warn" : "info"} title={outcome.created ? "Snapshot recorded" : "Snapshot already existed"}>
      <p>
        Block {outcome.block_number.toLocaleString("en-US")} ({outcome.lag_blocks} blocks behind the head):{" "}
        {outcome.changes.length} change(s), {outcome.finding_events.length} finding update(s).
      </p>
      {outcome.findings_not_reverified > 0 && (
        <p>{outcome.findings_not_reverified} open finding(s) could not be re-verified and were left unchanged.</p>
      )}
      {outcome.notes.map((note, index) => (
        <p key={index}>{note}</p>
      ))}
    </Callout>
  );
}

const PAGE = 20;

export function TimelinePanel({ address }: { address: string }) {
  const { data: status } = useStatus();
  const [pages, setPages] = useState(1);
  const timeline = useAsync(() => api.timeline(address, 0, PAGE * pages), [address, pages]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [outcome, setOutcome] = useState<SnapshotOutcome | null>(null);

  const snapshot = async (options: ScanOptions) => {
    setBusy(true);
    setError(null);
    try {
      setOutcome(await api.snapshot(address, options));
      await timeline.run();
    } catch (cause) {
      setError(cause instanceof ApiError ? cause : null);
    } finally {
      setBusy(false);
    }
  };

  const data = timeline.data;
  const first = !data || data.total === 0;
  const chainId = status?.chain_id ?? 1;
  return (
    <div className="flex flex-col gap-4">
      <Card title="Take a snapshot">
        <p className="mb-3 text-sm text-muted">
          Records the wallet's security state at a confirmed block and compares it with the previous
          snapshot. {first ? "The first snapshot is a baseline." : "The token scope is fixed by the first snapshot."}
        </p>
        <ScanForm
          submitLabel="Take snapshot"
          busy={busy}
          onSubmit={snapshot}
          showLookback={first}
          tokenHint={first ? "Optional; fixed for this wallet after the first snapshot." : "Leave empty to keep the existing scope."}
        />
      </Card>
      {error && <ErrorView error={error} />}
      {outcome && <SnapshotResult outcome={outcome} />}
      <Card title={data ? `Security timeline (${data.total} snapshot${data.total === 1 ? "" : "s"})` : "Security timeline"}>
        {timeline.loading && !data && <Loading />}
        {timeline.error && <ErrorView error={timeline.error} onRetry={timeline.run} />}
        {data && data.total === 0 && <Empty>No snapshots yet. Take one to start the timeline.</Empty>}
        {data && data.items.length > 0 && (
          <>
            <ol className="ml-1">
              {data.items.map((entry) => (
                <Entry key={entry.snapshot_id} entry={entry} chainId={chainId} />
              ))}
            </ol>
            {data.items.length < data.total && (
              <Button className="mt-4" onClick={() => setPages((p) => p + 1)}>
                Show older snapshots
              </Button>
            )}
          </>
        )}
      </Card>
    </div>
  );
}
