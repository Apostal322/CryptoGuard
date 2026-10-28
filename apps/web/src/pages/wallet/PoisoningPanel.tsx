import { useState } from "react";

import { ApiError, api } from "../../api/client";
import type { PoisoningCase, PoisoningReport } from "../../api/types";
import { ScanForm, type ScanOptions } from "../../components/ScanForm";
import { RelatedActivityPanel } from "./RelatedActivity";
import {
  Badge,
  Callout,
  Card,
  Empty,
  ErrorView,
  Limitations,
  SeverityBadges,
  SimulatedBadge,
  TxLink,
} from "../../components/ui";
import { humanize } from "../../lib/format";

/** Full address with the characters it shares with the imitated address highlighted. */
export function AffixAddress({ address, prefix, suffix }: { address: string; prefix: number; suffix: number }) {
  const body = address.slice(2);
  const head = body.slice(0, prefix);
  const tail = suffix > 0 ? body.slice(body.length - suffix) : "";
  const middle = body.slice(prefix, body.length - suffix);
  return (
    <code className="break-all font-mono text-[0.8125rem]" aria-label={address}>
      0x<mark className="rounded-sm bg-review/25 text-ink">{head}</mark>
      <span className="text-muted">{middle}</span>
      <mark className="rounded-sm bg-review/25 text-ink">{tail}</mark>
    </code>
  );
}

export function CaseCard({ item, report }: { item: PoisoningCase; report: PoisoningReport }) {
  return (
    <li className="flex flex-col gap-3 rounded-lg border border-line bg-surface-2 p-4">
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadges severity={item.severity} confidence={item.confidence} />
        <Badge>{item.rule_id}</Badge>
      </div>
      <div className="grid gap-2 text-sm">
        <div>
          <p className="text-xs text-muted">Suspected lookalike</p>
          <AffixAddress address={item.suspect} prefix={item.prefix_match} suffix={item.suffix_match} />
        </div>
        <div>
          <p className="text-xs text-muted">
            Imitates (paid at block {item.reference_first_used_block.toLocaleString("en-US")}
            {item.reference_confirmed ? ", signed by this wallet" : ", signer unverified"})
          </p>
          <AffixAddress address={item.reference} prefix={item.prefix_match} suffix={item.suffix_match} />
        </div>
        <p className="text-xs text-muted">
          Shares the first {item.prefix_match} and last {item.suffix_match} hex characters. A random
          address matches this closely with odds of about {item.random_match_odds}.
        </p>
      </div>
      <p className="text-sm">{item.explanation}</p>
      <ul className="flex flex-col gap-1.5">
        {item.signals.map((signal, index) => (
          <li key={index} className="text-sm">
            <span className="font-medium">{humanize(signal.code)}</span>{" "}
            <span className="text-muted">{signal.description}</span>
            {signal.transaction_hash && (
              <span className="block text-xs">
                <TxLink chainId={report.chain_id} hash={signal.transaction_hash} simulated={report.simulated} />
              </span>
            )}
          </li>
        ))}
      </ul>
      <Callout title="Before you send">{item.recommended_action}</Callout>
    </li>
  );
}

export function PoisoningPanel({ address }: { address: string }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [report, setReport] = useState<PoisoningReport | null>(null);

  const scan = async (options: ScanOptions) => {
    setBusy(true);
    setError(null);
    try {
      setReport(await api.poisoningScan(address, options));
    } catch (cause) {
      setError(cause instanceof ApiError ? cause : null);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <Card title="Address-poisoning check">
        <p className="mb-3 text-sm text-muted">
          Looks for addresses in this wallet's recent ERC-20 transfers that imitate addresses it paid (in tokens or ETH),
          for example planted with zero-value transfers. Nothing is stored; snapshots run the same
          check continuously.
        </p>
        <ScanForm submitLabel="Check for poisoning" busy={busy} onSubmit={scan} />
      </Card>
      {error && <ErrorView error={error} />}
      {report && (
        <Card
          title={`${report.cases.length} case${report.cases.length === 1 ? "" : "s"} in ${report.transfers_analyzed} transfer${report.transfers_analyzed === 1 ? "" : "s"}`}
          actions={<SimulatedBadge simulated={report.simulated} />}
        >
          <div className="flex flex-col gap-4">
            <p className="text-xs text-faint">
              Includes {report.wallet_transactions_located} transaction(s) the wallet signed itself
              (native-ETH payments count as references)
              {report.wallet_transactions_unlocated === null
                ? "; the wallet's own transactions could not be checked on this provider"
                : report.wallet_transactions_unlocated > 0
                  ? `; ${report.wallet_transactions_unlocated} could not be located`
                  : ""}
              .
            </p>
            {!report.complete_for_requested_range && (
              <Callout tone="warn" title="Partial coverage">
                The request budget ended the scan early; older transfers were not analyzed.
              </Callout>
            )}
            {report.cases.length === 0 ? (
              <Empty>
                No lookalike addresses were found in blocks {report.scanned_from_block.toLocaleString("en-US")} to{" "}
                {report.block_number.toLocaleString("en-US")}. This does not cover earlier history or native ETH transfers.
              </Empty>
            ) : (
              <ul className="flex flex-col gap-3">
                {report.cases.map((item) => (
                  <CaseCard key={item.suspect} item={item} report={report} />
                ))}
              </ul>
            )}
            <Limitations items={report.limitations} />
          </div>
        </Card>
      )}
      <RelatedActivityPanel address={address} />
    </div>
  );
}
