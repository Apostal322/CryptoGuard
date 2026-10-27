import { api } from "../../api/client";
import type { AnalysisPathStep, WalletAnalysis } from "../../api/types";
import { Address, Badge, Callout, Limitations, TxLink } from "../../components/ui";
import { humanize } from "../../lib/format";
import { useAsync } from "../../lib/useAsync";

const RELATION: Record<AnalysisPathStep["relation"], string> = {
  transfer: "token transfer",
  native_transfer: "ETH payment",
  caused: "signed the transaction behind a transfer to",
  token_use: "used token contract",
};

function sectionNote(status: string): string | null {
  if (status === "insufficient_data") return "Not enough observed data to say anything here.";
  if (status === "unavailable") return "The server lacks the optional analytics dependencies.";
  if (status === "skipped") return "Skipped: the observed graph exceeds the configured size budget.";
  return null;
}

export function ExperimentalContextView({ analysis }: { analysis: WalletAnalysis }) {
  const { network, activity, structure } = analysis;
  if ([network, activity, structure].every((s) => s.status === "disabled")) return null;
  return (
    <section aria-label="Experimental context" className="flex flex-col gap-3 rounded-lg border border-dashed border-line p-4 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="font-semibold">Additional context</h3>
        <Badge tone="review">Experimental · shadow mode</Badge>
      </div>
      <p className="text-muted">
        Computed from stored observations up to block {analysis.cutoff_block.toLocaleString("en-US")}. These are
        context for review, not findings: they never change severities or alerts.
      </p>

      {network.status !== "disabled" && (
        <div className="flex flex-col gap-2">
          <h4 className="font-medium">Network relationships</h4>
          {sectionNote(network.status) && <p className="text-muted">{sectionNote(network.status)}</p>}
          {network.notes.map((n) => (
            <p key={n} className="text-xs text-faint">
              {n}
            </p>
          ))}
          {network.statement && <Callout tone="info">{network.statement}</Callout>}
          <ul className="flex flex-col gap-2">
            {network.related.map((r) => (
              <li key={r.address} className="rounded-lg bg-surface-2 px-3 py-2">
                <div className="flex flex-wrap items-center gap-1.5">
                  {r.roles.map((role) => (
                    <Badge key={role}>{humanize(role)}</Badge>
                  ))}
                  <span className="text-xs text-muted">{r.hops === 1 ? "directly linked" : `${r.hops} links away`}</span>
                </div>
                <Address value={r.address} />
                <ol className="mt-1 flex flex-col gap-0.5 text-xs text-muted">
                  {r.path.map((step, i) => (
                    <li key={i}>
                      <span className="font-mono">{step.source.slice(0, 10)}…</span> {RELATION[step.relation]}{" "}
                      <span className="font-mono">{step.target.slice(0, 10)}…</span> ({step.events} event
                      {step.events === 1 ? "" : "s"}
                      {step.example_block !== null && `, e.g. block ${step.example_block.toLocaleString("en-US")}`})
                      {step.example_transaction && (
                        <>
                          {" "}
                          <TxLink chainId={analysis.chain_id} hash={step.example_transaction} simulated={analysis.simulated} />
                        </>
                      )}
                    </li>
                  ))}
                </ol>
              </li>
            ))}
          </ul>
        </div>
      )}

      {activity.status !== "disabled" && (
        <div className="flex flex-col gap-2">
          <h4 className="font-medium">Activity compared with this wallet's history</h4>
          {sectionNote(activity.status) && <p className="text-muted">{sectionNote(activity.status)}</p>}
          {activity.statement && <p>{activity.statement}</p>}
          <ul className="flex flex-col gap-2">
            {activity.anomalies.map((a) => (
              <li key={`${a.series}-${a.from_block}`} className="rounded-lg bg-surface-2 px-3 py-2">
                <p>{a.statement}</p>
                <p className="text-xs text-muted">
                  Blocks {a.from_block.toLocaleString("en-US")}–{a.to_block.toLocaleString("en-US")}: {a.observed} observed,
                  about {a.expected} expected from {a.history_bins} earlier windows.
                </p>
                <ul className="mt-1 flex flex-col gap-0.5">
                  {a.transactions.slice(0, 3).map((tx) => (
                    <li key={tx}>
                      <TxLink chainId={analysis.chain_id} hash={tx} simulated={analysis.simulated} />
                    </li>
                  ))}
                </ul>
              </li>
            ))}
          </ul>
          {activity.notes.map((n) => (
            <p key={n} className="text-xs text-faint">
              {n}
            </p>
          ))}
        </div>
      )}

      {structure.status !== "disabled" && (
        <details className="text-xs text-muted">
          <summary className="cursor-pointer">Engineering details (graph structure)</summary>
          <dl className="mt-2 grid grid-cols-2 gap-x-4 gap-y-1">
            {Object.entries(structure.features).map(([k, v]) => (
              <div key={k} className="contents">
                <dt>{humanize(k)}</dt>
                <dd className="font-mono">{v === null ? "n/a" : String(v)}</dd>
              </div>
            ))}
          </dl>
          {structure.notes.map((n) => (
            <p key={n} className="mt-1">
              {n}
            </p>
          ))}
        </details>
      )}

      <Limitations items={[...analysis.coverage, ...analysis.notes]} />
    </section>
  );
}

export function ExperimentalContext({ address }: { address: string }) {
  const analysis = useAsync(() => api.analysis(address), [address]);
  // Optional enrichment: when it is off or fails, the rest of the page is unaffected.
  if (!analysis.data) return null;
  return <ExperimentalContextView analysis={analysis.data} />;
}
