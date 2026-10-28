import { useState } from "react";

import { ApiError, api } from "../../api/client";
import type { CampaignDetail, CampaignSummary, RelatedActivity } from "../../api/types";
import { Address, Badge, Button, Callout, ErrorView, Limitations, Loading, TxLink } from "../../components/ui";
import { humanize } from "../../lib/format";
import { useAsync } from "../../lib/useAsync";

const CONFIDENCE: Record<CampaignSummary["confidence"], { label: string; tone: "info" | "review" | "neutral" }> = {
  directly_observed: { label: "Directly observed link", tone: "info" },
  strongly_supported: { label: "Strongly supported link", tone: "info" },
  tentative: { label: "Tentative grouping", tone: "review" },
  insufficient: { label: "Insufficient evidence", tone: "neutral" },
};

function Drilldown({ id, chainId }: { id: string; chainId: number }) {
  const detail = useAsync(() => api.campaign(id), [id]);
  if (detail.loading) return <Loading label="Loading evidence…" />;
  if (detail.error) return <ErrorView error={detail.error} onRetry={detail.run} />;
  const d: CampaignDetail | null = detail.data;
  if (!d) return null;
  return (
    <div className="mt-3 flex flex-col gap-3">
      <ul className="flex flex-col gap-2">
        {d.evidence.map((e) => (
          <li key={`${e.kind}:${e.key}`} className="rounded-lg bg-surface-2 px-3 py-2">
            <div className="flex flex-wrap items-center gap-1.5">
              <Badge tone={e.merges ? "info" : "neutral"}>{e.merges ? "Links these attempts" : "Context only"}</Badge>
              <Badge>{humanize(e.strength)}</Badge>
            </div>
            <p className="mt-1">{e.statement}</p>
            <Address value={e.key} />
            <p className="text-xs text-muted">
              {e.attempts} attempts on {e.wallets} wallet(s). {e.reason}
            </p>
          </li>
        ))}
      </ul>
      {d.articulation_entities.length + d.articulation_attempts.length > 0 && (
        <Callout tone="warn" title="Held together through single points">
          Removing any one of these would split the group, so attempts on either side may share nothing directly:{" "}
          {[...d.articulation_entities, ...d.articulation_attempts.map((a) => `attempt ${a.slice(0, 12)}…`)].join(", ")}.
        </Callout>
      )}
      <details className="text-sm">
        <summary className="cursor-pointer">
          Attempts ({d.members.length} of {d.members_total})
        </summary>
        <ul className="mt-2 flex flex-col gap-1 text-xs">
          {d.members.map((m) => (
            <li key={m.attempt_id} className="flex flex-col gap-0.5 border-b border-line py-1">
              <span>
                Targeted <code className="font-mono">{m.victim}</code> with lookalike{" "}
                <code className="font-mono">{m.lookalike}</code> ({humanize(m.event_type)}, block{" "}
                {m.block_number.toLocaleString("en-US")})
              </span>
              <span className="text-muted">
                {m.signer ? (
                  <>
                    signed by <code className="font-mono">{m.signer}</code> ·{" "}
                  </>
                ) : null}
                <TxLink chainId={chainId} hash={m.transaction_hash} simulated={false} />
              </span>
            </li>
          ))}
        </ul>
      </details>
    </div>
  );
}

export function RelatedActivityView({ data }: { data: RelatedActivity }) {
  const [open, setOpen] = useState<string | null>(null);
  const others = data.campaigns.filter((c) => c.targeted_wallets > 1);
  return (
    <section aria-label="Related suspicious activity" className="flex flex-col gap-3 rounded-lg border border-dashed border-line p-4 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="font-semibold">Related suspicious activity</h3>
        <Badge tone="review">Experimental · shadow mode</Badge>
      </div>
      <p>{data.statement}</p>
      <p className="text-xs text-faint">
        Analysis of {data.run.wallets_analysed} monitored wallet(s), {data.run.attempts} poisoning attempts, up to block{" "}
        {data.run.cutoff_block.toLocaleString("en-US")}. This is context for review: it does not change findings or mark any
        address as malicious.
      </p>
      <ul className="flex flex-col gap-2">
        {others.map((c) => (
          <li key={c.campaign_id} className="rounded-lg bg-surface-2 px-3 py-2">
            <div className="flex flex-wrap items-center gap-1.5">
              <Badge tone={CONFIDENCE[c.confidence].tone}>{CONFIDENCE[c.confidence].label}</Badge>
              <span className="text-xs text-muted">
                {c.attempts} attempts · {c.targeted_wallets} targeted wallets · blocks {c.first_block.toLocaleString("en-US")}–
                {c.last_block.toLocaleString("en-US")}
              </span>
            </div>
            <p className="mt-1">Potentially related poisoning activity. {c.explanation}</p>
            <Button className="mt-2" onClick={() => setOpen(open === c.campaign_id ? null : c.campaign_id)}>
              {open === c.campaign_id ? "Hide evidence" : "Show evidence"}
            </Button>
            {open === c.campaign_id && <Drilldown id={c.campaign_id} chainId={data.run.chain_id} />}
          </li>
        ))}
      </ul>
      <Limitations items={[...data.run.limitations, ...data.run.coverage]} />
    </section>
  );
}

export function RelatedActivityPanel({ address }: { address: string }) {
  const related = useAsync(() => api.relatedActivity(address), [address]);
  // Off (409) or never run (404): the section is simply absent; nothing else depends on it.
  if (related.error instanceof ApiError && ["feature_disabled", "no_campaign_run"].includes(related.error.code)) return null;
  if (related.error) return null;
  if (!related.data) return null;
  return <RelatedActivityView data={related.data} />;
}
