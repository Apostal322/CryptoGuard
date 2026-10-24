import { useRef, type KeyboardEvent } from "react";
import { useParams, useSearchParams } from "react-router-dom";

import { useStatus } from "../../app/status";
import { Address, Callout, ExternalLink } from "../../components/ui";
import { explorerAddressUrl } from "../../lib/explorer";
import { looksLikeAddress } from "../../lib/format";
import { ApprovalsPanel } from "./ApprovalsPanel";
import { FindingsPanel } from "./FindingsPanel";
import { OverviewPanel } from "./OverviewPanel";
import { PoisoningPanel } from "./PoisoningPanel";
import { TimelinePanel } from "./TimelinePanel";

const TABS = [
  { id: "overview", label: "Overview" },
  { id: "approvals", label: "Permissions" },
  { id: "timeline", label: "Timeline" },
  { id: "findings", label: "Findings" },
  { id: "poisoning", label: "Address poisoning" },
] as const;
type TabId = (typeof TABS)[number]["id"];

export function WalletPage() {
  const { address = "" } = useParams();
  const [params, setParams] = useSearchParams();
  const { data: status } = useStatus();
  const tabRefs = useRef<(HTMLButtonElement | null)[]>([]);
  const active: TabId = TABS.some((t) => t.id === params.get("tab")) ? (params.get("tab") as TabId) : "overview";

  if (!looksLikeAddress(address)) {
    return <Callout tone="error" title="Not an address">The URL does not contain a valid Ethereum address.</Callout>;
  }

  const select = (id: TabId) => setParams({ tab: id }, { replace: true });
  const onKey = (event: KeyboardEvent, index: number) => {
    const delta = event.key === "ArrowRight" ? 1 : event.key === "ArrowLeft" ? -1 : 0;
    if (!delta) return;
    event.preventDefault();
    const next = (index + delta + TABS.length) % TABS.length;
    select(TABS[next]!.id);
    tabRefs.current[next]?.focus();
  };
  const real = status?.mode === "real";
  const chainId = status?.chain_id ?? 1;

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-col gap-1">
        <p className="text-xs uppercase tracking-wide text-muted">Wallet</p>
        <h1 className="text-lg font-semibold">
          <Address value={address} />
        </h1>
        {real && (
          <p className="text-sm">
            <ExternalLink href={explorerAddressUrl(chainId, address)}>View on block explorer</ExternalLink>
          </p>
        )}
      </div>

      <div role="tablist" aria-label="Wallet views" className="flex gap-1 overflow-x-auto border-b border-line">
        {TABS.map((tab, index) => (
          <button
            key={tab.id}
            ref={(element) => {
              tabRefs.current[index] = element;
            }}
            role="tab"
            id={`tab-${tab.id}`}
            aria-selected={active === tab.id}
            aria-controls={`panel-${tab.id}`}
            tabIndex={active === tab.id ? 0 : -1}
            onClick={() => select(tab.id)}
            onKeyDown={(event) => onKey(event, index)}
            className={`-mb-px whitespace-nowrap border-b-2 px-3 py-2 text-sm ${
              active === tab.id ? "border-accent text-ink" : "border-transparent text-muted hover:text-ink"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      <div role="tabpanel" id={`panel-${active}`} aria-labelledby={`tab-${active}`}>
        {active === "overview" && <OverviewPanel address={address} />}
        {active === "approvals" && <ApprovalsPanel address={address} />}
        {active === "timeline" && <TimelinePanel address={address} />}
        {active === "findings" && <FindingsPanel address={address} />}
        {active === "poisoning" && <PoisoningPanel address={address} />}
      </div>
    </div>
  );
}
