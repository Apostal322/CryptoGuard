import { useMemo, useState } from "react";

import { ApiError, api } from "../../api/client";
import type { GraphEdge, GraphEdgeType, GraphNode, WalletGraph } from "../../api/types";
import { Address, Badge, Button, Callout, Card, Empty, ErrorView, Limitations, Loading, SeverityBadges, SimulatedBadge, TxLink } from "../../components/ui";
import { humanize } from "../../lib/format";
import { useAsync } from "../../lib/useAsync";
import { GraphCanvas } from "./GraphCanvas";
import { EDGE_COLOR, EDGE_LABEL, NODE_COLOR, edgeTypesPresent } from "./graphStyle";

function shortName(graph: WalletGraph, id: string): string {
  if (id === graph.wallet) return "This wallet";
  const node = graph.nodes.find((n) => n.id === id);
  if (node?.label_source === "summary") return node.label ?? id;
  return node?.label ? `${node.label} (${id.slice(0, 8)}…)` : id;
}

function NodeDetail({ node, graph }: { node: GraphNode; graph: WalletGraph }) {
  return (
    <div className="flex flex-col gap-3 text-sm">
      <div className="flex flex-wrap gap-1.5">
        {node.kinds.map((kind) => (
          <Badge key={kind}>{humanize(kind)}</Badge>
        ))}
        {node.code_kind && <Badge>{humanize(node.code_kind)}</Badge>}
      </div>
      {node.address ? <Address value={node.address} /> : <p>{node.label}</p>}
      {node.label && node.label_source !== "summary" && (
        <p className="text-muted">
          Label: {node.label}{" "}
          <span className="text-xs text-faint">
            ({node.label_source === "known_contract" ? "curated known contract; not a safety verdict" : "token symbol supplied by the contract; untrusted"})
          </span>
        </p>
      )}
      {node.hidden_count !== null && (
        <p className="text-muted">
          {node.hidden_count} counterparties are summarized here. None is involved in an open finding or poisoning case.
        </p>
      )}
      {node.findings.length > 0 ? (
        <ul className="flex flex-col gap-2">
          {node.findings.map((f) => (
            <li key={f.finding_id} className="rounded-lg bg-surface-2 px-3 py-2">
              <SeverityBadges severity={f.severity} confidence={f.confidence} />
              <p className="mt-1">{f.title}</p>
              <p className="text-xs text-faint">
                {f.rule_id} · {f.status}
              </p>
            </li>
          ))}
        </ul>
      ) : (
        node.id !== graph.wallet && <p className="text-muted">No open findings concern this address.</p>
      )}
    </div>
  );
}

function EdgeDetail({ edge, graph }: { edge: GraphEdge; graph: WalletGraph }) {
  return (
    <div className="flex flex-col gap-3 text-sm">
      <div className="flex flex-wrap gap-1.5">
        <Badge tone={edge.evidence_class === "heuristic_signal" ? "review" : "info"}>
          {edge.evidence_class === "heuristic_signal" ? "Inferred (heuristic)" : "Observed fact"}
        </Badge>
        <Badge>{EDGE_LABEL[edge.type]}</Badge>
      </div>
      <p>{edge.explanation}</p>
      <p className="text-xs text-muted">
        From <span className="font-mono">{edge.source}</span> to <span className="font-mono">{edge.target}</span>
      </p>
      {edge.evidence.length > 0 && (
        <ul className="flex flex-col gap-2">
          {edge.evidence.map((item, index) => (
            <li key={index} className="rounded-lg bg-surface-2 px-3 py-2">
              <p>{item.description}</p>
              <p className="mt-1 text-xs text-muted">
                {humanize(item.kind)}
                {item.block_number !== null && ` · block ${item.block_number.toLocaleString("en-US")}`}
                {item.transaction_hash && (
                  <>
                    {" · "}
                    <TxLink chainId={graph.chain_id} hash={item.transaction_hash} simulated={graph.simulated} />
                  </>
                )}
              </p>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export function GraphView({ graph }: { graph: WalletGraph }) {
  const [hidden, setHidden] = useState<Set<GraphEdgeType>>(new Set());
  const [selected, setSelected] = useState<string | null>(null);
  const types = useMemo(() => edgeTypesPresent(graph.edges), [graph]);
  const node = graph.nodes.find((n) => n.id === selected) ?? null;
  const edge = graph.edges.find((e) => e.id === selected) ?? null;
  const visibleEdges = graph.edges.filter((e) => !hidden.has(e.type));

  const toggle = (type: GraphEdgeType) =>
    setHidden((current) => {
      const next = new Set(current);
      if (next.has(type)) next.delete(type);
      else next.add(type);
      return next;
    });

  return (
    <div className="flex flex-col gap-4">
      <fieldset className="flex flex-wrap gap-x-4 gap-y-2 text-sm">
        <legend className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted">Relationships</legend>
        {types.map((type) => (
          <label key={type} className="flex items-center gap-2">
            <input type="checkbox" checked={!hidden.has(type)} onChange={() => toggle(type)} />
            <svg width="16" height="4" aria-hidden>
              <line x1="0" y1="2" x2="16" y2="2" stroke={EDGE_COLOR[type]} strokeWidth="2" strokeDasharray={type === "RESEMBLES" ? "3 2" : undefined} />
            </svg>
            {EDGE_LABEL[type]} ({graph.edges.filter((e) => e.type === type).length})
          </label>
        ))}
      </fieldset>

      <div className="grid gap-4 lg:grid-cols-[1fr_22rem]">
        <GraphCanvas graph={graph} hiddenTypes={hidden} selectedId={selected} onSelect={setSelected} />
        <aside aria-live="polite" className="rounded-lg border border-line bg-surface p-4">
          <h3 className="mb-3 text-sm font-semibold">{node ? "Address" : edge ? "Relationship" : "Details"}</h3>
          {node && <NodeDetail node={node} graph={graph} />}
          {edge && <EdgeDetail edge={edge} graph={graph} />}
          {!node && !edge && (
            <p className="text-sm text-muted">
              Select a node or an edge, in the graph or in the list below, to see its evidence.
            </p>
          )}
        </aside>
      </div>

      <div className="flex flex-wrap gap-3 text-xs text-muted" aria-label="Node colours">
        {(Object.keys(NODE_COLOR) as (keyof typeof NODE_COLOR)[]).map((kind) => (
          <span key={kind} className="flex items-center gap-1.5">
            <svg width="10" height="10" aria-hidden>
              <circle cx="5" cy="5" r="5" fill={NODE_COLOR[kind]} />
            </svg>
            {humanize(kind)}
          </span>
        ))}
        <span>· coloured ring = open finding (amber/orange/red by severity) · dashed line = inferred</span>
      </div>

      <details open className="rounded-lg border border-line px-4 py-3">
        <summary className="cursor-pointer text-sm font-medium">All relationships as a list ({visibleEdges.length})</summary>
        <ul className="mt-3 divide-y divide-line">
          {visibleEdges.map((e) => (
            <li key={e.id}>
              <button
                type="button"
                onClick={() => setSelected(e.id)}
                aria-pressed={selected === e.id}
                className="flex w-full flex-col items-start gap-0.5 py-2 text-left text-sm hover:bg-surface-2"
              >
                <span className="flex flex-wrap items-center gap-2">
                  <Badge tone={e.evidence_class === "heuristic_signal" ? "review" : "neutral"}>{EDGE_LABEL[e.type]}</Badge>
                  <span className="break-all text-xs text-muted">
                    {shortName(graph, e.source)} → {shortName(graph, e.target)}
                  </span>
                </span>
              </button>
            </li>
          ))}
        </ul>
      </details>
    </div>
  );
}

export function GraphPanel({ address }: { address: string }) {
  const [maxNodes, setMaxNodes] = useState(60);
  const [includeInactive, setIncludeInactive] = useState(false);
  const graph = useAsync(() => api.graph(address, maxNodes, includeInactive), [address, maxNodes, includeInactive]);
  const noSnapshot = graph.error instanceof ApiError && graph.error.code === "no_snapshot";
  const data = graph.data;

  return (
    <Card
      title="Threat graph"
      actions={
        <div className="flex flex-wrap items-center gap-3 text-sm">
          <label className="flex items-center gap-2">
            Nodes
            <select
              className="rounded border border-line bg-bg px-2 py-1"
              value={maxNodes}
              onChange={(event) => setMaxNodes(Number(event.target.value))}
            >
              {[30, 60, 100, 150].map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
          </label>
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={includeInactive} onChange={(e) => setIncludeInactive(e.target.checked)} />
            Include zero allowances
          </label>
          {data && <SimulatedBadge simulated={data.simulated} />}
        </div>
      }
    >
      <p className="mb-4 text-sm text-muted">
        Relationships observed in this wallet's latest snapshot and stored transfers. Every edge
        links to its evidence; only "resembles" edges are inferred. No edge claims that an address
        is malicious.
      </p>
      {graph.loading && !data && <Loading label="Building the graph from stored observations…" />}
      {noSnapshot && <Empty>No snapshot yet. Take one on the Timeline tab; the graph is built from it.</Empty>}
      {graph.error && !noSnapshot && <ErrorView error={graph.error} onRetry={graph.run} />}
      {data && (
        <div className="flex flex-col gap-4">
          <p className="text-xs text-faint">
            Snapshot #{data.snapshot_id} at block {data.snapshot_block.toLocaleString("en-US")} · {data.nodes.length} nodes ·{" "}
            {data.edges.length} edges
          </p>
          {(data.limits.hidden_counterparties > 0 || data.limits.hidden_approvals > 0) && (
            <Callout tone="info" title="Summarized for readability">
              {data.limits.hidden_counterparties > 0 && `${data.limits.hidden_counterparties} lower-priority counterparties are grouped into one node. `}
              {data.limits.hidden_approvals > 0 && `${data.limits.hidden_approvals} lower-priority approvals are not drawn (see Permissions). `}
              Raise the node limit to show more.
            </Callout>
          )}
          {data.edges.length === 0 ? (
            <Empty>No relationships were observed in the stored data for this wallet.</Empty>
          ) : (
            <GraphView graph={data} />
          )}
          <Limitations items={data.limitations} />
          <Button className="self-start" onClick={graph.run}>
            Rebuild from latest snapshot
          </Button>
        </div>
      )}
    </Card>
  );
}
