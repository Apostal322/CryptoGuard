import type { GraphEdge, GraphEdgeType, GraphNode, GraphNodeKind, Severity, WalletGraph } from "../../api/types";

// Cytoscape draws on a canvas, so colours are literal values matching the theme tokens.
export const COLORS = {
  ink: "#e6e8eb",
  muted: "#9aa3ad",
  line: "#3a414b",
  surface: "#181c22",
  accent: "#8ab4f8",
  review: "#d4a72c",
  elevated: "#f0883e",
  critical: "#f85149",
  ok: "#3fb950",
  simulated: "#c297ff",
};

export const NODE_COLOR: Record<GraphNodeKind, string> = {
  wallet: COLORS.accent,
  spender: "#7d8fd9",
  token: "#5fb3a1",
  delegation_target: "#c297ff",
  counterparty: "#6b737d",
  summary: "#3a414b",
};

export const EDGE_COLOR: Record<GraphEdgeType, string> = {
  APPROVED_SPENDER: "#7d8fd9",
  HOLDS_TOKEN: "#5fb3a1",
  DELEGATES_TO: "#c297ff",
  TRANSFERRED_TO: "#9aa3ad",
  RECEIVED_FROM: "#6b737d",
  RESEMBLES: COLORS.review,
  OTHER_COUNTERPARTIES: "#3a414b",
};

export const EDGE_LABEL: Record<GraphEdgeType, string> = {
  APPROVED_SPENDER: "Approved spender",
  HOLDS_TOKEN: "Holds token",
  DELEGATES_TO: "Delegates to (EIP-7702)",
  TRANSFERRED_TO: "Transfers from wallet",
  RECEIVED_FROM: "Transfers to wallet",
  RESEMBLES: "Resembles (inferred)",
  OTHER_COUNTERPARTIES: "Summarized counterparties",
};

const SEVERITY_RANK: Record<Severity, number> = {
  critical_evidence: 4,
  elevated_risk: 3,
  review_recommended: 2,
  unknown: 1,
  informational: 0,
};

const SEVERITY_COLOR: Partial<Record<Severity, string>> = {
  critical_evidence: COLORS.critical,
  elevated_risk: COLORS.elevated,
  review_recommended: COLORS.review,
};

/** Border colour from the most severe open finding on the node, if any. */
export function findingColor(node: GraphNode): string | null {
  const worst = [...node.findings].sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity])[0];
  return worst ? (SEVERITY_COLOR[worst.severity] ?? null) : null;
}

/** Short canvas label; the detail panel always shows the full address. */
export function nodeLabel(node: GraphNode, wallet: string): string {
  if (node.id === wallet) return "This wallet";
  if (node.label_source === "summary") return node.label ?? "Others";
  const short = node.address ? `${node.address.slice(0, 6)}…${node.address.slice(-4)}` : node.id;
  if (!node.label) return short;
  const label = node.label.length > 24 ? `${node.label.slice(0, 23)}…` : node.label;
  return `${label}\n${short}`;
}

/** Concentric ring: wallet in the centre, direct permissions next, then counterparties. */
export function ring(node: GraphNode): number {
  if (node.kinds.includes("wallet")) return 4;
  if (node.kinds.some((k) => k === "spender" || k === "delegation_target")) return 3;
  if (node.kinds.includes("token")) return 2;
  if (node.kinds.includes("summary")) return 0;
  return 1;
}

/**
 * Deterministic radial positions: wallet at the centre, permissions/tokens/delegation on an
 * inner ring, counterparties (lookalike next to the address it imitates) on an outer ring.
 * Same input, same picture, unlike force-directed layouts.
 */
export function radialPositions(graph: WalletGraph): Record<string, { x: number; y: number }> {
  const positions: Record<string, { x: number; y: number }> = { [graph.wallet]: { x: 0, y: 0 } };
  const inner = graph.nodes.filter((n) => n.id !== graph.wallet && ring(n) >= 2);
  const outerAll = graph.nodes.filter((n) => n.id !== graph.wallet && ring(n) < 2);

  // Order the outer ring so each RESEMBLES pair sits side by side.
  const outerIds = outerAll.map((n) => n.id).sort();
  const ordered: string[] = [];
  for (const edge of graph.edges) {
    if (edge.type !== "RESEMBLES") continue;
    for (const id of [edge.target, edge.source]) {
      if (outerIds.includes(id) && !ordered.includes(id)) ordered.push(id);
    }
  }
  for (const id of outerIds) if (!ordered.includes(id)) ordered.push(id);

  // Few nodes: an arc centred on ``centre`` (permissions above, transfers below). Many nodes:
  // the arc grows into a full ring.
  const place = (ids: string[], radius: number, centre: number, maxStep: number) => {
    const step = Math.min((2 * Math.PI) / Math.max(ids.length, 1), maxStep);
    const start = centre - (step * (ids.length - 1)) / 2;
    ids.forEach((id, index) => {
      const angle = start + step * index;
      positions[id] = { x: Math.round(radius * Math.cos(angle)), y: Math.round(radius * Math.sin(angle)) };
    });
  };
  const innerIds = inner.map((n) => n.id).sort();
  const r1 = Math.max(130, (innerIds.length * 80) / (2 * Math.PI));
  const r2 = Math.max(r1 + 110, (ordered.length * 70) / (2 * Math.PI));
  place(innerIds, r1, -Math.PI / 2, 0.75);
  place(ordered, r2, Math.PI / 2, 0.45);
  return positions;
}

export function edgeTypesPresent(edges: GraphEdge[]): GraphEdgeType[] {
  const order = Object.keys(EDGE_LABEL) as GraphEdgeType[];
  const present = new Set(edges.map((e) => e.type));
  return order.filter((t) => present.has(t));
}
