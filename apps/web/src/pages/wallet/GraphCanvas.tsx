import type { Core, ElementDefinition } from "cytoscape";
import { useEffect, useRef, useState } from "react";

import type { GraphEdgeType, WalletGraph } from "../../api/types";
import { COLORS, EDGE_COLOR, NODE_COLOR, findingColor, nodeLabel, radialPositions, ring } from "./graphStyle";

function elements(graph: WalletGraph): ElementDefinition[] {
  const positions = radialPositions(graph);
  const nodes: ElementDefinition[] = graph.nodes.map((node) => ({
    group: "nodes",
    position: positions[node.id] ?? { x: 0, y: 0 },
    data: {
      id: node.id,
      label: nodeLabel(node, graph.wallet),
      color: NODE_COLOR[node.kinds[0] ?? "counterparty"],
      border: findingColor(node) ?? COLORS.line,
      flagged: node.findings.length > 0 ? 1 : 0,
      ring: ring(node),
      size: node.id === graph.wallet ? 46 : node.kinds.includes("summary") ? 36 : 28,
    },
  }));
  const edges: ElementDefinition[] = graph.edges.map((edge) => ({
    group: "edges",
    data: {
      id: edge.id,
      source: edge.source,
      target: edge.target,
      type: edge.type,
      color: EDGE_COLOR[edge.type],
      dashed: edge.evidence_class === "heuristic_signal" ? 1 : 0,
    },
  }));
  return [...nodes, ...edges];
}

/**
 * Interactive canvas (zoom, pan, select). Cytoscape is loaded lazily so the main bundle
 * stays small. The canvas is not accessible by itself; GraphPanel renders the same
 * relationships as a keyboard-navigable list.
 */
export function GraphCanvas({
  graph,
  hiddenTypes,
  selectedId,
  onSelect,
}: {
  graph: WalletGraph;
  hiddenTypes: Set<GraphEdgeType>;
  selectedId: string | null;
  onSelect: (id: string | null) => void;
}) {
  const container = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<Core | null>(null);
  const onSelectRef = useRef(onSelect);
  onSelectRef.current = onSelect;
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    void import("cytoscape")
      .then(({ default: cytoscape }) => {
        if (cancelled || !container.current) return;
        const cy = cytoscape({
          container: container.current,
          elements: elements(graph),
          minZoom: 0.2,
          maxZoom: 3,
          wheelSensitivity: 0.3,
          boxSelectionEnabled: false,
          layout: { name: "preset" },
          style: [
            {
              selector: "node",
              style: {
                "background-color": "data(color)",
                "border-width": "mapData(flagged, 0, 1, 1, 3)",
                "border-color": "data(border)",
                width: "data(size)",
                height: "data(size)",
                label: "data(label)",
                color: COLORS.ink,
                "font-size": 9,
                "text-wrap": "wrap",
                "text-valign": "bottom",
                "text-margin-y": 4,
                "text-background-color": COLORS.surface,
                "text-background-opacity": 0.85,
                "text-background-padding": "2px",
              },
            },
            {
              selector: "edge",
              style: {
                width: 1.5,
                "line-color": "data(color)",
                "target-arrow-color": "data(color)",
                "target-arrow-shape": "triangle",
                "curve-style": "bezier",
                "arrow-scale": 0.8,
                opacity: 0.85,
              },
            },
            { selector: "edge[dashed = 1]", style: { "line-style": "dashed", width: 2 } },
            { selector: ":selected", style: { "border-width": 4, "border-color": COLORS.accent, "line-color": COLORS.accent, "target-arrow-color": COLORS.accent, opacity: 1 } },
            { selector: ".cg-hidden", style: { display: "none" } },
          ],
        });
        // Positions are precomputed (radialPositions); fit once the container has its real
        // size, since Cytoscape may have measured it before layout settled.
        requestAnimationFrame(() => {
          cy.resize();
          cy.fit(undefined, 32);
        });
        const observer = new ResizeObserver(() => {
          cy.resize();
          cy.fit(undefined, 32);
        });
        observer.observe(container.current);
        cy.one("destroy", () => observer.disconnect());
        cy.on("tap", (event) => {
          const target = event.target as Core | { id: () => string };
          onSelectRef.current(target === cy ? null : (target as { id: () => string }).id());
        });
        cyRef.current = cy;
      })
      .catch(() => setFailed(true));
    return () => {
      cancelled = true;
      cyRef.current?.destroy();
      cyRef.current = null;
    };
  }, [graph]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.batch(() => {
      cy.elements().removeClass("cg-hidden");
      cy.edges().forEach((edge) => {
        if (hiddenTypes.has(edge.data("type") as GraphEdgeType)) edge.addClass("cg-hidden");
      });
      cy.nodes().forEach((node) => {
        const visible = node.connectedEdges().filter((e) => !e.hasClass("cg-hidden")).length;
        if (node.id() !== graph.wallet && visible === 0) node.addClass("cg-hidden");
      });
    });
  }, [hiddenTypes, graph]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.elements().unselect();
    if (selectedId) cy.getElementById(selectedId).select();
  }, [selectedId]);

  if (failed) {
    return <p className="text-sm text-critical">The graph renderer could not be loaded; the list below shows the same data.</p>;
  }
  return (
    <div className="relative">
      <div
        ref={container}
        role="img"
        aria-label={`Relationship graph with ${graph.nodes.length} nodes and ${graph.edges.length} edges. The list below contains the same information.`}
        className="h-[28rem] w-full rounded-lg border border-line bg-bg"
      />
      <div className="absolute right-2 top-2 flex gap-1">
        <button type="button" className="rounded border border-line bg-surface-2 px-2 py-1 text-xs" onClick={() => cyRef.current?.fit(undefined, 24)}>
          Fit
        </button>
        <button type="button" className="rounded border border-line bg-surface-2 px-2 py-1 text-xs" onClick={() => cyRef.current?.zoom(cyRef.current.zoom() * 1.25)}>
          Zoom in
        </button>
        <button type="button" className="rounded border border-line bg-surface-2 px-2 py-1 text-xs" onClick={() => cyRef.current?.zoom(cyRef.current.zoom() / 1.25)}>
          Zoom out
        </button>
      </div>
    </div>
  );
}
