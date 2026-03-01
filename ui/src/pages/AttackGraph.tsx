import { useEffect, useMemo, useRef, useState } from "react";
import { SectionHeader } from "../components/SectionHeader";
import { useGraph } from "../hooks/useApiData";
import { GraphEdge, GraphNode, ProgressionItem } from "../types";

type LayoutNode = GraphNode & { x: number; y: number };

const nodeColors: Record<string, { stroke: string; fill: string; text: string }> = {
  compromised: { stroke: "#ef4444", fill: "rgba(239,68,68,0.14)", text: "#fca5a5" },
  reachable: { stroke: "#f59e0b", fill: "rgba(245,158,11,0.14)", text: "#fbbf24" },
  observed: { stroke: "#22c55e", fill: "rgba(34,197,94,0.12)", text: "#7ee59a" }
};

const edgeColors: Record<string, string> = {
  feasible: "#ef4444",
  incomplete: "#f59e0b",
  blocked: "#22c55e"
};

function edgePath(from: { x: number; y: number }, to: { x: number; y: number }) {
  const dx = to.x - from.x;
  const dy = to.y - from.y;
  const cx = from.x + dx * 0.5;
  const cy = from.y + dy * 0.15;
  return `M ${from.x} ${from.y} Q ${cx} ${cy} ${to.x} ${to.y}`;
}

function layoutNodes(nodes: GraphNode[]) {
  const columns: Record<string, number> = {
    compromised: 220,
    reachable: 600,
    observed: 980
  };
  const hostNodes = nodes.filter((n) => n.kind === "host");
  const idNodes = nodes.filter((n) => n.kind === "identity");

  const place = (list: GraphNode[], baseY: number) => {
    const grouped: Record<string, GraphNode[]> = { compromised: [], reachable: [], observed: [] };
    list.forEach((n) => grouped[n.status]?.push(n));
    const out: LayoutNode[] = [];
    Object.entries(grouped).forEach(([status, items]) => {
      items.forEach((item, idx) => {
        out.push({
          ...item,
          x: columns[status] || 600,
          y: baseY + idx * 90
        });
      });
    });
    return out;
  };

  return [...place(hostNodes, 140), ...place(idNodes, 340)];
}

function stageTone(stage: string) {
  const s = stage.toLowerCase();
  if (s.includes("impact")) return "bg-red";
  if (s.includes("privilege") || s.includes("credential")) return "bg-amber";
  return "bg-teal";
}

function stageFill(stage: string) {
  const s = stage.toLowerCase();
  if (s.includes("impact")) return "fill-red";
  if (s.includes("privilege") || s.includes("credential")) return "fill-amber";
  return "fill-teal";
}

export function AttackGraph() {
  const graph = useGraph();
  const svgRef = useRef<SVGSVGElement | null>(null);
  const [selectedNode, setSelectedNode] = useState<LayoutNode | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<GraphEdge | null>(null);
  const [selectedProgress, setSelectedProgress] = useState<ProgressionItem | null>(null);
  const [nodes, setNodes] = useState<LayoutNode[]>([]);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [zoom, setZoom] = useState(1);
  const dragRef = useRef<{ id: string; offsetX: number; offsetY: number } | null>(null);
  const panRef = useRef<{ startX: number; startY: number; originX: number; originY: number } | null>(null);

  useEffect(() => {
    setNodes(layoutNodes(graph.nodes || []));
  }, [graph.nodes]);

  const nodeById = useMemo(() => {
    const map = new Map<string, LayoutNode>();
    nodes.forEach((n) => map.set(n.id, n));
    return map;
  }, [nodes]);

  const progression = graph.progression || [];

  const toSvgPoint = (evt: React.MouseEvent) => {
    const rect = svgRef.current?.getBoundingClientRect();
    if (!rect) return { x: 0, y: 0 };
    const x = (evt.clientX - rect.left - pan.x) / zoom;
    const y = (evt.clientY - rect.top - pan.y) / zoom;
    return { x, y };
  };

  const onWheel = (evt: React.WheelEvent) => {
    evt.preventDefault();
    const delta = evt.deltaY > 0 ? -0.08 : 0.08;
    setZoom((z) => Math.min(1.6, Math.max(0.6, z + delta)));
  };

  const onMouseDown = (evt: React.MouseEvent) => {
    const target = evt.target as HTMLElement;
    if (target.closest("[data-node]")) return;
    panRef.current = { startX: evt.clientX, startY: evt.clientY, originX: pan.x, originY: pan.y };
  };

  const onMouseMove = (evt: React.MouseEvent) => {
    if (dragRef.current) {
      const point = toSvgPoint(evt);
      setNodes((prev) =>
        prev.map((n) =>
          n.id === dragRef.current?.id
            ? {
                ...n,
                x: point.x - dragRef.current.offsetX,
                y: point.y - dragRef.current.offsetY
              }
            : n
        )
      );
      return;
    }
    if (panRef.current) {
      const dx = evt.clientX - panRef.current.startX;
      const dy = evt.clientY - panRef.current.startY;
      setPan({ x: panRef.current.originX + dx, y: panRef.current.originY + dy });
    }
  };

  const onMouseUp = () => {
    dragRef.current = null;
    panRef.current = null;
  };

  return (
    <div className="space-y-8">
      <section className="card-elev">
        <SectionHeader title="Attack Graph" subtitle="Live infrastructure reachability + decision overlay" />
        <div className="mt-6 grid gap-6 xl:grid-cols-[1.5fr_1fr]">
          <div className="rounded-2xl border border-border bg-panel p-4">
            <svg
              ref={svgRef}
              viewBox="0 0 1200 520"
              className="h-[360px] w-full"
              onWheel={onWheel}
              onMouseDown={onMouseDown}
              onMouseMove={onMouseMove}
              onMouseUp={onMouseUp}
              onMouseLeave={onMouseUp}
            >
              <defs>
                <pattern id="dots" width="20" height="20" patternUnits="userSpaceOnUse">
                  <circle cx="2" cy="2" r="1" fill="#1f2937" />
                </pattern>
              </defs>
              <rect x="0" y="0" width="1200" height="520" fill="url(#dots)" />

              <g transform={`translate(${pan.x} ${pan.y}) scale(${zoom})`}>
                {graph.edges?.map((edge) => {
                  const from = nodeById.get(edge.from);
                  const to = nodeById.get(edge.to);
                  if (!from || !to) return null;
                  const stroke = edgeColors[edge.status] || "#64748b";
                  const isActive = selectedEdge?.from === edge.from && selectedEdge?.to === edge.to;
                  return (
                    <g key={`${edge.from}-${edge.to}`} onClick={() => setSelectedEdge(edge)}>
                      <path
                        d={edgePath(from, to)}
                        fill="none"
                        stroke={stroke}
                        strokeWidth={isActive ? "3" : "2"}
                        opacity={isActive ? 1 : 0.85}
                      />
                      <text x={(from.x + to.x) / 2} y={(from.y + to.y) / 2 - 10} fill={stroke} fontSize="12">
                        {edge.label}
                      </text>
                    </g>
                  );
                })}

                {nodes.map((node) => {
                  const color = nodeColors[node.status] || nodeColors.observed;
                  const isActive = selectedNode?.id === node.id;
                  return (
                    <g
                      key={node.id}
                      data-node
                      onMouseDown={(evt) => {
                        const point = toSvgPoint(evt);
                        dragRef.current = {
                          id: node.id,
                          offsetX: point.x - node.x,
                          offsetY: point.y - node.y
                        };
                      }}
                      onClick={() => setSelectedNode(node)}
                    >
                      <rect
                        x={node.x - 90}
                        y={node.y - 30}
                        width="180"
                        height="60"
                        rx="12"
                        fill={color.fill}
                        stroke={color.stroke}
                        strokeWidth={isActive ? "3" : "2"}
                      />
                      <text x={node.x} y={node.y - 4} textAnchor="middle" fontSize="13" fill="#e2e8f0">
                        {node.label}
                      </text>
                      <text x={node.x} y={node.y + 16} textAnchor="middle" fontSize="11" fill={color.text}>
                        {node.status.toUpperCase()}
                      </text>
                    </g>
                  );
                })}
              </g>
            </svg>
          </div>

          <div className="card space-y-4">
            <SectionHeader title="Selection" subtitle="Click a node or edge" />
            {selectedNode ? (
              <div className="rounded-xl border border-border bg-panelElev p-4 text-sm text-muted">
                <div className="text-xs uppercase tracking-[0.2em] text-muted">Node</div>
                <div className="mt-2 text-base font-semibold text-text">{selectedNode.label}</div>
                <div className="mt-1 text-xs text-muted">Type: {selectedNode.kind}</div>
                <div className="mt-1 text-xs text-muted">Status: {selectedNode.status}</div>
              </div>
            ) : null}
            {selectedEdge ? (
              <div className="rounded-xl border border-border bg-panelElev p-4 text-sm text-muted">
                <div className="text-xs uppercase tracking-[0.2em] text-muted">Edge</div>
                <div className="mt-2 text-base font-semibold text-text">{selectedEdge.label}</div>
                <div className="mt-1 text-xs text-muted">
                  {selectedEdge.from} → {selectedEdge.to}
                </div>
                <div className="mt-1 text-xs text-muted">Status: {selectedEdge.status}</div>
              </div>
            ) : null}
            {!selectedNode && !selectedEdge ? (
              <div className="rounded-xl border border-border bg-panelElev p-4 text-sm text-muted">
                No selection yet. Click a node or an edge to inspect it.
              </div>
            ) : null}
          </div>
        </div>
      </section>

      <section className="grid gap-6 xl:grid-cols-[1.4fr_1fr]">
        <div className="card space-y-4">
          <SectionHeader title="Attack Progression Graph" subtitle="Ordered by observed time" />
          <div className="rounded-2xl border border-border bg-panelElev p-4">
            <svg viewBox="0 0 900 180" className="h-[180px] w-full">
              <line x1="40" y1="90" x2="860" y2="90" stroke="#233140" strokeWidth="2" />
              {progression.map((item, idx) => {
                const x = 60 + idx * 120;
                return (
                  <g key={`${item.time}-${idx}`} onClick={() => setSelectedProgress(item)}>
                    <circle cx={x} cy={90} r="12" className={stageFill(item.stage)} />
                    <text x={x} y={120} textAnchor="middle" fontSize="10" fill="#9fb3c8">
                      {item.stage || "stage"}
                    </text>
                    <text x={x} y={140} textAnchor="middle" fontSize="9" fill="#64748b">
                      {item.time.split(" ")[1] || item.time}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>

          <div className="space-y-2 text-sm text-muted">
            {progression.map((item, idx) => (
              <div
                key={`${item.time}-${idx}`}
                className="flex items-start gap-3 rounded-xl border border-border bg-panelElev px-3 py-2 text-text"
              >
                <span className={`mt-1 h-2 w-2 rounded-full ${stageTone(item.stage)}`} />
                <div>
                  <div className="text-xs uppercase text-muted">{item.stage || "progression"}</div>
                  <div className="text-sm font-semibold">{item.action || "event"}</div>
                  <div className="text-xs text-muted">
                    {item.time} · {item.principal || "unknown"} · {item.asset || "unknown"}
                  </div>
                  {item.rationale ? <div className="text-xs text-muted">{item.rationale}</div> : null}
                </div>
              </div>
            ))}
          </div>
        </div>
        <div className="card space-y-4">
          <SectionHeader title="Progression Detail" subtitle="Selected step" />
          {selectedProgress ? (
            <div className="rounded-xl border border-border bg-panelElev p-4 text-sm text-muted">
              <div className="text-xs uppercase tracking-[0.2em] text-muted">Step</div>
              <div className="mt-2 text-base font-semibold text-text">{selectedProgress.action}</div>
              <div className="mt-1 text-xs text-muted">Stage: {selectedProgress.stage}</div>
              <div className="mt-1 text-xs text-muted">Time: {selectedProgress.time}</div>
              <div className="mt-1 text-xs text-muted">
                Principal: {selectedProgress.principal || "unknown"}
              </div>
              <div className="mt-1 text-xs text-muted">Asset: {selectedProgress.asset || "unknown"}</div>
              {selectedProgress.rationale ? (
                <div className="mt-2 text-xs text-muted">{selectedProgress.rationale}</div>
              ) : null}
            </div>
          ) : (
            <div className="rounded-xl border border-border bg-panelElev p-4 text-sm text-muted">
              Click a progression node to see details.
            </div>
          )}
        </div>
      </section>
    </div>
  );
}
