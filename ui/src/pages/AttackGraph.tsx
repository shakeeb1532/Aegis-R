import { SectionHeader } from "../components/SectionHeader";

type NodeStatus = "blocked" | "feasible" | "incomplete";
type EdgeStatus = "blocked" | "feasible" | "incomplete";

const nodes = [
  { id: "mal", label: "Malicious Packet", x: 70, y: 260, status: "feasible" as NodeStatus },
  { id: "waf", label: "WAF / Gateway", x: 260, y: 140, status: "blocked" as NodeStatus },
  { id: "api", label: "API Gateway", x: 260, y: 360, status: "blocked" as NodeStatus },
  { id: "app", label: "App Server", x: 540, y: 190, status: "incomplete" as NodeStatus },
  { id: "auth", label: "Auth Service", x: 540, y: 360, status: "blocked" as NodeStatus },
  { id: "db", label: "Database", x: 820, y: 260, status: "blocked" as NodeStatus },
  { id: "asset", label: "Target Asset", x: 1040, y: 260, status: "blocked" as NodeStatus }
];

const edges = [
  { from: "mal", to: "waf", label: "HTTP Flood", status: "blocked" as EdgeStatus, dashed: true },
  { from: "mal", to: "api", label: "SQL Injection", status: "blocked" as EdgeStatus, dashed: false },
  { from: "waf", to: "app", label: "Bypassed WAF", status: "incomplete" as EdgeStatus, dashed: false },
  { from: "api", to: "auth", label: "Rate Limited", status: "blocked" as EdgeStatus, dashed: false },
  { from: "app", to: "db", label: "ORM Protected", status: "blocked" as EdgeStatus, dashed: false },
  { from: "auth", to: "db", label: "Auth Required", status: "blocked" as EdgeStatus, dashed: false },
  { from: "db", to: "asset", label: "Encrypted", status: "blocked" as EdgeStatus, dashed: false }
];

const colors = {
  blocked: { stroke: "#22c55e", fill: "rgba(34,197,94,0.12)", text: "#7ee59a" },
  feasible: { stroke: "#ef4444", fill: "rgba(239,68,68,0.14)", text: "#fca5a5" },
  incomplete: { stroke: "#f59e0b", fill: "rgba(245,158,11,0.14)", text: "#fbbf24" }
};

function edgePath(from: { x: number; y: number }, to: { x: number; y: number }) {
  const dx = to.x - from.x;
  const dy = to.y - from.y;
  const cx = from.x + dx * 0.5;
  const cy = from.y + dy * 0.1;
  return `M ${from.x} ${from.y} Q ${cx} ${cy} ${to.x} ${to.y}`;
}

export function AttackGraph() {
  return (
    <div className="space-y-8">
      <section className="card-elev">
        <SectionHeader title="Attack Graph" subtitle="Causal feasibility path overlay" />
        <div className="mt-6 rounded-2xl border border-border bg-panel p-4">
          <svg viewBox="0 0 1200 520" className="h-[360px] w-full">
            <defs>
              <pattern id="dots" width="20" height="20" patternUnits="userSpaceOnUse">
                <circle cx="2" cy="2" r="1" fill="#1f2937" />
              </pattern>
            </defs>
            <rect x="0" y="0" width="1200" height="520" fill="url(#dots)" />

            {edges.map((edge) => {
              const from = nodes.find((n) => n.id === edge.from)!;
              const to = nodes.find((n) => n.id === edge.to)!;
              const color = colors[edge.status];
              return (
                <g key={`${edge.from}-${edge.to}`}>
                  <path
                    d={edgePath(from, to)}
                    fill="none"
                    stroke={color.stroke}
                    strokeWidth="2"
                    strokeDasharray={edge.dashed ? "6 6" : "0"}
                    opacity="0.9"
                  />
                  <circle cx={from.x} cy={from.y} r="5" fill={color.stroke} />
                  <circle cx={to.x} cy={to.y} r="5" fill={color.stroke} />
                  <text x={(from.x + to.x) / 2} y={(from.y + to.y) / 2 - 10} fill={color.text} fontSize="12">
                    {edge.label}
                  </text>
                </g>
              );
            })}

            {nodes.map((node) => {
              const color = colors[node.status];
              return (
                <g key={node.id}>
                  <rect
                    x={node.x - 90}
                    y={node.y - 32}
                    width="180"
                    height="64"
                    rx="12"
                    fill={color.fill}
                    stroke={color.stroke}
                    strokeWidth="2"
                  />
                  <text x={node.x} y={node.y - 6} textAnchor="middle" fontSize="13" fill="#e2e8f0">
                    {node.label}
                  </text>
                  <text x={node.x} y={node.y + 16} textAnchor="middle" fontSize="11" fill={color.text}>
                    {node.status.toUpperCase()}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>
      </section>

      <section className="grid gap-6 xl:grid-cols-[1.4fr_1fr]">
        <div className="card space-y-4">
          <SectionHeader title="Progression Timeline" subtitle="Last 24h" />
          <div className="space-y-3 text-sm text-muted">
            <div className="flex items-start gap-3">
              <span className="mt-1 h-2 w-2 rounded-full bg-teal"></span>
              09:16 UTC — Token refresh anomaly on svc-backup
            </div>
            <div className="flex items-start gap-3">
              <span className="mt-1 h-2 w-2 rounded-full bg-amber"></span>
              10:04 UTC — MFA disabled for breakglass account
            </div>
            <div className="flex items-start gap-3">
              <span className="mt-1 h-2 w-2 rounded-full bg-red"></span>
              10:22 UTC — Admin role added to svc-backup
            </div>
          </div>
        </div>
        <div className="card space-y-4">
          <SectionHeader title="Reachable Nodes" subtitle="Feasible targets" />
          <ul className="space-y-3 text-sm text-muted">
            <li className="flex items-center justify-between">
              M365 mailbox export
              <span className="badge border-teal text-teal">POSSIBLE</span>
            </li>
            <li className="flex items-center justify-between">
              Data vault access
              <span className="badge border-amber text-amber">INCOMPLETE</span>
            </li>
            <li className="flex items-center justify-between">
              Azure admin plane
              <span className="badge border-border text-muted">IMPOSSIBLE</span>
            </li>
          </ul>
        </div>
      </section>
    </div>
  );
}
