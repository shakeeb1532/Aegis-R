import { SectionHeader } from "../components/SectionHeader";

const nodes = [
  { id: "idp", label: "IdP", x: 40, y: 120, status: "confirmed" },
  { id: "svc", label: "svc-backup", x: 230, y: 60, status: "possible" },
  { id: "mail", label: "M365", x: 230, y: 180, status: "possible" },
  { id: "data", label: "Data Vault", x: 420, y: 120, status: "incomplete" }
];

const edges = [
  { from: "idp", to: "svc" },
  { from: "idp", to: "mail" },
  { from: "svc", to: "data" }
];

export function AttackGraph() {
  return (
    <div className="space-y-8">
      <section className="card-elev">
        <SectionHeader title="Attack Graph" subtitle="Current attacker position overlay" />
        <div className="mt-6 rounded-2xl border border-border bg-panel p-4">
          <svg viewBox="0 0 520 240" className="h-72 w-full">
            {edges.map((edge) => {
              const from = nodes.find((n) => n.id === edge.from)!;
              const to = nodes.find((n) => n.id === edge.to)!;
              return (
                <line
                  key={`${edge.from}-${edge.to}`}
                  x1={from.x}
                  y1={from.y}
                  x2={to.x}
                  y2={to.y}
                  stroke="#334155"
                  strokeWidth="2"
                />
              );
            })}
            {nodes.map((node) => (
              <g key={node.id}>
                <circle
                  cx={node.x}
                  cy={node.y}
                  r={26}
                  fill={
                    node.status === "confirmed"
                      ? "#f87171"
                      : node.status === "possible"
                      ? "#2dd4bf"
                      : "#f59e0b"
                  }
                  opacity="0.9"
                />
                <text
                  x={node.x}
                  y={node.y + 4}
                  textAnchor="middle"
                  fontSize="10"
                  fill="#0b1117"
                >
                  {node.label}
                </text>
              </g>
            ))}
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
