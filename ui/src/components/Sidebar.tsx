import { NavLink } from "react-router-dom";

const nav = [
  { path: "/", label: "Dashboard", icon: "▦" },
  { path: "/ingestion", label: "Ingestion", icon: "⬌" },
  { path: "/reasoning", label: "Decisions", icon: "◌" },
  { path: "/tuning", label: "Tuning", icon: "⛭" },
  { path: "/queue", label: "Queue", icon: "◍" },
  { path: "/governance", label: "Governance", icon: "✶" },
  { path: "/audit", label: "Audit", icon: "◫" },
  { path: "/attack-graph", label: "Attack Graph", icon: "◉" },
  { path: "/evaluations", label: "Evaluations", icon: "◈" }
];

export function Sidebar() {
  return (
    <aside className="sticky top-0 flex h-screen w-72 flex-col border-r border-border/80 bg-panel px-5 py-6">
      <div className="mb-8 flex items-center gap-3 rounded-2xl border border-border/70 bg-panelElev px-3 py-3">
        <div className="grid h-12 w-12 place-items-center rounded-xl border border-teal/30 bg-panel text-lg text-teal">
          ⛨
        </div>
        <div>
          <p className="section-title text-xl font-semibold tracking-wide">AMAN</p>
          <p className="text-xs uppercase tracking-[0.2em] text-muted">Security Governance</p>
        </div>
      </div>

      <p className="mb-3 px-2 text-xs uppercase tracking-[0.2em] text-muted">Navigation</p>
      <nav className="flex flex-col gap-1.5 text-base">
        {nav.map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            end={item.path === "/"}
            className={({ isActive }) =>
              [
                "group flex items-center gap-3 rounded-xl px-4 py-3 transition",
                isActive
                  ? "border border-[#1f4f73] bg-[#0d2234] text-[#34c9ff] shadow-glow"
                  : "border border-transparent text-muted hover:border-border/60 hover:bg-panelElev hover:text-text"
              ].join(" ")
            }
          >
            <span className="text-sm opacity-80">{item.icon}</span>
            {item.label}
          </NavLink>
        ))}
      </nav>

      <div className="mt-auto rounded-xl border border-border/70 bg-panelElev p-3 text-xs text-muted">
        <div className="mb-1 uppercase tracking-[0.14em]">Pilot Status</div>
        <div>Tenant: aman-pilot</div>
        <div>Mode: Human-governed</div>
      </div>
    </aside>
  );
}
