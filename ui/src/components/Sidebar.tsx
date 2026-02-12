import { NavLink } from "react-router-dom";

const nav = [
  { path: "/", label: "Overview" },
  { path: "/attack-graph", label: "Attack Graph" },
  { path: "/reasoning", label: "Reasoning" },
  { path: "/queue", label: "Reasoning Queue" },
  { path: "/governance", label: "Governance" },
  { path: "/audit", label: "Audit & Evidence" },
  { path: "/evaluations", label: "Evaluations" }
];

export function Sidebar() {
  return (
    <aside className="h-screen w-64 border-r border-border bg-panel px-6 py-8">
      <div className="mb-10">
        <p className="text-xs uppercase tracking-[0.3em] text-muted">Aman</p>
        <h1 className="section-title text-2xl font-semibold">Analyst Console</h1>
      </div>
      <nav className="flex flex-col gap-2 text-sm">
        {nav.map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            end={item.path === "/"}
            className={({ isActive }) =>
              [
                "rounded-xl px-4 py-3 transition",
                isActive
                  ? "bg-panelElev text-teal shadow-glow"
                  : "text-muted hover:bg-panelElev hover:text-text"
              ].join(" ")
            }
          >
            {item.label}
          </NavLink>
        ))}
      </nav>
      <div className="mt-auto pt-12 text-xs text-muted">
        Tenant: pilot-01<br />
        Mode: Human-governed
      </div>
    </aside>
  );
}
