import { NavLink } from "react-router-dom";
import {
  LayoutDashboard,
  Activity,
  ShieldCheck,
  SlidersHorizontal,
  ListTodo,
  CheckCircle2,
  FileText,
  Share2,
  BarChart3,
  Shield
} from "lucide-react";

const nav = [
  { path: "/", label: "Dashboard", icon: LayoutDashboard },
  { path: "/ingestion", label: "Ingestion", icon: Activity },
  { path: "/reasoning", label: "Decisions", icon: ShieldCheck },
  { path: "/tuning", label: "Tuning", icon: SlidersHorizontal },
  { path: "/queue", label: "Queue", icon: ListTodo },
  { path: "/governance", label: "Governance", icon: CheckCircle2 },
  { path: "/audit", label: "Audit", icon: FileText },
  { path: "/attack-graph", label: "Attack Graph", icon: Share2 },
  { path: "/evaluations", label: "Evaluations", icon: BarChart3 }
];

export function Sidebar() {
  return (
    <aside className="sticky top-0 flex h-screen w-72 flex-col border-r border-border/80 bg-panel px-5 py-6">
      <div className="mb-8 flex items-center gap-3 rounded-2xl border border-border/70 bg-panelElev px-3 py-3">
        <div className="grid h-12 w-12 place-items-center rounded-xl border border-teal/30 bg-panel text-teal">
          <Shield className="h-6 w-6" />
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
            <item.icon className="h-4 w-4 opacity-80" />
            {item.label}
          </NavLink>
        ))}
      </nav>

      <div className="mt-auto space-y-3 rounded-xl border border-border/70 bg-panelElev p-3 text-xs text-muted">
        <div>
          <div className="mb-1 uppercase tracking-[0.14em]">Pilot Status</div>
          <div>Tenant: aman-pilot</div>
          <div>Mode: Human-governed</div>
        </div>
        <button
          className="w-full rounded-full border border-border px-3 py-2 text-[11px] uppercase tracking-[0.2em] text-muted"
          onClick={() => window.dispatchEvent(new CustomEvent("aman:openWizard"))}
        >
          Open Setup
        </button>
      </div>
    </aside>
  );
}
