import { Routes, Route } from "react-router-dom";
import { Sidebar } from "./components/Sidebar";
import { TopBar } from "./components/TopBar";
import { SetupWizard } from "./components/SetupWizard";
import { Overview } from "./pages/Overview";
import { AttackGraph } from "./pages/AttackGraph";
import { Reasoning } from "./pages/Reasoning";
import { Queue } from "./pages/Queue";
import { Governance } from "./pages/Governance";
import { Audit } from "./pages/Audit";
import { Evaluations } from "./pages/Evaluations";

export default function App() {
  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <div className="flex flex-1 flex-col">
        <TopBar />
        <main className="flex-1 space-y-8 bg-base px-8 py-8">
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/attack-graph" element={<AttackGraph />} />
            <Route path="/reasoning" element={<Reasoning />} />
            <Route path="/queue" element={<Queue />} />
            <Route path="/governance" element={<Governance />} />
            <Route path="/audit" element={<Audit />} />
            <Route path="/evaluations" element={<Evaluations />} />
          </Routes>
        </main>
      </div>
      <SetupWizard />
    </div>
  );
}
