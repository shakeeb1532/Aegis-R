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
import { Ingestion } from "./pages/Ingestion";

export default function App() {
  return (
    <div className="flex min-h-screen bg-base text-text">
      <Sidebar />
      <div className="flex flex-1 flex-col">
        <TopBar />
        <main className="flex-1 space-y-8 bg-base px-4 py-6 md:px-6 xl:px-8">
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/attack-graph" element={<AttackGraph />} />
            <Route path="/reasoning" element={<Reasoning />} />
            <Route path="/queue" element={<Queue />} />
            <Route path="/governance" element={<Governance />} />
            <Route path="/audit" element={<Audit />} />
            <Route path="/evaluations" element={<Evaluations />} />
            <Route path="/ingestion" element={<Ingestion />} />
          </Routes>
        </main>
      </div>
      <SetupWizard />
    </div>
  );
}
