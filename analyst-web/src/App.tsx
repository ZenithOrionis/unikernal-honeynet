import { Routes, Route } from "react-router-dom";
import { useEffect, useState } from "react";
import { AppShell } from "./components/AppShell";
import { OverviewPage } from "./pages/OverviewPage";
import { EventsPage } from "./pages/EventsPage";
import { CredentialsPage } from "./pages/CredentialsPage";
import { FleetPage } from "./pages/FleetPage";
import { DetectionsPage } from "./pages/DetectionsPage";
import { ExportsPage } from "./pages/ExportsPage";
import { InvestigationsPage } from "./pages/InvestigationsPage";
import { getStoredToken, setStoredToken } from "./lib/api";

export default function App() {
  const [token, setToken] = useState(getStoredToken());

  useEffect(() => {
    setStoredToken(token);
  }, [token]);

  return (
    <AppShell token={token} onTokenChange={setToken}>
      <Routes>
        <Route path="/" element={<OverviewPage />} />
        <Route path="/detections" element={<DetectionsPage />} />
        <Route path="/investigations" element={<InvestigationsPage />} />
        <Route path="/fleet" element={<FleetPage />} />
        <Route path="/exports" element={<ExportsPage />} />
        <Route path="/events" element={<EventsPage />} />
        <Route path="/credentials" element={<CredentialsPage />} />
      </Routes>
    </AppShell>
  );
}
