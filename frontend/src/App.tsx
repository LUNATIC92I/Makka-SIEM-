import { Navigate, Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import { Spinner } from "./components/ui";
import { useAuth } from "./hooks/useAuth";
import ConnectorsPage from "./pages/Connectors";
import InvestigationDetailPage from "./pages/InvestigationDetail";
import InvestigationsPage from "./pages/Investigations";
import LoginPage from "./pages/Login";
import MapPage from "./pages/MapPage";
import OverviewPage from "./pages/Overview";
import ReportsPage from "./pages/Reports";
import SettingsPage from "./pages/Settings";
import TasksPage from "./pages/Tasks";
import ThreatIntelPage from "./pages/ThreatIntel";

export default function App() {
  const { user, ready } = useAuth();
  if (!ready) return <Spinner label="Démarrage…" />;
  if (!user) return <LoginPage />;
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<OverviewPage />} />
        <Route path="investigations" element={<InvestigationsPage />} />
        <Route path="investigations/:id" element={<InvestigationDetailPage />} />
        <Route path="map" element={<MapPage />} />
        <Route path="intel" element={<ThreatIntelPage />} />
        <Route path="reports" element={<ReportsPage />} />
        <Route path="connectors" element={<ConnectorsPage />} />
        <Route path="tasks" element={<TasksPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="*" element={<Navigate to="/" />} />
      </Route>
    </Routes>
  );
}
