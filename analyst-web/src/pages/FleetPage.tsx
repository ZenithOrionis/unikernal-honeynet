import { useEffect, useState } from "react";
import { api } from "../lib/api";
import type { FleetRecord, RequestError } from "../lib/types";
import { Badge } from "../components/Badge";
import { DataTable } from "../components/DataTable";
import { SectionCard } from "../components/SectionCard";

export function FleetPage() {
  const [fleet, setFleet] = useState<FleetRecord[]>([]);
  const [error, setError] = useState("");
  const [healthFilter, setHealthFilter] = useState("all");
  const [siteFilter, setSiteFilter] = useState("all");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    api
      .fleet()
      .then(setFleet)
      .catch((err: RequestError) => setError(err.status === 401 ? "Unauthorized. Provide a valid analyst token." : err.message))
      .finally(() => setLoading(false));
  }, []);

  const sites = Array.from(new Set(fleet.map((row) => row.site))).sort();
  const visibleFleet = fleet.filter((row) => {
    if (healthFilter !== "all" && row.health_status !== healthFilter) {
      return false;
    }
    if (siteFilter !== "all" && row.site !== siteFilter) {
      return false;
    }
    return true;
  });
  const silentCount = fleet.filter((row) => row.health_status === "silent").length;

  return (
    <div className="page-grid">
      <SectionCard
        title="Fleet"
        subtitle="Live sensor posture across sites, environments, and exposed endpoints."
        actions={
          <div className="filter-grid">
            <label>
              Health
              <select value={healthFilter} onChange={(event) => setHealthFilter(event.target.value)}>
                <option value="all">All</option>
                <option value="healthy">Healthy</option>
                <option value="degraded">Degraded</option>
                <option value="silent">Silent</option>
              </select>
            </label>
            <label>
              Site
              <select value={siteFilter} onChange={(event) => setSiteFilter(event.target.value)}>
                <option value="all">All</option>
                {sites.map((site) => (
                  <option key={site} value={site}>
                    {site}
                  </option>
                ))}
              </select>
            </label>
          </div>
        }
      >
        {silentCount > 0 ? (
          <div className="error-panel">
            {silentCount} fleet member{silentCount === 1 ? "" : "s"} are silent and reducing coverage right now.
          </div>
        ) : null}
        {error ? <div className="error-panel">{error}</div> : null}
        {loading ? <div className="loading-panel">Loading fleet posture...</div> : null}
        <DataTable
          rows={visibleFleet}
          emptyMessage="No fleet members available."
          columns={[
            { key: "site", title: "Site", render: (row) => row.site },
            { key: "env", title: "Environment", render: (row) => row.environment },
            { key: "public", title: "Public endpoint", render: (row) => row.public_endpoint ?? "-" },
            { key: "coverage", title: "Coverage role", render: (row) => row.coverage_role },
            {
              key: "health",
              title: "Health",
              render: (row) => (
                <div>
                  <Badge tone={row.health_status === "healthy" ? "success" : row.health_status === "silent" ? "danger" : "warning"}>
                    {row.health_status}
                  </Badge>
                  {row.health_status === "silent" ? <div className="muted-copy">Action required: sensor is silent.</div> : null}
                </div>
              ),
            },
            {
              key: "heartbeat",
              title: "Heartbeat age",
              render: (row) => (row.last_heartbeat_at ? new Date(row.last_heartbeat_at).toLocaleString() : "Never"),
            },
            {
              key: "runtime",
              title: "Runtime state",
              render: (row) => (
                <div>
                  <strong>{row.runtime_state ?? "unknown"}</strong>
                  <div className="muted-copy">{row.failure_reason ?? row.relay_health ?? "No failure reported"}</div>
                </div>
              ),
            },
            {
              key: "version",
              title: "Version",
              render: (row) => (
                <div className="muted-copy">
                  decoy {row.decoy_version}
                  <br />
                  collector {row.collector_version}
                </div>
              ),
            },
          ]}
        />
      </SectionCard>
    </div>
  );
}
