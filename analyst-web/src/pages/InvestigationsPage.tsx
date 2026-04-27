import { useEffect, useState } from "react";
import { api, downloadArtifact } from "../lib/api";
import type { InvestigationRecord, RequestError } from "../lib/types";
import { Badge } from "../components/Badge";
import { DataTable } from "../components/DataTable";
import { SectionCard } from "../components/SectionCard";

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

export function InvestigationsPage() {
  const [investigations, setInvestigations] = useState<InvestigationRecord[]>([]);
  const [selected, setSelected] = useState<InvestigationRecord | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [statusMessage, setStatusMessage] = useState("");

  useEffect(() => {
    setLoading(true);
    api
      .investigations()
      .then((rows) => {
        setInvestigations(rows);
        setSelected(rows[0] ?? null);
      })
      .catch((err: RequestError) => setError(err.status === 401 ? "Unauthorized. Provide a valid analyst token." : err.message))
      .finally(() => setLoading(false));
  }, []);

  async function exportEvidence() {
    if (!selected) return;
    setStatusMessage("Generating investigation evidence package...");
    const artifact = await api.exportEvidence({ format: "json", investigation_id: selected.id });
    const blob = await downloadArtifact(artifact.download_url);
    downloadBlob(blob, `investigation-${selected.id}.json`);
    setStatusMessage("Investigation evidence package downloaded.");
  }

  return (
    <div className="page-grid">
      <SectionCard title="Investigations" subtitle="Grouped activity by source or campaign fingerprint.">
        {error ? <div className="error-panel">{error}</div> : null}
        {statusMessage ? <div className="status-inline">{statusMessage}</div> : null}
        {loading ? <div className="loading-panel">Loading investigations...</div> : null}
        <DataTable
          rows={investigations}
          emptyMessage="No investigations available."
          columns={[
            {
              key: "fingerprint",
              title: "Fingerprint",
              render: (row) => (
                <div>
                  <strong>{row.fingerprint}</strong>
                  <div className="muted-copy">{row.status}</div>
                </div>
              ),
            },
            { key: "spread", title: "Decoy spread", render: (row) => row.decoy_spread },
            { key: "count", title: "Detections", render: (row) => row.detection_count },
            {
              key: "class",
              title: "Activity class",
              render: (row) => (
                <Badge tone={row.activity_class === "targeted" ? "danger" : row.activity_class === "opportunistic" ? "warning" : "default"}>
                  {row.activity_class}
                </Badge>
              ),
            },
            { key: "first", title: "First seen", render: (row) => new Date(row.first_seen).toLocaleString() },
            { key: "last", title: "Last seen", render: (row) => new Date(row.last_seen).toLocaleString() },
            {
              key: "open",
              title: "Action",
              render: (row) => (
                <button onClick={() => setSelected(row)} className={selected?.id === row.id ? "active" : ""}>
                  Open
                </button>
              ),
            },
          ]}
        />
      </SectionCard>

      <SectionCard
        title="Investigation detail"
        subtitle="Triage context for grouped activity before export or escalation."
        actions={
          <div className="button-row">
            <button disabled={!selected} onClick={exportEvidence}>
              Generate Evidence
            </button>
          </div>
        }
      >
        {!selected ? (
          <div className="empty-inline">Select an investigation to inspect grouped activity.</div>
        ) : (
          <div className="detail-grid">
            <div className="detail-card">
              <strong>{selected.fingerprint}</strong>
              <p>
                {selected.detection_count} detections across {selected.decoy_spread} decoys.
              </p>
              <div className="tag-wrap">
                <Badge tone={selected.activity_class === "targeted" ? "danger" : selected.activity_class === "opportunistic" ? "warning" : "default"}>
                  {selected.activity_class}
                </Badge>
                <Badge>{selected.status}</Badge>
              </div>
            </div>
            <div className="detail-card">
              <strong>Analyst readout</strong>
              <p>
                {selected.activity_class === "targeted"
                  ? "Spread and recurrence indicate a more deliberate campaign shape."
                  : selected.activity_class === "opportunistic"
                    ? "Activity looks broad and shallow, consistent with internet-wide scanning."
                    : "The activity needs more context before it can be confidently classified."}
              </p>
            </div>
            <div className="detail-card">
              <strong>Timeline</strong>
              <small>
                First seen {new Date(selected.first_seen).toLocaleString()} | Last seen{" "}
                {new Date(selected.last_seen).toLocaleString()}
              </small>
            </div>
            <div className="detail-card">
              <strong>Analyst notes</strong>
              <p>{selected.analyst_notes || "No notes recorded yet for this investigation."}</p>
            </div>
          </div>
        )}
      </SectionCard>
    </div>
  );
}
