import { useEffect, useState } from "react";
import { api, downloadArtifact } from "../lib/api";
import type { DetectionRecord, RequestError } from "../lib/types";
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

export function DetectionsPage() {
  const [detections, setDetections] = useState<DetectionRecord[]>([]);
  const [status, setStatus] = useState("all");
  const [severity, setSeverity] = useState("all");
  const [detectionType, setDetectionType] = useState("all");
  const [site, setSite] = useState("all");
  const [srcIp, setSrcIp] = useState("");
  const [timeWindow, setTimeWindow] = useState("all");
  const [selected, setSelected] = useState<DetectionRecord | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [statusMessage, setStatusMessage] = useState("");

  async function load() {
    const params = new URLSearchParams();
    if (status !== "all") params.set("status", status);
    if (severity !== "all") params.set("severity", severity);
    if (detectionType !== "all") params.set("detection_type", detectionType);
    if (site !== "all") params.set("site", site);
    if (srcIp.trim()) params.set("src_ip", srcIp.trim());

    try {
      setLoading(true);
      const rows = await api.detections(`?${params.toString()}`);
      const filteredRows =
        timeWindow === "all"
          ? rows
          : rows.filter((row) => {
              const ageMs = Date.now() - new Date(row.last_seen_at).getTime();
              const hours = timeWindow === "24h" ? 24 : 1;
              return ageMs <= hours * 60 * 60 * 1000;
            });
      setDetections(filteredRows);
      setSelected((current) => filteredRows.find((row) => row.id === current?.id) ?? filteredRows[0] ?? null);
      setError("");
    } catch (err) {
      const requestError = err as RequestError;
      setError(requestError.status === 401 ? "Unauthorized. Provide a valid analyst token." : requestError.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, [status, severity, detectionType, site, srcIp, timeWindow]);

  async function updateSelected(nextStatus: string) {
    if (!selected) return;
    setStatusMessage(`Updating detection to ${nextStatus}...`);
    await api.updateDetection(selected.id, { status: nextStatus });
    setStatusMessage(`Detection moved to ${nextStatus}.`);
    await load();
  }

  async function exportEvidence() {
    if (!selected) return;
    setStatusMessage("Generating evidence package...");
    const artifact = await api.exportEvidence({ format: "json", detection_id: selected.id });
    const blob = await downloadArtifact(artifact.download_url);
    downloadBlob(blob, `evidence-${selected.id}.json`);
    setStatusMessage("Evidence package downloaded.");
  }

  async function exportBlocklist() {
    setStatusMessage("Generating blocklist artifact...");
    const artifact = await api.exportBlocklist("csv");
    const blob = await downloadArtifact(artifact.download_url);
    downloadBlob(blob, `blocklist-${artifact.id}.csv`);
    setStatusMessage("Blocklist artifact downloaded.");
  }

  const availableSites = Array.from(
    new Set(detections.map((row) => row.site).filter((value): value is string => Boolean(value))),
  ).sort();
  const availableTypes = Array.from(new Set(detections.map((row) => row.detection_type))).sort();

  return (
    <div className="page-grid">
      <SectionCard
        title="Detections"
        subtitle="Actionable findings with recommended containment steps."
        actions={
          <div className="filter-grid">
            <label>
              Status
              <select value={status} onChange={(event) => setStatus(event.target.value)}>
                <option value="all">All</option>
                <option value="new">New</option>
                <option value="triaging">Triaging</option>
                <option value="confirmed">Confirmed</option>
                <option value="suppressed">Suppressed</option>
                <option value="closed">Closed</option>
              </select>
            </label>
            <label>
              Severity
              <select value={severity} onChange={(event) => setSeverity(event.target.value)}>
                <option value="all">All</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </label>
            <label>
              Detection type
              <select value={detectionType} onChange={(event) => setDetectionType(event.target.value)}>
                <option value="all">All</option>
                {availableTypes.map((type) => (
                  <option key={type} value={type}>
                    {type}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Site
              <select value={site} onChange={(event) => setSite(event.target.value)}>
                <option value="all">All</option>
                {availableSites.map((siteName) => (
                  <option key={siteName} value={siteName}>
                    {siteName}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Source IP
              <input value={srcIp} onChange={(event) => setSrcIp(event.target.value)} placeholder="198.51.100.24" />
            </label>
            <label>
              Time window
              <select value={timeWindow} onChange={(event) => setTimeWindow(event.target.value)}>
                <option value="all">All time</option>
                <option value="1h">Last hour</option>
                <option value="24h">Last 24 hours</option>
              </select>
            </label>
          </div>
        }
      >
        {error ? <div className="error-panel">{error}</div> : null}
        {statusMessage ? <div className="status-inline">{statusMessage}</div> : null}
        {loading ? <div className="loading-panel">Loading detections...</div> : null}
        <DataTable
          rows={detections}
          emptyMessage="No detections available."
          columns={[
            {
              key: "severity",
              title: "Severity",
              render: (row) => (
                <Badge tone={row.severity === "critical" ? "danger" : row.severity === "high" ? "warning" : "default"}>
                  {row.severity}
                </Badge>
              ),
            },
            { key: "type", title: "Type", render: (row) => row.detection_type },
            { key: "src", title: "Source IP", render: (row) => row.src_ip ?? "-" },
            {
              key: "fleet",
              title: "Decoy / Site",
              render: (row) => (
                <div>
                  <strong>{row.decoy_id ?? "-"}</strong>
                  <div className="muted-copy">{row.site ?? "unknown site"}</div>
                </div>
              ),
            },
            { key: "confidence", title: "Confidence", render: (row) => row.confidence },
            { key: "status", title: "Status", render: (row) => row.status },
            { key: "seen", title: "First seen", render: (row) => new Date(row.first_seen_at).toLocaleString() },
            {
              key: "actions",
              title: "Actions",
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
        title="Detection detail"
        subtitle="Evidence, recommended response, and analyst actions."
        actions={
          <div className="button-row">
            <button onClick={() => updateSelected("triaging")} disabled={!selected}>
              Mark Triaging
            </button>
            <button onClick={() => updateSelected("confirmed")} disabled={!selected}>
              Confirm
            </button>
            <button onClick={() => updateSelected("suppressed")} disabled={!selected}>
              Suppress
            </button>
            <button onClick={exportEvidence} disabled={!selected}>
              Generate Evidence
            </button>
            <button onClick={exportBlocklist}>Export Blocklist</button>
          </div>
        }
      >
        {!selected ? (
          <div className="empty-inline">Select a detection to inspect details.</div>
        ) : (
          <div className="detail-grid">
            <div className="detail-card">
              <strong>{selected.title}</strong>
              <p>{selected.summary}</p>
              <div className="tag-wrap">
                <Badge tone={selected.severity === "critical" ? "danger" : selected.severity === "high" ? "warning" : "default"}>
                  {selected.severity}
                </Badge>
                <Badge>{selected.confidence}</Badge>
                <Badge>{selected.status}</Badge>
              </div>
            </div>
            <div className="detail-card">
              <strong>Recommended response</strong>
              <p>{selected.recommended_action}</p>
              <small>Block targets: {selected.recommended_block_targets.join(", ") || "none"}</small>
            </div>
            <div className="detail-card">
              <strong>Campaign context</strong>
              <p>
                {selected.occurrences} linked observations across {selected.site ?? "unknown site"}.
              </p>
              <small>
                First seen {new Date(selected.first_seen_at).toLocaleString()} | Last seen{" "}
                {new Date(selected.last_seen_at).toLocaleString()}
              </small>
            </div>
            <div className="detail-card">
              <strong>Observed credentials</strong>
              <p>
                {(selected.evidence_summary.usernames as string[] | undefined)?.length
                  ? "Credential activity observed. Values are redacted by default in the analyst console."
                  : "No credential evidence attached to this detection."}
              </p>
            </div>
            <div className="detail-card">
              <strong>Evidence summary</strong>
              <pre>{JSON.stringify(selected.evidence_summary, null, 2)}</pre>
            </div>
          </div>
        )}
      </SectionCard>
    </div>
  );
}
