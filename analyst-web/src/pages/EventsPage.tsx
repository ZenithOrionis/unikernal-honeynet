import { useEffect, useState } from "react";
import { api } from "../lib/api";
import type { EventRecord, RequestError } from "../lib/types";
import { Badge } from "../components/Badge";
import { DataTable } from "../components/DataTable";
import { SectionCard } from "../components/SectionCard";

export function EventsPage() {
  const [events, setEvents] = useState<EventRecord[]>([]);
  const [filter, setFilter] = useState("all");
  const [error, setError] = useState("");

  useEffect(() => {
    const query = filter === "all" ? "" : `?suspicious=${filter === "suspicious"}`;
    api
      .events(query)
      .then(setEvents)
      .catch((err: RequestError) => setError(err.status === 401 ? "Unauthorized. Provide a valid analyst token." : err.message));
  }, [filter]);

  return (
    <SectionCard
      title="Events"
      subtitle="Secondary drill-down view for raw decoy activity and evidence inspection."
      actions={
        <div className="button-row">
          <button className={filter === "all" ? "active" : ""} onClick={() => setFilter("all")}>
            All
          </button>
          <button className={filter === "suspicious" ? "active" : ""} onClick={() => setFilter("suspicious")}>
            Suspicious
          </button>
          <button className={filter === "normal" ? "active" : ""} onClick={() => setFilter("normal")}>
            Normal
          </button>
        </div>
      }
    >
      {error ? <div className="error-panel">{error}</div> : null}
      <DataTable
        rows={events}
        emptyMessage="No events available."
        columns={[
          { key: "time", title: "Time", render: (row) => new Date(row.occurred_at).toLocaleString() },
          {
            key: "decoy",
            title: "Decoy",
            render: (row) => (
              <div>
                <strong>{row.decoy_id}</strong>
                <div className="muted-copy">
                  {row.profile} | {row.site}
                </div>
              </div>
            ),
          },
          {
            key: "request",
            title: "Request",
            render: (row) => (
              <div>
                <strong>
                  {row.method} {row.path}
                </strong>
                <div className="muted-copy">
                  {row.src_ip} | {row.status_code || "n/a"} | {row.latency_ms}ms
                </div>
              </div>
            ),
          },
          {
            key: "class",
            title: "Class",
            render: (row) => <Badge tone={row.suspicious ? "warning" : "default"}>{row.event_class}</Badge>,
          },
          {
            key: "tags",
            title: "Tags",
            render: (row) => (
              <div className="tag-wrap">
                {row.normalized_tags.map((tag) => (
                  <Badge key={tag} tone={row.suspicious ? "danger" : "default"}>
                    {tag}
                  </Badge>
                ))}
              </div>
            ),
          },
        ]}
      />
    </SectionCard>
  );
}
