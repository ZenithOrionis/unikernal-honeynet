import { useEffect, useState } from "react";
import { api } from "../lib/api";
import type { CredentialRecord, RequestError } from "../lib/types";
import { DataTable } from "../components/DataTable";
import { SectionCard } from "../components/SectionCard";

export function CredentialsPage() {
  const [records, setRecords] = useState<CredentialRecord[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    api
      .credentials()
      .then(setRecords)
      .catch((err: RequestError) => setError(err.status === 401 ? "Unauthorized. Provide a valid analyst token." : err.message));
  }, []);

  return (
    <SectionCard title="Credential attempts" subtitle="Track attempted usernames and passwords for follow-on analysis.">
      {error ? <div className="error-panel">{error}</div> : null}
      <DataTable
        rows={records}
        emptyMessage="No credential attempts recorded."
        columns={[
          { key: "time", title: "Time", render: (row) => new Date(row.attempted_at).toLocaleString() },
          { key: "decoy", title: "Decoy", render: (row) => row.decoy_id },
          { key: "src", title: "Source IP", render: (row) => row.src_ip },
          { key: "username", title: "Username", render: (row) => row.username || "-" },
          { key: "password", title: "Password", render: (row) => row.password || "-" },
          { key: "event", title: "Event ID", render: (row) => <code>{row.event_id}</code> },
        ]}
      />
    </SectionCard>
  );
}
