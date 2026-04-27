import { useEffect, useState } from "react";
import { api } from "../lib/api";
import type { CoverageSummary, FleetRecord, Posture, RequestError } from "../lib/types";
import { SectionCard } from "../components/SectionCard";
import { StatCard } from "../components/StatCard";
import { TrendBars } from "../components/TrendBars";
import { Badge } from "../components/Badge";

export function OverviewPage() {
  const [posture, setPosture] = useState<Posture | null>(null);
  const [coverage, setCoverage] = useState<CoverageSummary | null>(null);
  const [fleet, setFleet] = useState<FleetRecord[]>([]);
  const [error, setError] = useState("");
  const [warning, setWarning] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    Promise.allSettled([api.posture(), api.fleetCoverage(), api.fleet()]).then((results) => {
      const [postureResult, coverageResult, fleetResult] = results;

      if (postureResult.status === "fulfilled") {
        setPosture(postureResult.value);
      } else {
        const err = postureResult.reason as RequestError;
        setError(err.status === 401 ? "Unauthorized. Provide a valid analyst token." : err.message);
      }

      if (coverageResult.status === "fulfilled") {
        setCoverage(coverageResult.value);
      } else {
        setWarning("Coverage details are partially unavailable. Core posture still reflects live detections.");
      }

      if (fleetResult.status === "fulfilled") {
        setFleet(fleetResult.value);
      } else {
        setWarning((current) => current || "Fleet detail is partially unavailable. Refresh after the API recovers.");
      }

      setLoading(false);
    });
  }, []);

  if (error) {
    return <div className="error-panel">{error}</div>;
  }

  if (loading || !posture) {
    return <div className="loading-panel">Loading exposure and detection posture...</div>;
  }

  const unhealthyFleet = fleet.filter((item) => item.health_status !== "healthy");
  const coverageGaps = coverage?.coverage_gaps ?? posture.coverage_gaps;

  return (
    <div className="page-grid">
      <section className="hero-panel">
        <div>
          <span className="eyebrow">Exposure + Detection Posture</span>
          <h2>What needs action now</h2>
          <p>
            Track exposed decoys, silent sensors, detections that need analyst action, and the
            sources most likely to deserve fast containment.
          </p>
        </div>
      </section>

      {warning ? <div className="loading-panel">{warning}</div> : null}

      <section className="stat-grid">
        <StatCard label="Active decoys" value={posture.active_decoys} delta={`${posture.fleet_total} total`} />
        <StatCard label="Fleet unhealthy" value={posture.fleet_unhealthy} delta={`${posture.silent_decoys} silent`} />
        <StatCard label="Detections new" value={posture.detections_new} />
        <StatCard label="In triage" value={posture.detections_in_triage} />
        <StatCard label="Exposed endpoints" value={posture.exposed_endpoints} />
        <StatCard label="Recommended blocks" value={posture.recommended_blocks.length} />
      </section>

      <div className="panel-grid">
        <SectionCard title="Severity load" subtitle="Current action load by severity.">
          <TrendBars
            items={[
              { label: "Critical", value: posture.critical_detections },
              { label: "High", value: posture.high_detections },
              { label: "Medium", value: posture.medium_detections },
            ]}
          />
        </SectionCard>

        <SectionCard title="Top sources" subtitle="Most active sources across the deception fleet.">
          <TrendBars items={posture.top_sources.map((item) => ({ label: item.src_ip, value: item.hits }))} />
        </SectionCard>

        <SectionCard title="Coverage gaps" subtitle="Expected fleet members or sites currently under-covered.">
          {coverageGaps.length === 0 ? (
            <div className="empty-inline">No current coverage gaps.</div>
          ) : (
            <div className="tag-wrap">
              {coverageGaps.map((site) => (
                <Badge key={site} tone="warning">
                  {site}
                </Badge>
              ))}
            </div>
          )}
        </SectionCard>

        <SectionCard title="24-hour delta" subtitle="Recent activity change across core analyst signals.">
          <TrendBars
            items={[
              { label: "Events", value: posture.changes_last_24h.events },
              { label: "Detections", value: posture.changes_last_24h.detections },
              { label: "Credentials", value: posture.changes_last_24h.credentials },
            ]}
          />
        </SectionCard>

        <SectionCard title="Recommended blocks" subtitle="Sources most ready for containment actions.">
          {posture.recommended_blocks.length === 0 ? (
            <div className="empty-inline">No immediate block recommendations.</div>
          ) : (
            <div className="stack-list">
              {posture.recommended_blocks.map((source) => (
                <article key={source} className="list-card">
                  <div className="list-card-title">
                    <strong>{source}</strong>
                    <Badge tone="danger">contain</Badge>
                  </div>
                  <p>Generate a blocklist artifact or validate this source against perimeter logs.</p>
                </article>
              ))}
            </div>
          )}
        </SectionCard>

        <SectionCard title="Silent / degraded sensors" subtitle="Fleet members reducing coverage right now.">
          {unhealthyFleet.length === 0 ? (
            <div className="empty-inline">All fleet members are healthy.</div>
          ) : (
            <div className="stack-list">
              {unhealthyFleet.map((item) => (
                <article key={item.decoy_id} className="list-card">
                  <div className="list-card-title">
                    <strong>{item.decoy_id}</strong>
                    <Badge tone={item.health_status === "silent" ? "danger" : "warning"}>{item.health_status}</Badge>
                  </div>
                  <p>
                    {item.site} | {item.environment} | {item.coverage_role}
                  </p>
                  <small>{item.failure_reason ?? "Heartbeat freshness or relay health requires attention."}</small>
                </article>
              ))}
            </div>
          )}
        </SectionCard>

        <SectionCard title="Recent detections" subtitle="Latest high-signal findings from worker materialization.">
          <div className="stack-list">
            {posture.recent_detections.length === 0 ? (
              <div className="empty-inline">No detections yet.</div>
            ) : (
              posture.recent_detections.map((detection) => (
                <article key={detection.id} className="list-card">
                  <div className="list-card-title">
                    <strong>{detection.title}</strong>
                    <Badge tone={detection.severity === "critical" ? "danger" : detection.severity === "high" ? "warning" : "default"}>
                      {detection.severity}
                    </Badge>
                  </div>
                  <p>{detection.summary}</p>
                  <small>
                    {detection.src_ip ?? "unknown source"} | {detection.site ?? "unknown site"} |{" "}
                    {new Date(detection.last_seen_at).toLocaleString()}
                  </small>
                </article>
              ))
            )}
          </div>
        </SectionCard>
      </div>
    </div>
  );
}
