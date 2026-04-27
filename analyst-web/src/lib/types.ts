export type RequestError = Error & { status?: number };

export type Posture = {
  detections_new: number;
  detections_in_triage: number;
  fleet_total: number;
  fleet_unhealthy: number;
  coverage_gaps: string[];
  recommended_blocks: string[];
  exposed_endpoints: number;
  critical_detections: number;
  high_detections: number;
  medium_detections: number;
  active_decoys: number;
  silent_decoys: number;
  degraded_decoys: number;
  changes_last_24h: {
    events: number;
    detections: number;
    credentials: number;
  };
  top_sources: Array<{ src_ip: string; hits: number }>;
  recent_detections: DetectionRecord[];
};

export type EventRecord = {
  id: string;
  event_id: string;
  occurred_at: string;
  decoy_id: string;
  profile: string;
  edge_node_id: string;
  decoy_version: string;
  collector_version: string;
  site: string;
  environment: string;
  coverage_role: string;
  src_ip: string;
  source_country?: string | null;
  method: string;
  path: string;
  request_fingerprint: string;
  event_class: string;
  status_code: number;
  user_agent: string;
  username: string;
  password: string;
  suspicious: boolean;
  latency_ms: number;
  tags: string[];
  normalized_tags: string[];
  headers_subset: Record<string, string>;
};

export type CredentialRecord = {
  id: string;
  attempted_at: string;
  decoy_id: string;
  src_ip: string;
  username: string;
  password: string;
  event_id: string;
};

export type FleetRecord = {
  decoy_id: string;
  profile: string;
  edge_node_id: string;
  decoy_version: string;
  collector_version: string;
  public_endpoint?: string | null;
  status: string;
  health_status: string;
  coverage_role: string;
  environment: string;
  site: string;
  last_seen_at: string;
  last_heartbeat_at?: string | null;
  runtime_state?: string;
  failure_reason?: string | null;
  relay_health?: string | null;
  relay_queue_backlog?: number | null;
};

export type DetectionRecord = {
  id: string;
  detection_type: string;
  severity: string;
  confidence: string;
  status: string;
  title: string;
  summary: string;
  recommended_action: string;
  recommended_block_targets: string[];
  assigned_to?: string | null;
  triage_notes?: string | null;
  evidence_summary: Record<string, unknown>;
  decoy_id?: string | null;
  site?: string | null;
  src_ip?: string | null;
  occurrences: number;
  first_seen_at: string;
  last_seen_at: string;
  investigation_id?: string | null;
};

export type InvestigationRecord = {
  id: string;
  fingerprint: string;
  first_seen: string;
  last_seen: string;
  detection_count: number;
  decoy_spread: number;
  activity_class: string;
  analyst_notes?: string | null;
  status: string;
};

export type ArtifactRecord = {
  id: string;
  artifact_type: string;
  export_format: string;
  generated_by: string;
  generated_at: string;
  bucket: string;
  object_key: string;
  linked_investigation?: string | null;
  download_url: string;
};

export type CoverageSummary = {
  coverage_gaps: string[];
  healthy: number;
  degraded: number;
  silent: number;
};

export type BlocklistSummary = {
  entries: Array<{ target: string; detections: number }>;
};
