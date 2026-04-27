import type {
  ArtifactRecord,
  BlocklistSummary,
  CoverageSummary,
  CredentialRecord,
  DetectionRecord,
  EventRecord,
  FleetRecord,
  InvestigationRecord,
  Posture,
  RequestError,
} from "./types";

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:5000";
const DEFAULT_TOKEN = import.meta.env.VITE_ANALYST_TOKEN ?? "dev-analyst-token";

export function getStoredToken(): string {
  return window.localStorage.getItem("honeynet-analyst-token") ?? DEFAULT_TOKEN;
}

export function setStoredToken(token: string): void {
  window.localStorage.setItem("honeynet-analyst-token", token);
}

export function shouldHideTokenEntry(): boolean {
  return import.meta.env.VITE_HIDE_DEV_TOKEN_ENTRY === "true";
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${getStoredToken()}`,
      ...(init?.headers ?? {}),
    },
  });

  if (!response.ok) {
    const text = await response.text();
    const error = new Error(text || `${response.status} ${response.statusText}`) as RequestError;
    error.status = response.status;
    throw error;
  }

  return response.json() as Promise<T>;
}

export async function downloadArtifact(path: string): Promise<Blob> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: {
      Authorization: `Bearer ${getStoredToken()}`,
    },
  });
  if (!response.ok) {
    const error = new Error(await response.text()) as RequestError;
    error.status = response.status;
    throw error;
  }
  return response.blob();
}

export const api = {
  posture: () => request<Posture>("/api/v1/stats/posture"),
  events: (query = "") => request<EventRecord[]>(`/api/v1/events${query}`),
  credentials: () => request<CredentialRecord[]>("/api/v1/credentials"),
  fleet: () => request<FleetRecord[]>("/api/v1/fleet"),
  fleetCoverage: () => request<CoverageSummary>("/api/v1/fleet/coverage"),
  detections: (query = "") => request<DetectionRecord[]>(`/api/v1/detections${query}`),
  detection: (id: string) => request<DetectionRecord>(`/api/v1/detections/${id}`),
  updateDetection: (id: string, payload: Partial<Pick<DetectionRecord, "status" | "assigned_to" | "triage_notes">>) =>
    request<DetectionRecord>(`/api/v1/detections/${id}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),
  investigations: () => request<InvestigationRecord[]>("/api/v1/investigations"),
  investigation: (id: string) => request<InvestigationRecord>(`/api/v1/investigations/${id}`),
  blocklists: () => request<BlocklistSummary>("/api/v1/blocklists"),
  exports: () => request<ArtifactRecord[]>("/api/v1/exports"),
  exportBlocklist: (format: "csv" | "json") =>
    request<ArtifactRecord>("/api/v1/blocklists/export", {
      method: "POST",
      body: JSON.stringify({ format }),
    }),
  exportEvidence: (payload: { format: "json" | "html"; detection_id?: string; investigation_id?: string }) =>
    request<ArtifactRecord>("/api/v1/exports/evidence", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  exportManagementSummary: (format: "html" | "csv") =>
    request<ArtifactRecord>("/api/v1/reports/export", {
      method: "POST",
      body: JSON.stringify({ format, limit: 500 }),
    }),
};
