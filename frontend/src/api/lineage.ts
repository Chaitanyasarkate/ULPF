import { API_BASE } from './config';

async function fetchJson<T>(url: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${url}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Unknown error' }));
    throw new Error(error.error || error.message || `HTTP ${response.status}`);
  }

  return response.json();
}

export interface HealthStatus {
  status: string;
  dependencies?: Record<string, boolean>;
  error?: string;
}

export interface LineageChain {
  event_id: string;
  raw_event_id: string;
  ancestors: LineageRecord[];
  descendants: LineageRecord[];
  sha256?: string;
  parser_id?: string;
  parser_version?: string;
  schema_version?: string;
}

export interface LineageRecord {
  parent_event_id: string;
  child_event_id: string;
  relationship_type: string;
  raw_event_id: string;
  created_at: string;
}

export interface LineageVerification {
  event_id: string;
  raw_event_id: string;
  lineage_complete: boolean;
  raw_object_exists: boolean;
  sha256_verified: boolean;
  normalized_object_exists: boolean;
  status: 'VALID' | 'INVALID' | 'UNAVAILABLE';
  errors: string[];
}

export interface RawEventRecovery {
  raw_event_id: string;
  raw_payload?: string;
  sha256?: string;
  expected_sha256?: string;
  object_key?: string;
  bucket?: string;
  verified: boolean;
  exists?: boolean;
  error?: string;
}

export const lineageApi = {
  getLineageChain: (eventId: string) =>
    fetchJson<LineageChain>(`/lineage/event/${encodeURIComponent(eventId)}`),

  getLineageByRaw: (rawEventId: string) =>
    fetchJson<{ parsed: unknown; normalized: unknown; lineage_records: LineageRecord[] }>(
      `/lineage/raw/${encodeURIComponent(rawEventId)}`
    ),

  verifyLineage: (eventId: string) =>
    fetchJson<LineageVerification>(`/lineage/verify/${encodeURIComponent(eventId)}`),

  recoverRawEvent: (eventId: string) =>
    fetchJson<RawEventRecovery>(`/lineage/raw-event/${encodeURIComponent(eventId)}`),

  getHealth: () => fetchJson<HealthStatus>('/lineage/health'),
};
