const API_BASE = import.meta.env.VITE_API_BASE_URL || '/api/v1';

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

export interface SchemaProfile {
  source_id: string;
  schema_version: string;
  required_fields: string[];
  optional_fields: string[];
  field_types: Record<string, string>;
  active: boolean;
  description?: string;
  created_at: string;
  updated_at: string;
}

export interface SchemaListResponse {
  schemas: SchemaProfile[];
  count: number;
}

export interface DriftDetectionResult {
  source_id: string;
  schema_version: string;
  event_id: string;
  drift_detected: boolean;
  drift_types: string[];
  new_fields: string[];
  missing_required_fields: string[];
  missing_optional_fields: string[];
  type_changes: Array<{ field: string; expected_type: string; actual_type: string }>;
  severity: 'info' | 'warning' | 'error';
  detected_at: string;
}

export interface DriftListResponse {
  drift_events: DriftDetectionResult[];
  count: number;
  total_count: number;
}

export interface SchemaCreateRequest {
  source_id: string;
  schema_version: string;
  required_fields?: string[];
  optional_fields?: string[];
  field_types?: Record<string, string>;
  active?: boolean;
  description?: string;
}

export const schemaApi = {
  listSchemas: (params?: { source_type?: string }) => {
    const searchParams = new URLSearchParams();
    if (params?.source_type) searchParams.set('source_type', params.source_type);
    const query = searchParams.toString();
    return fetchJson<SchemaListResponse>(`/schema/profiles${query ? `?${query}` : ''}`);
  },

  getSchema: (sourceId: string) =>
    fetchJson<SchemaProfile>(`/schema/profiles/${encodeURIComponent(sourceId)}`),

  createSchema: (data: SchemaCreateRequest) =>
    fetchJson<SchemaProfile>('/schema/profiles', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  listDriftEvents: (params?: { source_id?: string; limit?: number }) => {
    const searchParams = new URLSearchParams();
    if (params?.source_id) searchParams.set('source_id', params.source_id);
    if (params?.limit) searchParams.set('limit', params.limit.toString());
    const query = searchParams.toString();
    return fetchJson<DriftListResponse>(`/schema/drift${query ? `?${query}` : ''}`);
  },

  getDriftByEvent: (eventId: string) =>
    fetchJson<DriftDetectionResult>(`/schema/drift/${encodeURIComponent(eventId)}`),
};
