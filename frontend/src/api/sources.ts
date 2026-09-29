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

export interface SourceProfile {
  source_id: string;
  source_name: string;
  source_type: string;
  format: string;
  parser_id: string;
  parser_version: string;
  normalizer_id?: string;
  normalizer_version?: string;
  schema_version: string;
  enabled: boolean;
  status: string;
  vendor?: string;
  product?: string;
  product_version?: string;
  description?: string;
  transport?: string;
  created_at: string;
  updated_at: string;
}

export interface SourceListResponse {
  sources: SourceProfile[];
  count: number;
}

export interface SourceCreateRequest {
  source_id: string;
  source_name: string;
  source_type: string;
  format: string;
  parser_id: string;
  parser_version?: string;
  normalizer_id?: string;
  normalizer_version?: string;
  schema_version?: string;
  enabled?: boolean;
  vendor?: string;
  product?: string;
  product_version?: string;
  description?: string;
  transport?: string;
}

export const sourcesApi = {
  listSources: (params?: { source_type?: string; enabled_only?: boolean }) => {
    const searchParams = new URLSearchParams();
    if (params?.source_type) searchParams.set('source_type', params.source_type);
    if (params?.enabled_only) searchParams.set('enabled_only', 'true');
    const query = searchParams.toString();
    return fetchJson<SourceListResponse>(`/sources${query ? `?${query}` : ''}`);
  },

  getSource: (sourceId: string) =>
    fetchJson<SourceProfile>(`/sources/${encodeURIComponent(sourceId)}`),

  createSource: (data: SourceCreateRequest) =>
    fetchJson<SourceProfile>('/sources', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  updateSource: (sourceId: string, data: Partial<SourceCreateRequest>) =>
    fetchJson<SourceProfile>(`/sources/${encodeURIComponent(sourceId)}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    }),

  deleteSource: (sourceId: string) =>
    fetchJson<{ message: string; source_id: string }>(`/sources/${encodeURIComponent(sourceId)}`, {
      method: 'DELETE',
    }),

  enableSource: (sourceId: string) =>
    fetchJson<SourceProfile>(`/sources/${encodeURIComponent(sourceId)}/enable`, {
      method: 'POST',
    }),

  disableSource: (sourceId: string) =>
    fetchJson<SourceProfile>(`/sources/${encodeURIComponent(sourceId)}/disable`, {
      method: 'POST',
    }),
};
