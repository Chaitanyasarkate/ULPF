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

export interface FailureRecord {
  raw_event_id: string;
  source_id: string;
  source_type: string;
  format: string;
  stage: string;
  code: string;
  message: string;
  received_at: string;
}

export interface FailureListResponse {
  failures: FailureRecord[];
  count: number;
}

export const failuresApi = {
  listParsingFailures: () => fetchJson<FailureListResponse>('/failures/parsing'),
  listNormalizationFailures: () => fetchJson<FailureListResponse>('/failures/normalization'),
};
