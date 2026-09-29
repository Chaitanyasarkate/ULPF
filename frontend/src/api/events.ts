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

export interface NormalizedEvent {
  event_id: string;
  raw_event_id: string;
  source_id: string;
  source_type: string;
  format: string;
  parser_id: string;
  parser_version: string;
  schema_version: string;
  event_timestamp?: string;
  ingestion_timestamp: string;
  sha256: string;
  ocsf: {
    event?: {
      action?: string;
      severity?: string;
      time?: string;
      category?: string;
      class_name?: string;
    };
    source?: {
      ip?: string;
      port?: number;
    };
    destination?: {
      ip?: string;
      port?: number;
    };
    network?: {
      protocol?: string;
      bytes?: number;
    };
    device?: {
      name?: string;
      type?: string;
      interface?: string;
    };
  };
  parsed_fields: Record<string, unknown>;
  raw_payload: string;
}

export interface EventSearchResponse {
  events: NormalizedEvent[];
  total: number;
  page: number;
  page_size: number;
}

export interface EventMetrics {
  total_events: number;
  events_by_source: Record<string, number>;
  events_by_action: Record<string, number>;
  events_by_severity: Record<string, number>;
  parsing_failures: number;
  normalization_failures: number;
  schema_drift_events: number;
  active_sources: number;
}

export interface TimeSeriesPoint {
  timestamp: string;
  count: number;
}

export const eventsApi = {
  searchEvents: (params?: {
    query?: string;
    source_type?: string;
    action?: string;
    severity?: string;
    start_date?: string;
    end_date?: string;
    page?: number;
    page_size?: number;
  }) => {
    const searchParams = new URLSearchParams();
    if (params?.query) searchParams.set('query', params.query);
    if (params?.source_type) searchParams.set('source_type', params.source_type);
    if (params?.action) searchParams.set('action', params.action);
    if (params?.severity) searchParams.set('severity', params.severity);
    if (params?.start_date) searchParams.set('start_date', params.start_date);
    if (params?.end_date) searchParams.set('end_date', params.end_date);
    if (params?.page) searchParams.set('page', params.page.toString());
    if (params?.page_size) searchParams.set('page_size', params.page_size.toString());
    const query = searchParams.toString();
    return fetchJson<EventSearchResponse>(`/events${query ? `?${query}` : ''}`);
  },

  getEvent: (eventId: string) =>
    fetchJson<NormalizedEvent>(`/events/${encodeURIComponent(eventId)}`),

  getMetrics: () => fetchJson<EventMetrics>('/metrics/summary'),

  getTimeSeries: (params?: { start_date?: string; end_date?: string; interval?: string }) => {
    const searchParams = new URLSearchParams();
    if (params?.start_date) searchParams.set('start_date', params.start_date);
    if (params?.end_date) searchParams.set('end_date', params.end_date);
    if (params?.interval) searchParams.set('interval', params.interval);
    const query = searchParams.toString();
    return fetchJson<{ data: TimeSeriesPoint[] }>(`/metrics/timeseries${query ? `?${query}` : ''}`);
  },
};
