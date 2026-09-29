import { authenticatedFetch } from '../context/AuthContext';

export interface SimulatorStatus {
  running: boolean;
  pid?: number | null;
}

export interface SimulatorsStatusResponse {
  firewall?: SimulatorStatus;
  router?: SimulatorStatus;
  ids?: SimulatorStatus;
  any_running?: boolean;
  [key: string]: any;
}

export const simulatorsApi = {
  getStatus: () => fetchJson<SimulatorsStatusResponse>('/simulators'),
};

async function fetchJson<T>(url: string, options?: RequestInit): Promise<T> {
  const response = await authenticatedFetch(url, {
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