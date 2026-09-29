function getApiBaseUrl(): string {
  const envUrl = import.meta.env.VITE_API_BASE_URL;
  if (!envUrl) {
    return '/api/v1';
  }
  const clean = envUrl.trim().replace(/\/+$/, '');
  if (clean.endsWith('/api/v1')) {
    return clean;
  }
  return `${clean}/api/v1`;
}

export const API_BASE = getApiBaseUrl();
