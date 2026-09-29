import { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { jwtDecode } from 'jwt-decode';

interface User {
  username: string;
  role: 'admin' | 'analyst' | 'viewer';
}

interface AuthContextType {
  user: User | null;
  accessToken: string | null;
  refreshToken: string | null;
  login: (username: string, password: string) => Promise<boolean>;
  logout: () => void;
  refreshAccessToken: () => Promise<boolean>;
  hasPermission: (permission: string) => boolean;
  isLoading: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

const API_BASE = import.meta.env.VITE_API_BASE_URL || '/api/v1';

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [refreshToken, setRefreshToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // Initialize from localStorage on mount
  useEffect(() => {
    const storedAccess = localStorage.getItem('ulpf_access_token');
    const storedRefresh = localStorage.getItem('ulpf_refresh_token');
    const storedUser = localStorage.getItem('ulpf_user');

    if (storedAccess && storedRefresh && storedUser) {
      try {
        const decoded = jwtDecode<{ exp: number; role: string }>(storedAccess);
        if (decoded.exp * 1000 > Date.now()) {
          setAccessToken(storedAccess);
          setRefreshToken(storedRefresh);
          setUser(JSON.parse(storedUser));
        } else {
          // Token expired, try refresh
          refreshAccessToken().catch(() => clearAuth());
        }
      } catch {
        clearAuth();
      }
    }
    setIsLoading(false);
  }, []);

  const clearAuth = () => {
    localStorage.removeItem('ulpf_access_token');
    localStorage.removeItem('ulpf_refresh_token');
    localStorage.removeItem('ulpf_user');
    setAccessToken(null);
    setRefreshToken(null);
    setUser(null);
  };

  const login = async (username: string, password: string): Promise<boolean> => {
    try {
      const response = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });

      if (!response.ok) {
        const error = await response.json().catch(() => ({ error: 'Login failed' }));
        throw new Error(error.error || error.message || 'Login failed');
      }

      const data = await response.json();
      const decoded = jwtDecode<{ role: string }>(data.access_token);

      const userData: User = {
        username: data.user.username,
        role: decoded.role as 'admin' | 'analyst' | 'viewer',
      };

      localStorage.setItem('ulpf_access_token', data.access_token);
      localStorage.setItem('ulpf_refresh_token', data.refresh_token);
      localStorage.setItem('ulpf_user', JSON.stringify(userData));

      setAccessToken(data.access_token);
      setRefreshToken(data.refresh_token);
      setUser(userData);

      return true;
    } catch (error) {
      console.error('Login failed:', error);
      return false;
    }
  };

  const refreshAccessToken = async (): Promise<boolean> => {
    const storedRefresh = localStorage.getItem('ulpf_refresh_token');
    if (!storedRefresh) return false;

    try {
      const response = await fetch(`${API_BASE}/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: storedRefresh }),
      });

      if (!response.ok) {
        clearAuth();
        return false;
      }

      const data = await response.json();
      localStorage.setItem('ulpf_access_token', data.access_token);
      setAccessToken(data.access_token);
      return true;
    } catch {
      clearAuth();
      return false;
    }
  };

  const logout = () => {
    clearAuth();
  };

  const hasPermission = (permission: string): boolean => {
    if (!user) return false;
    
    const rolePermissions: Record<string, string[]> = {
      admin: [
        'events:view', 'events:search', 'events:convert', 'ingest:create',
        'lineage:view', 'schema:view', 'schema:manage',
        'sources:view', 'sources:manage', 'config:manage',
        'analytics:view', 'analytics:score', 'parsers:view', 'parsers:generate', 'parsers:register',
        'health:view', 'metrics:view',
      ],
      analyst: [
        'events:view', 'events:search', 'events:convert', 'ingest:create',
        'lineage:view', 'schema:view', 'sources:view',
        'analytics:view', 'analytics:score', 'parsers:view', 'parsers:generate',
        'health:view', 'metrics:view',
      ],
      viewer: [
        'events:view', 'events:search', 'sources:view', 'schema:view',
        'analytics:view', 'parsers:view', 'health:view', 'metrics:view',
      ],
    };

    return rolePermissions[user.role]?.includes(permission) ?? false;
  };

  return (
    <AuthContext.Provider value={{ user, accessToken, refreshToken, login, logout, refreshAccessToken, hasPermission, isLoading }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

export async function authenticatedFetch(url: string, options: RequestInit = {}): Promise<Response> {
  const accessToken = localStorage.getItem('ulpf_access_token');
  
  const headers = new Headers(options.headers);
  headers.set('Content-Type', 'application/json');
  if (accessToken) {
    headers.set('Authorization', `Bearer ${accessToken}`);
  }

  let response = await fetch(`${API_BASE}${url}`, {
    ...options,
    headers,
  });

  // If 401, try to refresh token and retry once
  if (response.status === 401) {
    const refreshToken = localStorage.getItem('ulpf_refresh_token');
    if (refreshToken) {
      const refreshResponse = await fetch(`${API_BASE}/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: refreshToken }),
      });

      if (refreshResponse.ok) {
        const data = await refreshResponse.json();
        localStorage.setItem('ulpf_access_token', data.access_token);
        headers.set('Authorization', `Bearer ${data.access_token}`);
        
        response = await fetch(`${API_BASE}${url}`, {
          ...options,
          headers,
        });
      } else {
        // Refresh failed, clear auth
        localStorage.removeItem('ulpf_access_token');
        localStorage.removeItem('ulpf_refresh_token');
        localStorage.removeItem('ulpf_user');
        window.location.href = '/login';
      }
    }
  }

  return response;
}