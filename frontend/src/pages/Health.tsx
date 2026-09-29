import { useState, useEffect } from 'react';
import { RefreshCw, CheckCircle, XCircle, AlertTriangle, HelpCircle } from 'lucide-react';
import { Card, StatusIndicator, LoadingState, ErrorState } from '../components';
import { healthApi, lineageApi, sourcesApi } from '../api';

interface ServiceStatus {
  name: string;
  status: 'healthy' | 'degraded' | 'unhealthy' | 'unknown';
  details?: Record<string, unknown>;
  lastChecked?: string;
}

export function HealthPage() {
  const [services, setServices] = useState<ServiceStatus[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastChecked, setLastChecked] = useState<Date | null>(null);

  const fetchHealth = async () => {
    setLoading(true);
    setError(null);

    const serviceStatuses: ServiceStatus[] = [
      { name: 'ULPF API', status: 'unknown' },
      { name: 'PostgreSQL', status: 'unknown' },
      { name: 'MinIO', status: 'unknown' },
      { name: 'OpenSearch', status: 'unknown' },
      { name: 'Kafka', status: 'unknown' },
      { name: 'Parser Engine', status: 'unknown' },
      { name: 'Normalizer', status: 'unknown' },
      { name: 'Lineage Service', status: 'unknown' },
      { name: 'Source Registry', status: 'unknown' },
    ];

    try {
      const [healthRes, lineageHealthRes, sourcesRes] = await Promise.allSettled([
        healthApi.getSystemHealth(),
        lineageApi.getHealth().catch(() => ({ status: 'unhealthy', dependencies: {} as Record<string, unknown> })),
        sourcesApi.listSources().catch(() => ({ sources: [], count: 0 })),
      ]);

      if (healthRes.status === 'fulfilled') {
        const idx = serviceStatuses.findIndex((s) => s.name === 'ULPF API');
        if (idx !== -1) {
          serviceStatuses[idx].status = healthRes.value.status === 'healthy' ? 'healthy' : 'degraded';
        }
        healthRes.value.services?.forEach((service) => {
          const idx = serviceStatuses.findIndex(
            (s) => s.name.toLowerCase() === service.name.toLowerCase()
          );
          if (idx !== -1) {
            serviceStatuses[idx].status = service.status;
            serviceStatuses[idx].details = service.details;
          }
        });
      }

      if (lineageHealthRes.status === 'fulfilled') {
        const idx = serviceStatuses.findIndex((s) => s.name === 'Lineage Service');
        if (idx !== -1) {
          serviceStatuses[idx].status = lineageHealthRes.value.status === 'healthy' ? 'healthy' : 'degraded';
          serviceStatuses[idx].details = (lineageHealthRes.value as any).dependencies;
        }
      }

      if (sourcesRes.status === 'fulfilled') {
        const idx = serviceStatuses.findIndex((s) => s.name === 'Source Registry');
        if (idx !== -1) {
          serviceStatuses[idx].status = 'healthy';
          serviceStatuses[idx].details = { sources_count: sourcesRes.value.count };
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to check health');
    } finally {
      serviceStatuses.forEach((s) => {
        if (s.status === 'unknown') {
          s.status = 'unhealthy';
        }
      });
      setServices(serviceStatuses);
      setLastChecked(new Date());
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHealth();
    const interval = setInterval(fetchHealth, 30000);
    return () => clearInterval(interval);
  }, []);

  const getStatusIcon = (status: ServiceStatus['status']) => {
    switch (status) {
      case 'healthy':
        return <CheckCircle className="w-6 h-6 text-green-400" />;
      case 'degraded':
        return <AlertTriangle className="w-6 h-6 text-yellow-400" />;
      case 'unhealthy':
        return <XCircle className="w-6 h-6 text-red-400" />;
      default:
        return <HelpCircle className="w-6 h-6 text-gray-400" />;
    }
  };

  const healthyCount = services.filter((s) => s.status === 'healthy').length;
  const degradedCount = services.filter((s) => s.status === 'degraded').length;
  const unhealthyCount = services.filter((s) => s.status === 'unhealthy').length;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">System Health</h1>
        <div className="flex items-center gap-4">
          {lastChecked && (
            <span className="text-sm text-gray-400">
              Last checked: {lastChecked.toLocaleTimeString()}
            </span>
          )}
          <button onClick={fetchHealth} className="btn-secondary">
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <div className="flex items-center gap-3">
            <CheckCircle className="w-8 h-8 text-green-400" />
            <div>
              <div className="text-3xl font-bold text-green-400">{healthyCount}</div>
              <div className="text-gray-400">Healthy</div>
            </div>
          </div>
        </Card>
        <Card>
          <div className="flex items-center gap-3">
            <AlertTriangle className="w-8 h-8 text-yellow-400" />
            <div>
              <div className="text-3xl font-bold text-yellow-400">{degradedCount}</div>
              <div className="text-gray-400">Degraded</div>
            </div>
          </div>
        </Card>
        <Card>
          <div className="flex items-center gap-3">
            <XCircle className="w-8 h-8 text-red-400" />
            <div>
              <div className="text-3xl font-bold text-red-400">{unhealthyCount}</div>
              <div className="text-gray-400">Unhealthy</div>
            </div>
          </div>
        </Card>
      </div>

      <Card title="Service Status">
        {loading ? (
          <LoadingState message="Checking services..." />
        ) : error ? (
          <ErrorState message={error} onRetry={fetchHealth} />
        ) : (
          <div className="space-y-4">
            {services.map((service) => (
              <div
                key={service.name}
                className="flex items-center justify-between p-4 bg-dark-200 rounded-lg"
              >
                <div className="flex items-center gap-4">
                  {getStatusIcon(service.status)}
                  <div>
                    <div className="font-medium">{service.name}</div>
                    {service.details && Object.keys(service.details).length > 0 && (
                      <div className="text-sm text-gray-400">
                        {Object.entries(service.details)
                          .map(([k, v]) => `${k}: ${v}`)
                          .join(', ')}
                      </div>
                    )}
                  </div>
                </div>
                <StatusIndicator status={service.status} />
              </div>
            ))}
          </div>
        )}
      </Card>

      <Card title="Health Check Legend">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="flex items-center gap-3">
            <CheckCircle className="w-5 h-5 text-green-400" />
            <div>
              <div className="font-medium text-green-400">Healthy</div>
              <div className="text-sm text-gray-400">Service is fully operational</div>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <AlertTriangle className="w-5 h-5 text-yellow-400" />
            <div>
              <div className="font-medium text-yellow-400">Degraded</div>
              <div className="text-sm text-gray-400">Service is available but with reduced functionality</div>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <XCircle className="w-5 h-5 text-red-400" />
            <div>
              <div className="font-medium text-red-400">Unhealthy</div>
              <div className="text-sm text-gray-400">Service is unavailable or critical issues detected</div>
            </div>
          </div>
        </div>
      </Card>
    </div>
  );
}
