import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Activity,
  AlertTriangle,
  Database,
  FileText,
  RefreshCw,
  Server,
  Shield,
} from 'lucide-react';
import { Card, KpiCard, LoadingState, ErrorState } from '../components';
import { eventsApi, healthApi, schemaApi, sourcesApi, failuresApi, simulatorsApi } from '../api';
import type { EventMetrics, SystemHealthResponse, SimulatorsStatusResponse } from '../api';

export function OverviewPage() {
  const navigate = useNavigate();
  const [metrics, setMetrics] = useState<EventMetrics | null>(null);
  const [health, setHealth] = useState<SystemHealthResponse | null>(null);
  const [simulators, setSimulators] = useState<SimulatorsStatusResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [fetching, setFetching] = useState(false);

  const fetchSimulatorStatus = async () => {
    try {
      const status = await simulatorsApi.getStatus();
      setSimulators(status);
    } catch {
      // Silently ignore - simulators endpoint may be unavailable
    }
  };

  const fetchData = async (includeFailures = false) => {
    if (fetching) return;
    setFetching(true);
    setError(null);
    try {
      const promises: Promise<any>[] = [
        eventsApi.searchEvents(),
        schemaApi.listDriftEvents(),
        healthApi.getSystemHealth(),
        sourcesApi.listSources({ enabled_only: true }),
        simulatorsApi.getStatus(),
      ];

      if (includeFailures) {
        promises.push(failuresApi.listParsingFailures(), failuresApi.listNormalizationFailures());
      }

      const [eventsData, driftData, healthData, sourcesData, simData, parsingFailuresData, normalizationFailuresData] = await Promise.allSettled(promises);

      if (eventsData.status === 'fulfilled') {
        const events = eventsData.value.events || [];
        const events_by_source: Record<string, number> = {};
        const events_by_action: Record<string, number> = {};
        const events_by_severity: Record<string, number> = {};

        events.forEach((event: any) => {
          const source = event.source_type || 'unknown';
          events_by_source[source] = (events_by_source[source] || 0) + 1;

          const action = event.ocsf?.event?.action || 'unknown';
          events_by_action[action] = (events_by_action[action] || 0) + 1;

          const severity = event.ocsf?.event?.severity || 'unknown';
          events_by_severity[severity] = (events_by_severity[severity] || 0) + 1;
        });

        setMetrics({
          total_events: eventsData.value.total || events.length,
          events_by_source,
          events_by_action,
          events_by_severity,
          parsing_failures: parsingFailuresData?.status === 'fulfilled' ? (parsingFailuresData.value.total_count ?? parsingFailuresData.value.count ?? 0) : 0,
          normalization_failures: normalizationFailuresData?.status === 'fulfilled' ? (normalizationFailuresData.value.total_count ?? normalizationFailuresData.value.count ?? 0) : 0,
          schema_drift_events:
            driftData.status === 'fulfilled' ? (driftData.value.total_count ?? driftData.value.count ?? 0) : 0,
          active_sources: sourcesData.status === 'fulfilled' ? (sourcesData.value.count ?? 0) : 0,
        });
      }

      if (healthData.status === 'fulfilled') {
        setHealth(healthData.value);
      }

      if (simData.status === 'fulfilled') {
        setSimulators(simData.value);
      }

      setLastUpdated(new Date());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load dashboard data');
    } finally {
      setLoading(false);
      setFetching(false);
    }
  };

  useEffect(() => {
    fetchData(true);
    fetchSimulatorStatus();
    const interval = setInterval(() => {
      fetchData();
      fetchSimulatorStatus();
    }, 5000);
    return () => clearInterval(interval);
  }, []);

  if (loading && !metrics) {
    return <LoadingState message="Loading dashboard..." />;
  }

  if (error && !metrics) {
    return <ErrorState message={error} onRetry={fetchData} />;
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Dashboard Overview</h1>
        <div className="flex items-center gap-4">
          {lastUpdated && (
            <span className="text-sm text-gray-400">
              Last updated: {lastUpdated.toLocaleTimeString()}
            </span>
          )}

          {simulators?.any_running ? (
            <span className="flex items-center gap-1 text-green-400 text-sm font-medium">
              <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
              Monitoring Live
            </span>
          ) : (
            <span className="flex items-center gap-1 text-gray-400 text-sm">
              <span className="w-2 h-2 rounded-full bg-gray-500" />
              Monitoring Stopped
            </span>
          )}

          <button
            onClick={() => fetchData()}
            className="btn-secondary flex items-center gap-2"
          >
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        <KpiCard
          title="Total Events"
          value={metrics?.total_events ?? '—'}
          icon={Activity}
          status="neutral"
        />
        <KpiCard
          title="Active Sources"
          value={metrics?.active_sources ?? '—'}
          icon={Server}
          status="success"
          onClick={() => navigate('/sources')}
        />
        <KpiCard
          title="Schema Drift Events"
          value={metrics?.schema_drift_events ?? '—'}
          icon={AlertTriangle}
          status={(metrics?.schema_drift_events ?? 0) > 0 ? 'warning' : 'neutral'}
          onClick={() => navigate('/schema-drift')}
        />
        <KpiCard
          title="Parsing Failures"
          value={metrics?.parsing_failures ?? '—'}
          icon={FileText}
          status={(metrics?.parsing_failures ?? 0) > 0 ? 'error' : 'neutral'}
          onClick={() => navigate('/parsing-failures')}
        />
        <KpiCard
          title="Normalization Failures"
          value={metrics?.normalization_failures ?? '—'}
          icon={Shield}
          status={(metrics?.normalization_failures ?? 0) > 0 ? 'error' : 'neutral'}
          onClick={() => navigate('/normalization-failures')}
        />
        <KpiCard
          title="System Status"
          value={health?.status === 'healthy' ? 'Healthy' : 'Degraded'}
          icon={health?.status === 'healthy' ? Database : AlertTriangle}
          status={health?.status === 'healthy' ? 'success' : 'warning'}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card title="Events by Source">
          {metrics?.events_by_source && Object.keys(metrics.events_by_source).length > 0 ? (
            <div className="space-y-2">
              {Object.entries(metrics.events_by_source).map(([source, count]) => (
                <div key={source} className="flex justify-between items-center">
                  <span className="text-gray-300">{source}</span>
                  <span className="font-medium">{count}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-gray-400">No source data available</p>
          )}
        </Card>

        <Card title="Events by Action">
          {metrics?.events_by_action && Object.keys(metrics.events_by_action).length > 0 ? (
            <div className="space-y-2">
              {Object.entries(metrics.events_by_action).map(([action, count]) => (
                <div key={action} className="flex justify-between items-center">
                  <span className="text-gray-300 capitalize">{action}</span>
                  <span className="font-medium">{count}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-gray-400">No action data available</p>
          )}
        </Card>

        <Card title="Events by Severity">
          {metrics?.events_by_severity && Object.keys(metrics.events_by_severity).length > 0 ? (
            <div className="space-y-2">
              {Object.entries(metrics.events_by_severity).map(([severity, count]) => (
                <div key={severity} className="flex justify-between items-center">
                  <span className="text-gray-300 capitalize">{severity}</span>
                  <span className="font-medium">{count}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-gray-400">No severity data available</p>
          )}
        </Card>

        <Card title="System Health">
          {health?.services ? (
            <div className="space-y-2">
              {health.services.map((service) => (
                <div key={service.name} className="flex justify-between items-center">
                  <span className="text-gray-300">{service.name}</span>
                  <span className={`badge badge-${service.status === 'healthy' ? 'success' : service.status === 'degraded' ? 'warning' : 'error'}`}>
                    {service.status}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-gray-400">Health data unavailable</p>
          )}
        </Card>
      </div>
    </div>
  );
}
