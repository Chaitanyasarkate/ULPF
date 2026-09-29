import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { RefreshCw, AlertTriangle, Info, XCircle, ExternalLink } from 'lucide-react';
import { Card, Badge, DataTable, LoadingState, ErrorState } from '../components';
import { schemaApi, type DriftDetectionResult } from '../api';

export function SchemaDriftPage() {
  const navigate = useNavigate();
  const [driftEvents, setDriftEvents] = useState<DriftDetectionResult[]>([]);
  const [totalDriftCount, setTotalDriftCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [driftTypeFilter, setDriftTypeFilter] = useState<string>('');

  const fetchDriftEvents = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await schemaApi.listDriftEvents({ limit: 100 });
      setDriftEvents(response.drift_events);
      setTotalDriftCount(response.total_count || response.drift_events.length);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load drift events');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDriftEvents();
    const interval = setInterval(fetchDriftEvents, 2000);
    return () => clearInterval(interval);
  }, []);

  const filteredEvents = driftEvents.filter((event) => {
    if (severityFilter && event.severity !== severityFilter) return false;
    if (driftTypeFilter && !event.drift_types.includes(driftTypeFilter)) return false;
    return true;
  });

  const columns = [
    {
      key: 'detected_at',
      header: 'Detected',
      width: '180px',
      render: (event: DriftDetectionResult) => (
        <span className="text-gray-400">
          {new Date(event.detected_at).toLocaleString()}
        </span>
      ),
    },
    {
      key: 'event_id',
      header: 'Event ID',
      width: '200px',
      render: (event: DriftDetectionResult) => (
        <button
          onClick={() => navigate(`/events/${event.event_id}`)}
          className="font-mono text-xs text-primary-400 hover:text-primary-300 hover:underline flex items-center gap-1"
          title="View event details"
        >
          {event.event_id}
          <ExternalLink className="w-3 h-3" />
        </button>
      ),
    },
    {
      key: 'source_id',
      header: 'Source',
    },
    {
      key: 'drift_types',
      header: 'Drift Type',
      render: (event: DriftDetectionResult) => (
        <div className="flex gap-1 flex-wrap">
          {event.drift_types.map((type) => (
            <Badge
              key={type}
              variant={
                type === 'new_field'
                  ? 'info'
                  : type === 'missing_required_field'
                  ? 'error'
                  : 'warning'
              }
            >
              {type}
            </Badge>
          ))}
        </div>
      ),
    },
    {
      key: 'severity',
      header: 'Severity',
      render: (event: DriftDetectionResult) => {
        const variant =
          event.severity === 'error'
            ? 'error'
            : event.severity === 'warning'
            ? 'warning'
            : 'info';
        const Icon =
          event.severity === 'error'
            ? XCircle
            : event.severity === 'warning'
            ? AlertTriangle
            : Info;
        return (
          <div className="flex items-center gap-1">
            <Icon className={`w-4 h-4 ${
              event.severity === 'error'
                ? 'text-red-400'
                : event.severity === 'warning'
                ? 'text-yellow-400'
                : 'text-blue-400'
            }`} />
            <Badge variant={variant}>{event.severity}</Badge>
          </div>
        );
      },
    },
    {
      key: 'new_fields',
      header: 'New Fields',
      render: (event: DriftDetectionResult) =>
        event.new_fields.length > 0 ? (
          <div className="flex flex-wrap gap-1">
            {event.new_fields.map((field) => (
              <span key={field} className="text-xs bg-blue-900/50 px-2 py-0.5 rounded">
                {field}
              </span>
            ))}
          </div>
        ) : (
          <span className="text-gray-500">—</span>
        ),
    },
    {
      key: 'missing_required_fields',
      header: 'Missing Fields',
      render: (event: DriftDetectionResult) =>
        event.missing_required_fields.length > 0 ? (
          <div className="flex flex-wrap gap-1">
            {event.missing_required_fields.map((field) => (
              <span key={field} className="text-xs bg-red-900/50 px-2 py-0.5 rounded">
                {field}
              </span>
            ))}
          </div>
        ) : (
          <span className="text-gray-500">—</span>
        ),
    },
    {
      key: 'type_changes',
      header: 'Type Changes',
      render: (event: DriftDetectionResult) =>
        event.type_changes.length > 0 ? (
          <div className="flex flex-wrap gap-1">
            {event.type_changes.map((change) => (
              <span
                key={change.field}
                className="text-xs bg-yellow-900/50 px-2 py-0.5 rounded"
                title={`${change.expected_type} → ${change.actual_type}`}
              >
                {change.field}
              </span>
            ))}
          </div>
        ) : (
          <span className="text-gray-500">—</span>
        ),
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Schema Drift</h1>
        <div className="flex items-center gap-4">
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="input"
          >
            <option value="">All Severities</option>
            <option value="info">Info</option>
            <option value="warning">Warning</option>
            <option value="error">Error</option>
          </select>
          <select
            value={driftTypeFilter}
            onChange={(e) => setDriftTypeFilter(e.target.value)}
            className="input"
          >
            <option value="">All Types</option>
            <option value="new_field">New Field</option>
            <option value="missing_required_field">Missing Required</option>
            <option value="type_change">Type Change</option>
          </select>
          <button onClick={fetchDriftEvents} className="btn-secondary">
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <div className="text-3xl font-bold text-primary-400">{totalDriftCount}</div>
          <div className="text-gray-400">Total Drift Events</div>
        </Card>
        <Card>
          <div className="text-3xl font-bold text-blue-400">
            {driftEvents.filter((e) => e.severity === 'info').length}
          </div>
          <div className="text-gray-400">Info</div>
        </Card>
        <Card>
          <div className="text-3xl font-bold text-yellow-400">
            {driftEvents.filter((e) => e.severity === 'warning').length}
          </div>
          <div className="text-gray-400">Warnings</div>
        </Card>
        <Card>
          <div className="text-3xl font-bold text-red-400">
            {driftEvents.filter((e) => e.severity === 'error').length}
          </div>
          <div className="text-gray-400">Errors</div>
        </Card>
      </div>

      <Card title="Drift Events">
        {loading ? (
          <LoadingState message="Loading drift events..." />
        ) : error ? (
          <ErrorState message={error} onRetry={fetchDriftEvents} />
        ) : (
          <DataTable
            columns={columns}
            data={filteredEvents}
            keyExtractor={(event) => `${event.event_id}-${event.detected_at}`}
            onRowClick={(event) => navigate(`/events/${event.event_id}`)}
            emptyMessage="No schema drift detected"
          />
        )}
      </Card>

      <Card title="What is Schema Drift?">
        <div className="text-gray-300 space-y-4">
          <p>
            <strong className="text-white">Schema Drift</strong> occurs when the structure of
            incoming log events changes over time, such as when a vendor releases a new firmware
            version or adds new fields.
          </p>
          <div className="space-y-2">
            <h4 className="font-semibold text-white">Drift Types:</h4>
            <ul className="list-disc list-inside space-y-1 text-gray-400">
              <li>
                <strong className="text-blue-400">New Field:</strong> An unexpected field appeared
                in the event.
              </li>
              <li>
                <strong className="text-red-400">Missing Required Field:</strong> A required field
                is no longer present.
              </li>
              <li>
                <strong className="text-yellow-400">Type Change:</strong> A field has a different
                data type than expected.
              </li>
            </ul>
          </div>
          <p className="text-sm text-gray-500">
            Events with schema drift continue processing normally. The original payload is always
            preserved.
          </p>
        </div>
      </Card>
    </div>
  );
}
