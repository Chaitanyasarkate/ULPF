import { useState, useEffect } from 'react';
import { AlertTriangle, RefreshCw, Filter, Search, ChevronLeft, ChevronRight } from 'lucide-react';
import { Card, DataTable, Badge, LoadingState, EmptyState, Button, Input, Dropdown } from '../components';
import { authenticatedFetch } from '../context/AuthContext';

export interface Anomaly {
  anomaly_id: string;
  event_id: string;
  raw_event_id: string;
  source_id: string;
  source_type: string;
  rule_id: string;
  rule_name: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  reason: string;
  triggered_fields: Record<string, unknown>;
  detected_at: string;
  status: 'open' | 'acknowledged' | 'closed';
}

export interface AnomalySearchResponse {
  anomalies: Anomaly[];
  total: number;
  page: number;
  page_size: number;
}

interface DropdownItem {
  label: string;
  onClick: () => void;
  variant?: 'default' | 'destructive';
}

export function AnomaliesPage() {
  const [anomalies, setAnomalies] = useState<Anomaly[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const pageSize = 50;

  const fetchAnomalies = async () => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams();
      params.set('page', page.toString());
      params.set('page_size', pageSize.toString());
      if (searchQuery) params.set('query', searchQuery);
      if (severityFilter) params.set('severity', severityFilter);
      if (statusFilter) params.set('status', statusFilter);

      const response = await authenticatedFetch(`/anomalies?${params.toString()}`);
      if (!response.ok) {
        const err = await response.json().catch(() => ({ error: 'Failed to fetch anomalies' }));
        throw new Error(err.error || err.message || `HTTP ${response.status}`);
      }
      const data = await response.json();
      setAnomalies(data.anomalies || []);
      setTotal(data.total || 0);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load anomalies');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAnomalies();
  }, [page, searchQuery, severityFilter, statusFilter]);

  const severityOptions: DropdownItem[] = [
    { label: 'All Severities', onClick: () => setSeverityFilter('') },
    { label: 'Critical', onClick: () => setSeverityFilter('critical') },
    { label: 'High', onClick: () => setSeverityFilter('high') },
    { label: 'Medium', onClick: () => setSeverityFilter('medium') },
    { label: 'Low', onClick: () => setSeverityFilter('low') },
  ];

  const statusOptions: DropdownItem[] = [
    { label: 'All Statuses', onClick: () => setStatusFilter('') },
    { label: 'Open', onClick: () => setStatusFilter('open') },
    { label: 'Acknowledged', onClick: () => setStatusFilter('acknowledged') },
    { label: 'Closed', onClick: () => setStatusFilter('closed') },
  ];

  const columns = [
    {
      key: 'detected_at',
      header: 'Detected At',
      width: '180px',
      render: (anomaly: Anomaly) => (
        <span className="text-gray-400">
          {anomaly.detected_at ? new Date(anomaly.detected_at).toLocaleString() : '—'}
        </span>
      ),
    },
    {
      key: 'anomaly_id',
      header: 'Anomaly ID',
      width: '200px',
      render: (anomaly: Anomaly) => (
        <span className="text-primary-400 font-mono text-xs">{anomaly.anomaly_id}</span>
      ),
    },
    {
      key: 'source_type',
      header: 'Source',
      render: (anomaly: Anomaly) => (
        <Badge variant="info">{anomaly.source_type || 'unknown'}</Badge>
      ),
    },
    {
      key: 'rule_name',
      header: 'Rule',
      width: '200px',
      render: (anomaly: Anomaly) => (
        <span className="font-mono text-sm">{anomaly.rule_name}</span>
      ),
    },
    {
      key: 'severity',
      header: 'Severity',
      render: (anomaly: Anomaly) => {
        const variant = anomaly.severity === 'critical' || anomaly.severity === 'high' ? 'error' : anomaly.severity === 'medium' ? 'warning' : 'info';
        return <Badge variant={variant}>{anomaly.severity}</Badge>;
      },
    },
    {
      key: 'status',
      header: 'Status',
      render: (anomaly: Anomaly) => {
        const variant = anomaly.status === 'open' ? 'error' : anomaly.status === 'acknowledged' ? 'warning' : 'success';
        return <Badge variant={variant}>{anomaly.status}</Badge>;
      },
    },
    {
      key: 'reason',
      header: 'Reason',
      render: (anomaly: Anomaly) => (
        <span className="text-gray-300 max-w-xs truncate block" title={anomaly.reason}>
          {anomaly.reason}
        </span>
      ),
    },
  ];

  const totalPages = Math.ceil(total / pageSize);

  if (loading && anomalies.length === 0) {
    return <LoadingState message="Loading anomalies..." />;
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Anomalies</h1>
        <div className="flex items-center gap-2">
          <Button onClick={fetchAnomalies} variant="secondary">
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
        </div>
      </div>

      <Card>
        <div className="flex flex-col md:flex-row gap-4 mb-4">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
            <Input
              type="text"
              placeholder="Search anomalies..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-10"
            />
          </div>
          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-gray-400" />
            <Dropdown items={severityOptions} triggerLabel={severityFilter || 'Severity'} triggerIcon={<AlertTriangle className="w-4 h-4" />} align="right" />
            <Dropdown items={statusOptions} triggerLabel={statusFilter || 'Status'} triggerIcon={<AlertTriangle className="w-4 h-4" />} align="right" />
          </div>
        </div>

        {error ? (
          <EmptyState message={`Error: ${error}`} />
        ) : (
          <>
            <DataTable
              columns={columns}
              data={anomalies}
              keyExtractor={(anomaly) => anomaly.anomaly_id}
              onRowClick={() => {}}
              emptyMessage="No anomalies found"
            />

            {totalPages > 1 && (
              <div className="flex items-center justify-between mt-4 pt-4 border-t border-gray-700">
                <span className="text-sm text-gray-400">
                  Page {page} of {totalPages} ({total} total)
                </span>
                <div className="flex gap-2">
                  <Button
                    variant="secondary"
                    onClick={() => setPage((p) => Math.max(1, p - 1))}
                    disabled={page === 1}
                  >
                    <ChevronLeft className="w-4 h-4" />
                  </Button>
                  <Button
                    variant="secondary"
                    onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                    disabled={page === totalPages}
                  >
                    <ChevronRight className="w-4 h-4" />
                  </Button>
                </div>
              </div>
            )}
          </>
        )}
      </Card>

      <Card title="Anomaly Detection Rules">
        <div className="space-y-3 text-sm">
          <p className="text-gray-400">
            Rule-based anomaly detection runs on normalized OCSF events. Each anomaly includes
            a human-readable reason explaining exactly which rule fired and the field values that triggered it.
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-3 bg-dark-200 rounded">
              <p className="font-medium text-gray-100">Failed Auth Spike</p>
              <p className="text-gray-400">Detects 20+ failed logins from single source.ip in 5 minutes</p>
            </div>
            <div className="p-3 bg-dark-200 rounded">
              <p className="font-medium text-gray-100">Unusual Port Activity</p>
              <p className="text-gray-400">Flags destination ports not seen in source's historical baseline</p>
            </div>
            <div className="p-3 bg-dark-200 rounded">
              <p className="font-medium text-gray-100">Severity Escalation</p>
              <p className="text-gray-400">Sudden cluster of high/critical severity events from one source</p>
            </div>
            <div className="p-3 bg-dark-200 rounded">
              <p className="font-medium text-gray-100">Protocol Anomaly</p>
              <p className="text-gray-400">Unexpected protocol usage relative to source profile</p>
            </div>
          </div>
        </div>
      </Card>
    </div>
  );
}