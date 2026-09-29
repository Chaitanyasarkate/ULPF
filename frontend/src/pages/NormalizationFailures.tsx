import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { AlertTriangle, ExternalLink } from 'lucide-react';
import { Card, DataTable, LoadingState, ErrorState, EmptyState } from '../components';
import { failuresApi, type FailureRecord } from '../api';

export function NormalizationFailuresPage() {
  const navigate = useNavigate();
  const [failures, setFailures] = useState<FailureRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchFailures = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await failuresApi.listNormalizationFailures();
      setFailures(response.failures);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load normalization failures');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFailures();
    const interval = setInterval(fetchFailures, 2000);
    return () => clearInterval(interval);
  }, []);

  const columns = [
    {
      key: 'raw_event_id',
      header: 'Raw Event ID',
      render: (row: FailureRecord) => (
        <button
          onClick={() => navigate(`/lineage/raw/${row.raw_event_id}`)}
          className="font-mono text-xs text-primary-400 hover:text-primary-300 hover:underline flex items-center gap-1"
          title="View lineage"
        >
          {row.raw_event_id}
          <ExternalLink className="w-3 h-3" />
        </button>
      ),
    },
    {
      key: 'source_id',
      header: 'Source',
      render: (row: FailureRecord) => (
        <span className="font-mono text-xs">{row.source_id}</span>
      ),
    },
    {
      key: 'source_type',
      header: 'Type',
      render: (row: FailureRecord) => <span className="badge badge-info">{row.source_type}</span>,
    },
    {
      key: 'format',
      header: 'Format',
    },
    {
      key: 'code',
      header: 'Error Code',
      render: (row: FailureRecord) => (
        <span className="font-mono text-xs text-red-400">{row.code}</span>
      ),
    },
    {
      key: 'message',
      header: 'Message',
      render: (row: FailureRecord) => (
        <span className="text-sm text-gray-300 truncate block max-w-md" title={row.message}>
          {row.message}
        </span>
      ),
    },
    {
      key: 'received_at',
      header: 'Received At',
      render: (row: FailureRecord) => (
        <span className="text-xs text-gray-400">
          {new Date(row.received_at).toLocaleString()}
        </span>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Normalization Failures</h1>
        <span className="text-sm text-gray-400">
          {failures.length} record{failures.length !== 1 ? 's' : ''}
        </span>
      </div>

      <Card>
        {loading ? (
          <LoadingState message="Loading normalization failures..." />
        ) : error ? (
          <ErrorState message={error} onRetry={fetchFailures} />
        ) : failures.length === 0 ? (
          <EmptyState
            icon={<AlertTriangle className="w-8 h-8" />}
            message="No normalization failures detected"
          />
        ) : (
          <DataTable
            columns={columns}
            data={failures}
            keyExtractor={(row) => row.raw_event_id}
          />
        )}
      </Card>
    </div>
  );
}
