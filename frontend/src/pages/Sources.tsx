import { useState, useEffect } from 'react';
import { Plus, RefreshCw, Power, Pencil, Trash2, X } from 'lucide-react';
import { Card, Badge, DataTable, LoadingState, ErrorState, EmptyState } from '../components';
import { sourcesApi, type SourceProfile, type SourceCreateRequest } from '../api';

export function SourcesPage() {
  const [sources, setSources] = useState<SourceProfile[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [formData, setFormData] = useState<SourceCreateRequest>({
    source_id: '',
    source_name: '',
    source_type: 'firewall',
    format: 'syslog',
    parser_id: '',
    parser_version: '1.0.0',
    schema_version: '1.0.0',
    enabled: true,
  });
  const [formError, setFormError] = useState<string | null>(null);

  const fetchSources = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await sourcesApi.listSources();
      setSources(response.sources);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load sources');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSources();
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);

    if (!formData.source_id || !formData.source_name || !formData.parser_id) {
      setFormError('source_id, source_name, and parser_id are required');
      return;
    }

    try {
      await sourcesApi.createSource(formData);
      setShowForm(false);
      setFormData({
        source_id: '',
        source_name: '',
        source_type: 'firewall',
        format: 'syslog',
        parser_id: '',
        parser_version: '1.0.0',
        schema_version: '1.0.0',
        enabled: true,
      });
      fetchSources();
    } catch (err) {
      setFormError(err instanceof Error ? err.message : 'Failed to create source');
    }
  };

  const handleToggleEnabled = async (source: SourceProfile) => {
    try {
      if (source.enabled) {
        await sourcesApi.disableSource(source.source_id);
      } else {
        await sourcesApi.enableSource(source.source_id);
      }
      fetchSources();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update source');
    }
  };

  const handleDelete = async (sourceId: string) => {
    if (!confirm('Are you sure you want to delete this source?')) return;
    try {
      await sourcesApi.deleteSource(sourceId);
      fetchSources();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete source');
    }
  };

  const columns = [
    {
      key: 'source_id',
      header: 'Source ID',
      render: (source: SourceProfile) => (
        <span className="font-mono text-xs">{source.source_id}</span>
      ),
    },
    {
      key: 'source_name',
      header: 'Name',
      render: (source: SourceProfile) => <span className="font-medium">{source.source_name}</span>,
    },
    {
      key: 'source_type',
      header: 'Type',
      render: (source: SourceProfile) => <Badge variant="info">{source.source_type}</Badge>,
    },
    {
      key: 'format',
      header: 'Format',
    },
    {
      key: 'parser_id',
      header: 'Parser',
      render: (source: SourceProfile) => (
        <span className="font-mono text-xs">{source.parser_id}</span>
      ),
    },
    {
      key: 'status',
      header: 'Status',
      render: (source: SourceProfile) => (
        <Badge variant={source.enabled ? 'success' : 'error'}>
          {source.enabled ? 'Active' : 'Inactive'}
        </Badge>
      ),
    },
    {
      key: 'actions',
      header: 'Actions',
      render: (source: SourceProfile) => (
        <div className="flex gap-2">
          <button
            onClick={(e) => {
              e.stopPropagation();
              handleToggleEnabled(source);
            }}
            className="p-1 hover:bg-gray-700 rounded"
            title={source.enabled ? 'Disable' : 'Enable'}
          >
            <Power className="w-4 h-4" />
          </button>
          <button
            onClick={(e) => {
              e.stopPropagation();
              handleDelete(source.source_id);
            }}
            className="p-1 hover:bg-red-900 rounded text-red-400"
            title="Delete"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Sources</h1>
        <div className="flex gap-2">
          <button onClick={fetchSources} className="btn-secondary">
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </button>
          <button onClick={() => setShowForm(true)} className="btn-primary">
            <Plus className="w-4 h-4 mr-2" />
            Add Source
          </button>
        </div>
      </div>

      {showForm && (
        <Card title="Add New Source">
          <form onSubmit={handleSubmit} className="space-y-4">
            {formError && (
              <div className="p-3 bg-red-900/30 text-red-400 rounded text-sm">
                {formError}
              </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm text-gray-400 mb-1">Source ID *</label>
                <input
                  type="text"
                  value={formData.source_id}
                  onChange={(e) => setFormData({ ...formData, source_id: e.target.value })}
                  className="input w-full"
                  placeholder="e.g., firewall.vendor_x"
                />
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">Source Name *</label>
                <input
                  type="text"
                  value={formData.source_name}
                  onChange={(e) => setFormData({ ...formData, source_name: e.target.value })}
                  className="input w-full"
                  placeholder="e.g., Vendor X Firewall"
                />
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">Source Type</label>
                <select
                  value={formData.source_type}
                  onChange={(e) => setFormData({ ...formData, source_type: e.target.value })}
                  className="input w-full"
                >
                  <option value="firewall">Firewall</option>
                  <option value="router">Router</option>
                  <option value="ids">IDS</option>
                  <option value="vpn">VPN</option>
                  <option value="custom">Custom</option>
                </select>
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">Format</label>
                <select
                  value={formData.format}
                  onChange={(e) => setFormData({ ...formData, format: e.target.value })}
                  className="input w-full"
                >
                  <option value="syslog">Syslog</option>
                  <option value="json">JSON</option>
                  <option value="cef">CEF</option>
                  <option value="leef">LEEF</option>
                  <option value="custom">Custom</option>
                </select>
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">Parser ID *</label>
                <input
                  type="text"
                  value={formData.parser_id}
                  onChange={(e) => setFormData({ ...formData, parser_id: e.target.value })}
                  className="input w-full"
                  placeholder="e.g., firewall_syslog_v1"
                />
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">Parser Version</label>
                <input
                  type="text"
                  value={formData.parser_version}
                  onChange={(e) => setFormData({ ...formData, parser_version: e.target.value })}
                  className="input w-full"
                />
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">Vendor</label>
                <input
                  type="text"
                  value={formData.vendor || ''}
                  onChange={(e) => setFormData({ ...formData, vendor: e.target.value })}
                  className="input w-full"
                />
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-1">Product</label>
                <input
                  type="text"
                  value={formData.product || ''}
                  onChange={(e) => setFormData({ ...formData, product: e.target.value })}
                  className="input w-full"
                />
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-4">
              <button
                type="button"
                onClick={() => setShowForm(false)}
                className="btn-secondary"
              >
                Cancel
              </button>
              <button type="submit" className="btn-primary">
                Create Source
              </button>
            </div>
          </form>
        </Card>
      )}

      <Card>
        {loading ? (
          <LoadingState message="Loading sources..." />
        ) : error ? (
          <ErrorState message={error} onRetry={fetchSources} />
        ) : (
          <DataTable
            columns={columns}
            data={sources}
            keyExtractor={(source) => source.source_id}
            emptyMessage="No sources registered"
          />
        )}
      </Card>
    </div>
  );
}
