import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, Filter, ChevronLeft, ChevronRight } from 'lucide-react';
import { Card, DataTable, Badge, LoadingState, EmptyState } from '../components';
import type { NormalizedEvent } from '../api';

export function EventsPage() {
  const navigate = useNavigate();
  const [events, setEvents] = useState<NormalizedEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [searchQuery, setSearchQuery] = useState('');
  const [sourceFilter, setSourceFilter] = useState('');
  const pageSize = 50;

  const fetchEvents = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`/api/v1/events?page=${page}&page_size=${pageSize}${searchQuery ? `&query=${encodeURIComponent(searchQuery)}` : ''}${sourceFilter ? `&source_type=${encodeURIComponent(sourceFilter)}` : ''}`);
      if (!response.ok) {
        throw new Error('Failed to fetch events');
      }
      const data = await response.json();
      setEvents(data.events || []);
      setTotal(data.total || 0);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load events');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEvents();
  }, [page, searchQuery, sourceFilter]);

  useEffect(() => {
    const interval = setInterval(() => {
      fetchEvents();
    }, 2000);
    return () => clearInterval(interval);
  }, [page, searchQuery, sourceFilter]);

  const columns = [
    {
      key: 'event_timestamp',
      header: 'Timestamp',
      width: '180px',
      render: (event: NormalizedEvent) => (
        <span className="text-gray-400">
          {event.event_timestamp ? new Date(event.event_timestamp).toLocaleString() : '—'}
        </span>
      ),
    },
    {
      key: 'event_id',
      header: 'Event ID',
      width: '200px',
      render: (event: NormalizedEvent) => (
        <span className="text-primary-400 font-mono text-xs">{event.event_id}</span>
      ),
    },
    {
      key: 'source_type',
      header: 'Source',
      render: (event: NormalizedEvent) => (
        <Badge variant="info">{event.source_type || 'unknown'}</Badge>
      ),
    },
    {
      key: 'action',
      header: 'Action',
      render: (event: NormalizedEvent) => {
        const action = event.ocsf?.event?.action || 'unknown';
        const variant = action === 'allow' ? 'success' : action === 'deny' ? 'error' : 'warning';
        return <Badge variant={variant}>{action}</Badge>;
      },
    },
    {
      key: 'severity',
      header: 'Severity',
      render: (event: NormalizedEvent) => {
        const severity = event.ocsf?.event?.severity || 'unknown';
        const variant = severity === 'high' || severity === 'critical' ? 'error' : severity === 'medium' ? 'warning' : 'info';
        return <Badge variant={variant}>{severity}</Badge>;
      },
    },
    {
      key: 'source_ip',
      header: 'Source IP',
      render: (event: NormalizedEvent) => (
        <span className="font-mono text-sm">{event.ocsf?.source?.ip || '—'}</span>
      ),
    },
    {
      key: 'dest_ip',
      header: 'Dest IP',
      render: (event: NormalizedEvent) => (
        <span className="font-mono text-sm">{event.ocsf?.destination?.ip || '—'}</span>
      ),
    },
    {
      key: 'protocol',
      header: 'Protocol',
      render: (event: NormalizedEvent) => (
        <span>{event.ocsf?.network?.protocol || '—'}</span>
      ),
    },
  ];

  const totalPages = Math.ceil(total / pageSize);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Events</h1>
        <span className="text-gray-400">
          {total} total events
        </span>
      </div>

      <Card>
        <div className="flex flex-col md:flex-row gap-4 mb-4">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
            <input
              type="text"
              placeholder="Search events..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="input w-full pl-10"
            />
          </div>
          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-gray-400" />
            <select
              value={sourceFilter}
              onChange={(e) => setSourceFilter(e.target.value)}
              className="input"
            >
              <option value="">All Sources</option>
              <option value="firewall">Firewall</option>
              <option value="router">Router</option>
              <option value="ids">IDS</option>
            </select>
          </div>
        </div>

        {loading ? (
          <LoadingState message="Loading events..." />
        ) : error ? (
          <EmptyState message={`Error: ${error}`} />
        ) : (
          <>
            <DataTable
              columns={columns}
              data={events}
              keyExtractor={(event) => event.event_id}
              onRowClick={(event) => navigate(`/events/${event.event_id}`)}
              emptyMessage="No events found"
            />

            {totalPages > 1 && (
              <div className="flex items-center justify-between mt-4 pt-4 border-t border-gray-700">
                <span className="text-sm text-gray-400">
                  Page {page} of {totalPages}
                </span>
                <div className="flex gap-2">
                  <button
                    onClick={() => setPage((p) => Math.max(1, p - 1))}
                    disabled={page === 1}
                    className="btn-secondary disabled:opacity-50"
                  >
                    <ChevronLeft className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                    disabled={page === totalPages}
                    className="btn-secondary disabled:opacity-50"
                  >
                    <ChevronRight className="w-4 h-4" />
                  </button>
                </div>
              </div>
            )}
          </>
        )}
      </Card>
    </div>
  );
}
