import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, Eye, ChevronDown } from 'lucide-react';
import { Card, LoadingState, ErrorState } from '../components';
import { lineageApi } from '../api';
import type { RawEventRecovery, LineageChain } from '../api';

export function LineagePage() {
  const { rawEventId } = useParams<{ rawEventId: string }>();
  const navigate = useNavigate();
  const [lineage, setLineage] = useState<LineageChain | null>(null);
  const [rawEvent, setRawEvent] = useState<RawEventRecovery | null>(null);
  const [parsedEvent, setParsedEvent] = useState<Record<string, unknown> | null>(null);
  const [normalizedEvent, setNormalizedEvent] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showRawPayload, setShowRawPayload] = useState(false);

  useEffect(() => {
    const fetchData = async () => {
      if (!rawEventId) return;
      setLoading(true);
      setError(null);

      try {
        const [byRawRes, rawRes] = await Promise.allSettled([
          lineageApi.getLineageByRaw(rawEventId),
          lineageApi.recoverRawEvent(rawEventId),
        ]);

        if (byRawRes.status === 'fulfilled') {
          const data = byRawRes.value;
          setParsedEvent(data.parsed as Record<string, unknown> | null);
          setNormalizedEvent(data.normalized as Record<string, unknown> | null);
          setLineage({
            event_id: rawEventId,
            raw_event_id: rawEventId,
            ancestors: data.lineage_records || [],
            descendants: [],
          });
        }

        if (rawRes.status === 'fulfilled') {
          setRawEvent(rawRes.value);
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load lineage');
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [rawEventId]);

  if (loading) {
    return <LoadingState message="Loading lineage..." />;
  }

  if (error && !lineage) {
    return <ErrorState message={error} onRetry={() => window.location.reload()} />;
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <button onClick={() => navigate('/events')} className="btn-secondary">
          <ArrowLeft className="w-4 h-4 mr-2" />
          Back to Events
        </button>
        <h1 className="text-2xl font-bold">Lineage</h1>
      </div>

      <Card title="Raw Event ID">
        <div className="font-mono text-primary-400">{rawEventId}</div>
      </Card>

      <Card title="Event Lineage">
        <div className="space-y-4">
          <div className="p-4 bg-dark-200 rounded-lg border border-gray-700">
            <div className="text-sm text-gray-400 mb-1">Raw Event</div>
            <div className="font-mono text-green-400">{rawEventId}</div>
          </div>

          {parsedEvent && (
            <>
              <div className="flex justify-center">
                <ChevronDown className="w-5 h-5 text-gray-500" />
              </div>
              <div className="p-4 bg-dark-200 rounded-lg border border-gray-700">
                <div className="text-sm text-gray-400 mb-1">Parsed Event</div>
                <div className="font-mono text-yellow-400">
                  {(parsedEvent as { event_id?: string }).event_id || '—'}
                </div>
              </div>
            </>
          )}

          {normalizedEvent && (
            <>
              <div className="flex justify-center">
                <ChevronDown className="w-5 h-5 text-gray-500" />
              </div>
              <div className="p-4 bg-dark-200 rounded-lg border border-gray-700">
                <div className="text-sm text-gray-400 mb-1">Normalized Event</div>
                <div className="font-mono text-primary-400">
                  {(normalizedEvent as { event_id?: string }).event_id || '—'}
                </div>
              </div>
            </>
          )}
        </div>
      </Card>

      <Card title="Raw Event Payload">
        <button
          onClick={() => setShowRawPayload(!showRawPayload)}
          className="btn-secondary flex items-center gap-2 mb-4"
        >
          <Eye className="w-4 h-4" />
          {showRawPayload ? 'Hide' : 'Show'} Original Payload
        </button>
        {showRawPayload && (
          <pre className="p-4 bg-dark-300 rounded-lg overflow-x-auto text-sm font-mono text-gray-300">
            {rawEvent?.raw_payload || (parsedEvent as { raw_payload?: string })?.raw_payload || 'No raw payload available'}
          </pre>
        )}
      </Card>

      {parsedEvent && (
        <Card title="Parsed Fields">
          <pre className="p-4 bg-dark-300 rounded-lg overflow-x-auto text-sm font-mono text-gray-300">
            {JSON.stringify(parsedEvent, null, 2)}
          </pre>
        </Card>
      )}

      {normalizedEvent && (
        <Card title="Normalized Fields (OCSF)">
          <pre className="p-4 bg-dark-300 rounded-lg overflow-x-auto text-sm font-mono text-gray-300">
            {JSON.stringify((normalizedEvent as { ocsf?: unknown }).ocsf || {}, null, 2)}
          </pre>
        </Card>
      )}
    </div>
  );
}