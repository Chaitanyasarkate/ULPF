import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, CheckCircle, XCircle, AlertTriangle, Eye, ChevronDown, Copy, Download } from 'lucide-react';
import { Card, Badge, LoadingState, ErrorState } from '../components';
import { lineageApi } from '../api';
import type { LineageVerification, RawEventRecovery, LineageChain } from '../api';

interface ConversionResult {
  event_id: string;
  raw_event_id: string;
  output_format: string;
  formatter_id: string;
  formatter_version: string;
  schema_version: string;
  conversion_timestamp: string;
  payload: string;
}

const OUTPUT_FORMATS = [
  { value: 'json', label: 'JSON' },
  { value: 'cef', label: 'CEF' },
  { value: 'leef', label: 'LEEF' },
  { value: 'xml', label: 'XML' },
  { value: 'csv', label: 'CSV' },
  { value: 'syslog', label: 'Syslog' },
  { value: 'ocsf', label: 'OCSF' },
];

export function EventDetailPage() {
  const { eventId } = useParams<{ eventId: string }>();
  const navigate = useNavigate();
  const [event, setEvent] = useState<Record<string, unknown> | null>(null);
  const [lineage, setLineage] = useState<LineageChain | null>(null);
  const [verification, setVerification] = useState<LineageVerification | null>(null);
  const [rawEvent, setRawEvent] = useState<RawEventRecovery | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showRawPayload, setShowRawPayload] = useState(false);
  const [selectedFormat, setSelectedFormat] = useState('json');
  const [conversionResult, setConversionResult] = useState<ConversionResult | null>(null);
  const [converting, setConverting] = useState(false);
  const [conversionError, setConversionError] = useState<string | null>(null);

  const handleConvert = async () => {
    if (!eventId) return;
    setConverting(true);
    setConversionError(null);
    setConversionResult(null);

    try {
      const response = await fetch('/api/v1/convert', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          event_id: eventId,
          output_format: selectedFormat,
        }),
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.message || 'Conversion failed');
      }

      const data = await response.json();
      setConversionResult(data);
    } catch (err) {
      setConversionError(err instanceof Error ? err.message : 'Failed to convert event');
    } finally {
      setConverting(false);
    }
  };

  const copyToClipboard = async () => {
    if (conversionResult?.payload) {
      await navigator.clipboard.writeText(conversionResult.payload);
    }
  };

  const downloadPayload = () => {
    if (!conversionResult?.payload) return;
    const blob = new Blob([conversionResult.payload], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `event-${eventId}-${selectedFormat}.${selectedFormat === 'ocsf' || selectedFormat === 'json' ? 'json' : selectedFormat === 'xml' ? 'xml' : 'txt'}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  useEffect(() => {
    const fetchData = async () => {
      if (!eventId) return;
      setLoading(true);
      setError(null);

      try {
        const [eventRes, lineageRes, verificationRes, rawRes] = await Promise.allSettled([
          fetch(`/api/v1/events/${encodeURIComponent(eventId)}`),
          lineageApi.getLineageChain(eventId),
          lineageApi.verifyLineage(eventId),
          lineageApi.recoverRawEvent(eventId),
        ]);

        if (eventRes.status === 'fulfilled' && eventRes.value.ok) {
          setEvent(await eventRes.value.json());
        }

        if (lineageRes.status === 'fulfilled') {
          setLineage(lineageRes.value);
        }

        if (verificationRes.status === 'fulfilled') {
          setVerification(verificationRes.value);
        }

        if (rawRes.status === 'fulfilled') {
          setRawEvent(rawRes.value);
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load event');
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [eventId]);

  if (loading) {
    return <LoadingState message="Loading event details..." />;
  }

  if (error && !event) {
    return <ErrorState message={error} onRetry={() => window.location.reload()} />;
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <button onClick={() => navigate('/events')} className="btn-secondary">
          <ArrowLeft className="w-4 h-4 mr-2" />
          Back to Events
        </button>
        <h1 className="text-2xl font-bold">Event Details</h1>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card title="Basic Information">
          <div className="space-y-3">
            <div className="flex justify-between">
              <span className="text-gray-400">Event ID</span>
              <span className="font-mono text-sm text-primary-400">{eventId}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Source Type</span>
              <Badge variant="info">{event?.source_type as string || '—'}</Badge>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Format</span>
              <span>{event?.format as string || '—'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Timestamp</span>
              <span className="text-gray-300">
                {event?.event_timestamp ? new Date(event.event_timestamp as string).toLocaleString() : '—'}
              </span>
            </div>
          </div>
        </Card>

        <Card title="Network Information">
          <div className="space-y-3">
            <div className="flex justify-between">
              <span className="text-gray-400">Source IP</span>
              <span className="font-mono">{((event?.ocsf as any)?.source?.ip as string) || '—'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Source Port</span>
              <span>{((event?.ocsf as any)?.source?.port as number) || '—'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Destination IP</span>
              <span className="font-mono">{((event?.ocsf as any)?.destination?.ip as string) || '—'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Destination Port</span>
              <span>{((event?.ocsf as any)?.destination?.port as number) || '—'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Protocol</span>
              <span>{((event?.ocsf as any)?.network?.protocol as string) || '—'}</span>
            </div>
          </div>
        </Card>

        <Card title="Event Classification">
          <div className="space-y-3">
            <div className="flex justify-between">
              <span className="text-gray-400">Action</span>
              <Badge variant={(event?.ocsf as any)?.event?.action === 'allow' ? 'success' : 'error'}>
                {((event?.ocsf as any)?.event?.action as string) || 'unknown'}
              </Badge>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Severity</span>
              <Badge variant="warning">
                {((event?.ocsf as any)?.event?.severity as string) || 'unknown'}
              </Badge>
            </div>
          </div>
        </Card>

        <Card title="Processing Information">
          <div className="space-y-3">
            <div className="flex justify-between">
              <span className="text-gray-400">Parser</span>
              <span className="font-mono text-sm">{event?.parser_id as string || '—'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Parser Version</span>
              <span>{event?.parser_version as string || '—'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Schema Version</span>
              <span>{event?.schema_version as string || '—'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">SHA-256</span>
              <span className="font-mono text-xs text-gray-300">{event?.sha256 as string || '—'}</span>
            </div>
          </div>
        </Card>
      </div>

      <Card title="Lineage Verification">
        <div className="flex items-center gap-4 mb-6">
          {verification?.status === 'VALID' && (
            <div className="flex items-center gap-2 text-green-400">
              <CheckCircle className="w-6 h-6" />
              <span className="font-semibold">Integrity Verified</span>
            </div>
          )}
          {verification?.status === 'INVALID' && (
            <div className="flex items-center gap-2 text-red-400">
              <XCircle className="w-6 h-6" />
              <span className="font-semibold">Integrity Verification Failed</span>
            </div>
          )}
          {verification?.status === 'UNAVAILABLE' && (
            <div className="flex items-center gap-2 text-yellow-400">
              <AlertTriangle className="w-6 h-6" />
              <span className="font-semibold">Verification Unavailable</span>
            </div>
          )}
        </div>

        <div className="space-y-3">
          <div className="flex justify-between">
            <span className="text-gray-400">Raw Object Exists</span>
            <span>{verification?.raw_object_exists ? 'Yes' : 'No'}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-400">SHA-256 Verified</span>
            <span>{verification?.sha256_verified ? 'Yes' : 'No'}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-400">Normalized Event Exists</span>
            <span>{verification?.normalized_object_exists ? 'Yes' : 'No'}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-400">Lineage Complete</span>
            <span>{verification?.lineage_complete ? 'Yes' : 'No'}</span>
          </div>
          {verification?.errors && verification.errors.length > 0 && (
            <div className="mt-2 p-2 bg-red-900/30 rounded text-sm text-red-300">
              {verification.errors.map((err, i) => (
                <div key={i}>{err}</div>
              ))}
            </div>
          )}
        </div>
      </Card>

      <Card title="Event Lineage">
        <div className="space-y-4">
          <div className="p-4 bg-dark-200 rounded-lg border border-gray-700">
            <div className="text-sm text-gray-400 mb-1">Normalized Event</div>
            <div className="font-mono text-primary-400">{lineage?.event_id || eventId}</div>
          </div>

          <div className="flex justify-center">
            <ChevronDown className="w-5 h-5 text-gray-500" />
          </div>

          <div className="p-4 bg-dark-200 rounded-lg border border-gray-700">
            <div className="text-sm text-gray-400 mb-1">Parsed Event</div>
            <div className="font-mono text-yellow-400">
              {lineage?.ancestors?.find(a => a.relationship_type === 'parsed_from')?.parent_event_id || '—'}
            </div>
          </div>

          <div className="flex justify-center">
            <ChevronDown className="w-5 h-5 text-gray-500" />
          </div>

          <div className="p-4 bg-dark-200 rounded-lg border border-gray-700">
            <div className="text-sm text-gray-400 mb-1">Raw Event</div>
            <div className="font-mono text-green-400">
              {lineage?.raw_event_id || '—'}
            </div>
          </div>

          <div className="flex justify-center">
            <ChevronDown className="w-5 h-5 text-gray-500" />
          </div>

          <div className="p-4 bg-dark-200 rounded-lg border border-gray-700">
            <div className="text-sm text-gray-400 mb-1">MinIO Raw Object</div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-gray-300">{rawEvent?.object_key || '—'}</span>
              {rawEvent?.verified && <CheckCircle className="w-4 h-4 text-green-400" />}
            </div>
          </div>
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
            {rawEvent?.raw_payload || event?.raw_payload as string || 'No raw payload available'}
          </pre>
        )}
      </Card>

      <Card title="Normalized Fields (OCSF)">
        <pre className="p-4 bg-dark-300 rounded-lg overflow-x-auto text-sm font-mono text-gray-300">
          {JSON.stringify(event?.ocsf || {}, null, 2)}
        </pre>
      </Card>

      <Card title="Original Parsed Fields">
        <pre className="p-4 bg-dark-300 rounded-lg overflow-x-auto text-sm font-mono text-gray-300">
          {JSON.stringify(event?.parsed_fields || {}, null, 2)}
        </pre>
      </Card>

      <Card title="Convert Event">
        <div className="space-y-4">
          <div className="flex items-center gap-4">
            <label className="text-gray-400">Output Format:</label>
            <select
              value={selectedFormat}
              onChange={(e) => setSelectedFormat(e.target.value)}
              className="bg-dark-200 border border-gray-600 rounded px-3 py-2 text-gray-200 focus:outline-none focus:border-primary-500"
            >
              {OUTPUT_FORMATS.map((fmt) => (
                <option key={fmt.value} value={fmt.value}>
                  {fmt.label}
                </option>
              ))}
            </select>
            <button
              onClick={handleConvert}
              disabled={converting}
              className="btn-primary flex items-center gap-2"
            >
              {converting ? 'Converting...' : 'Convert'}
            </button>
          </div>

          {conversionError && (
            <div className="p-3 bg-red-900/30 border border-red-700 rounded text-red-300">
              {conversionError}
            </div>
          )}

          {conversionResult && (
            <div className="space-y-4">
              <div className="flex items-center gap-4 text-sm">
                <div className="flex items-center gap-2">
                  <span className="text-gray-400">Format:</span>
                  <Badge variant="info">{conversionResult.output_format.toUpperCase()}</Badge>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-gray-400">Formatter:</span>
                  <span className="font-mono text-gray-300">{conversionResult.formatter_id}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-gray-400">Version:</span>
                  <span className="text-gray-300">{conversionResult.formatter_version}</span>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={copyToClipboard}
                  className="btn-secondary flex items-center gap-2"
                >
                  <Copy className="w-4 h-4" />
                  Copy
                </button>
                <button
                  onClick={downloadPayload}
                  className="btn-secondary flex items-center gap-2"
                >
                  <Download className="w-4 h-4" />
                  Download
                </button>
              </div>

              <pre className="p-4 bg-dark-300 rounded-lg overflow-x-auto text-sm font-mono text-gray-300 max-h-96">
                {conversionResult.payload}
              </pre>
            </div>
          )}
        </div>
      </Card>
    </div>
  );
}
