interface StatusIndicatorProps {
  status: 'healthy' | 'degraded' | 'unhealthy' | 'unknown';
  showLabel?: boolean;
}

export function StatusIndicator({ status, showLabel = true }: StatusIndicatorProps) {
  const statusConfig = {
    healthy: {
      color: 'bg-green-500',
      label: 'Healthy',
    },
    degraded: {
      color: 'bg-yellow-500',
      label: 'Degraded',
    },
    unhealthy: {
      color: 'bg-red-500',
      label: 'Unhealthy',
    },
    unknown: {
      color: 'bg-gray-500',
      label: 'Unknown',
    },
  };

  const config = statusConfig[status];

  return (
    <div className="flex items-center gap-2">
      <div className={`w-2 h-2 rounded-full ${config.color}`} />
      {showLabel && <span className="text-sm text-gray-300">{config.label}</span>}
    </div>
  );
}
