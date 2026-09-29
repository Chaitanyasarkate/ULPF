import { LucideIcon } from 'lucide-react';

interface KpiCardProps {
  title: string;
  value: string | number;
  icon: LucideIcon;
  trend?: {
    value: number;
    positive: boolean;
  };
  status?: 'success' | 'warning' | 'error' | 'neutral';
  onClick?: () => void;
}

export function KpiCard({ title, value, icon: Icon, trend, status = 'neutral', onClick }: KpiCardProps) {
  const statusColors = {
    success: 'text-green-400',
    warning: 'text-yellow-400',
    error: 'text-red-400',
    neutral: 'text-blue-400',
  };

  return (
    <div
      className={`card flex flex-col gap-3 ${onClick ? 'cursor-pointer hover:border-primary-500 transition-colors' : ''}`}
      onClick={onClick}
      role={onClick ? 'button' : undefined}
      tabIndex={onClick ? 0 : undefined}
    >
      <div className="flex items-center justify-between">
        <span className="text-gray-400 text-sm">{title}</span>
        <Icon className={`w-5 h-5 ${statusColors[status]}`} />
      </div>
      <div className="flex items-end gap-2">
        <span className="text-3xl font-bold text-white">{value}</span>
        {trend && (
          <span className={`text-sm ${trend.positive ? 'text-green-400' : 'text-red-400'}`}>
            {trend.positive ? '+' : ''}{trend.value}%
          </span>
        )}
      </div>
    </div>
  );
}
