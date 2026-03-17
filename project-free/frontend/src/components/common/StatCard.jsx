import { TrendingUp, TrendingDown, Minus } from 'lucide-react';

export default function StatCard({ title, value, subtitle, icon: Icon, color = 'blue', trend }) {
  const colors = {
    blue:   { bg: 'bg-blue-50',   icon: 'text-blue-600',   border: 'border-blue-100' },
    red:    { bg: 'bg-red-50',    icon: 'text-red-600',    border: 'border-red-100' },
    green:  { bg: 'bg-green-50',  icon: 'text-green-600',  border: 'border-green-100' },
    yellow: { bg: 'bg-yellow-50', icon: 'text-yellow-600', border: 'border-yellow-100' },
    purple: { bg: 'bg-purple-50', icon: 'text-purple-600', border: 'border-purple-100' },
  };
  const c = colors[color] || colors.blue;

  return (
    <div className={`bg-white rounded-xl border ${c.border} p-5 flex items-start gap-4`}>
      {Icon && (
        <div className={`${c.bg} p-2.5 rounded-lg flex-shrink-0`}>
          <Icon className={`${c.icon} h-5 w-5`}/>
        </div>
      )}
      <div className="flex-1 min-w-0">
        <p className="text-xs font-medium text-gray-500 uppercase tracking-wide">{title}</p>
        <p className="text-2xl font-bold text-gray-900 mt-0.5">{value ?? '—'}</p>
        {(subtitle || trend != null) && (
          <div className="flex items-center gap-1 mt-1">
            {trend != null && (
              trend > 0  ? <TrendingUp  size={12} className="text-red-500"/>   :
              trend < 0  ? <TrendingDown size={12} className="text-green-500"/> :
                           <Minus       size={12} className="text-gray-400"/>
            )}
            {subtitle && <p className="text-xs text-gray-500">{subtitle}</p>}
          </div>
        )}
      </div>
    </div>
  );
}
