import { STATUS_COLORS } from '../../utils/constants.js';

export default function Badge({ status, label, className = '' }) {
  const color = STATUS_COLORS[status] || 'bg-gray-100 text-gray-700';
  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${color} ${className}`}>
      {label || status?.replace(/_/g, ' ')}
    </span>
  );
}
