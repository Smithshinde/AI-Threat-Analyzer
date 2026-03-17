import { Shield, AlertTriangle, FileText, Zap } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { useApi } from '../../hooks/useApi.js';
import { dashboardApi } from '../../services/api.js';
import Card from '../../components/common/Card.jsx';
import StatCard from '../../components/common/StatCard.jsx';
import Badge from '../../components/common/Badge.jsx';

const PIE_COLORS = ['#22c55e','#3b82f6','#eab308','#ef4444','#9ca3af'];

export default function CISODashboard() {
  const { data, loading } = useApi(() => dashboardApi.ciso());
  if (loading) return <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-10 w-10 border-b-2 border-blue-600"/></div>;

  const rm = data?.riskMetrics     || {};
  const cm = data?.controlMetrics  || {};
  const ps = data?.policyStats     || {};
  const fs = data?.findingStats    || {};

  const controlData  = Object.entries(cm.byStatus || {}).map(([k, v]) => ({ name: k.replace(/_/g,' '), value: v }));
  const findingData  = Object.entries(fs.bySeverity || {}).map(([k, v]) => ({ name: k, value: v }));

  return (
    <div className="space-y-6">
      {/* KPIs */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard title="Total Risks"         value={rm.total             || 0} icon={AlertTriangle} color="red"/>
        <StatCard title="Avg Risk Reduction"  value={`${rm.riskReduction  || 0}%`} icon={Shield} color="green" subtitle="Inherent → Residual"/>
        <StatCard title="Control Effectiveness" value={`${cm.avgEffectiveness || 0}%`} icon={Shield} color="blue"/>
        <StatCard title="Open Findings"       value={fs.byStatus?.open    || 0} icon={FileText}     color="yellow"/>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Risk by score */}
        <Card title="Risk by Rating">
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={[
              { name: 'Critical', value: rm.byScore?.critical || 0, fill: '#ef4444' },
              { name: 'High',     value: rm.byScore?.high     || 0, fill: '#f97316' },
              { name: 'Medium',   value: rm.byScore?.medium   || 0, fill: '#eab308' },
              { name: 'Low',      value: rm.byScore?.low      || 0, fill: '#22c55e' },
            ]}>
              <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0"/>
              <XAxis dataKey="name" tick={{ fontSize: 11 }}/>
              <YAxis tick={{ fontSize: 11 }}/>
              <Tooltip/>
              <Bar dataKey="value" radius={[4,4,0,0]}>
                {[{ fill:'#ef4444' },{ fill:'#f97316' },{ fill:'#eab308' },{ fill:'#22c55e' }].map((c,i) =>
                  <Cell key={i} fill={c.fill}/>
                )}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </Card>

        {/* Controls by status */}
        <Card title="Controls by Status">
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie data={controlData} innerRadius={50} outerRadius={75} dataKey="value">
                {controlData.map((_, i) => <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]}/>)}
              </Pie>
              <Tooltip/>
            </PieChart>
          </ResponsiveContainer>
          <div className="flex flex-wrap gap-2 mt-2">
            {controlData.map((d, i) => (
              <span key={d.name} className="text-xs text-gray-600 flex items-center gap-1">
                <span className="w-2 h-2 rounded-full" style={{ background: PIE_COLORS[i] }}/>
                {d.name}: {d.value}
              </span>
            ))}
          </div>
        </Card>

        {/* Audit findings */}
        <Card title="Audit Findings">
          {findingData.length ? (
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie data={findingData} innerRadius={50} outerRadius={75} dataKey="value">
                  {findingData.map((_, i) => <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]}/>)}
                </Pie>
                <Tooltip/>
              </PieChart>
            </ResponsiveContainer>
          ) : <p className="text-gray-400 text-sm text-center py-12">No findings</p>}
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent incidents */}
        <Card title="Recent Incidents" subtitle="Last 10">
          <div className="space-y-2">
            {(data?.recentIncidents || []).length === 0 && <p className="text-gray-400 text-sm">No incidents</p>}
            {(data?.recentIncidents || []).map(inc => (
              <div key={inc.id} className="flex items-center justify-between py-2 border-b border-gray-50 last:border-0">
                <div>
                  <p className="text-sm font-medium text-gray-900">{inc.title || 'Untitled'}</p>
                  <p className="text-xs text-gray-500">{new Date(inc.detected_at).toLocaleDateString()}</p>
                </div>
                <Badge status={inc.severity}/>
              </div>
            ))}
          </div>
        </Card>

        {/* Policy status */}
        <Card title="Policy Status">
          <div className="space-y-3">
            {Object.entries(ps.byStatus || {}).map(([status, count]) => (
              <div key={status} className="flex items-center justify-between">
                <Badge status={status}/>
                <span className="text-sm font-bold text-gray-900">{count}</span>
              </div>
            ))}
          </div>
          <div className="mt-4 pt-4 border-t border-gray-100">
            <p className="text-2xl font-bold text-gray-900">{ps.total || 0}</p>
            <p className="text-xs text-gray-500">Total policies</p>
          </div>
        </Card>
      </div>
    </div>
  );
}
