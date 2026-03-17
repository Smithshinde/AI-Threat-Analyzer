import { AlertTriangle, Shield, Zap, FileText, TrendingUp } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, LineChart, Line } from 'recharts';
import { useApi } from '../../hooks/useApi.js';
import { dashboardApi, reportsApi } from '../../services/api.js';
import Card from '../../components/common/Card.jsx';
import StatCard from '../../components/common/StatCard.jsx';
import { CompliancePie } from '../../components/charts/ComplianceChart.jsx';
import RiskHeatmap from '../../components/charts/RiskHeatmap.jsx';

export default function ExecutiveDashboard() {
  const { data: dash, loading }     = useApi(() => dashboardApi.executive());
  const { data: trend }             = useApi(() => reportsApi.riskTrend(6));

  if (loading) return <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-10 w-10 border-b-2 border-blue-600"/></div>;

  const risks      = dash?.risks || {};
  const compliance = dash?.compliance || [];
  const incidents  = dash?.incidents || {};

  // Aggregate compliance for pie
  const compAgg = compliance.reduce(
    (acc, f) => ({
      compliant:    acc.compliant    + (f.compliant    || 0),
      partial:      acc.partial      + (f.partial      || 0),
      non_compliant:acc.non_compliant+ (f.non_compliant|| 0),
      not_assessed: acc.not_assessed + (f.not_assessed || 0),
    }),
    { compliant: 0, partial: 0, non_compliant: 0, not_assessed: 0 }
  );

  return (
    <div className="space-y-6">
      {/* Key messages */}
      {dash?.activity && (
        <div className="bg-blue-50 border border-blue-200 rounded-xl p-4">
          <p className="text-sm font-semibold text-blue-900 mb-1">Board-Level Summary</p>
          <p className="text-xs text-blue-700">
            {risks.critical_risks > 0 ? `⚠️ ${risks.critical_risks} critical risks require attention. ` : ''}
            {incidents?.bySeverity?.p1_critical > 0 ? `🚨 ${incidents.bySeverity.p1_critical} P1 incidents active. ` : ''}
            {compliance.some(c => c.compliance_percentage < 70) ? `📋 Some frameworks below 70% compliance. ` : '✅ No critical board-level issues.'}
          </p>
        </div>
      )}

      {/* KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard title="Total Risks"      value={risks.total_risks    || 0} icon={AlertTriangle} color="red"    subtitle={`${risks.critical_risks || 0} critical`}/>
        <StatCard title="Open Risks"       value={risks.open_risks     || 0} icon={TrendingUp}    color="orange" subtitle={`Avg score: ${risks.avg_inherent_score || 0}`}/>
        <StatCard title="Active Incidents" value={incidents.total      || 0} icon={Zap}           color="yellow" subtitle={`${incidents.bySeverity?.p1_critical || 0} P1 critical`}/>
        <StatCard title="Avg Compliance"   value={`${Math.round(compliance.reduce((a,c) => a + (c.compliance_percentage||0), 0) / (compliance.length || 1))}%`} icon={FileText} color="green"/>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Risk heatmap */}
        <Card title="Risk Heat Map" subtitle="Inherent risk distribution" className="lg:col-span-2">
          <RiskHeatmap data={dash?.risks?.heatmap || {}}/>
        </Card>

        {/* Compliance pie */}
        <Card title="Overall Compliance" subtitle="Across all frameworks">
          <CompliancePie data={compAgg}/>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Compliance by framework bar */}
        <Card title="Compliance by Framework">
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={compliance.map(f => ({ name: f.framework_name?.replace('_',' '), score: f.compliance_percentage || 0 }))}>
              <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0"/>
              <XAxis dataKey="name" tick={{ fontSize: 11 }}/>
              <YAxis domain={[0,100]} tick={{ fontSize: 11 }}/>
              <Tooltip formatter={v => [`${v}%`, 'Score']}/>
              <Bar dataKey="score" fill="#3b82f6" radius={[4,4,0,0]}/>
            </BarChart>
          </ResponsiveContainer>
        </Card>

        {/* Risk trend */}
        <Card title="Risk Trend (6 months)">
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={trend?.trend || []}>
              <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0"/>
              <XAxis dataKey="month" tick={{ fontSize: 11 }}/>
              <YAxis tick={{ fontSize: 11 }}/>
              <Tooltip/>
              <Line type="monotone" dataKey="new_risks"  stroke="#ef4444" name="New" strokeWidth={2} dot={false}/>
              <Line type="monotone" dataKey="closed"     stroke="#22c55e" name="Closed" strokeWidth={2} dot={false}/>
              <Line type="monotone" dataKey="critical"   stroke="#f97316" name="Critical" strokeWidth={2} strokeDasharray="5 5" dot={false}/>
            </LineChart>
          </ResponsiveContainer>
        </Card>
      </div>

      {/* KRIs */}
      {dash?.kris?.length > 0 && (
        <Card title="Key Risk Indicators">
          <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
            {dash.kris.map(kri => {
              const color = kri.current_value <= kri.threshold_green ? 'green' :
                            kri.current_value <= kri.threshold_amber  ? 'yellow' : 'red';
              const bg    = { green: 'border-green-200 bg-green-50', yellow: 'border-yellow-200 bg-yellow-50', red: 'border-red-200 bg-red-50' };
              return (
                <div key={kri.name} className={`border rounded-xl p-4 ${bg[color]}`}>
                  <p className="text-xs font-medium text-gray-600">{kri.name}</p>
                  <p className="text-2xl font-bold text-gray-900 mt-1">{kri.current_value}{kri.unit === 'percent' ? '%' : ''}</p>
                  <p className="text-xs text-gray-500">Target: {kri.target_value}{kri.unit === 'percent' ? '%' : ''}</p>
                </div>
              );
            })}
          </div>
        </Card>
      )}
    </div>
  );
}
