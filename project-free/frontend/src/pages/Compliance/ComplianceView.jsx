import { useState } from 'react';
import { CheckCircle, XCircle, MinusCircle, HelpCircle } from 'lucide-react';
import { useApi } from '../../hooks/useApi.js';
import { complianceApi } from '../../services/api.js';
import Card from '../../components/common/Card.jsx';
import Badge from '../../components/common/Badge.jsx';
import { ComplianceRadial } from '../../components/charts/ComplianceChart.jsx';

const STATUS_ICONS = {
  compliant:    <CheckCircle size={16} className="text-green-500"/>,
  partial:      <MinusCircle size={16} className="text-yellow-500"/>,
  non_compliant:<XCircle    size={16} className="text-red-500"/>,
  not_assessed: <HelpCircle size={16} className="text-gray-400"/>,
};

export default function ComplianceView() {
  const { data: dash, loading }   = useApi(() => complianceApi.dashboard());
  const [selectedFw, setSelectedFw] = useState(null);
  const { data: gap } = useApi(() => selectedFw ? complianceApi.gapAnalysis(selectedFw) : Promise.resolve({ data: { data: null } }), [selectedFw]);

  const scores    = dash?.scores    || [];
  const frameworks= dash?.frameworks|| [];

  if (loading) return <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-10 w-10 border-b-2 border-blue-600 mx-auto"/></div>;

  return (
    <div className="space-y-6">
      {/* Framework cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {scores.map(s => (
          <Card key={s.framework_name} className="cursor-pointer hover:ring-2 hover:ring-blue-300 transition-all"
            onClick={() => setSelectedFw(frameworks.find(f => f.framework?.name === s.framework_name)?.framework_id)}>
            <ComplianceRadial score={Math.round(s.compliance_percentage || 0)} framework={s.framework_name?.replace('_',' ')}/>
            <div className="grid grid-cols-2 gap-1 mt-3 text-xs text-center">
              <div className="bg-green-50 rounded p-1">
                <p className="font-bold text-green-700">{s.compliant}</p>
                <p className="text-gray-500">Compliant</p>
              </div>
              <div className="bg-red-50 rounded p-1">
                <p className="font-bold text-red-700">{s.non_compliant}</p>
                <p className="text-gray-500">Non-comp.</p>
              </div>
            </div>
          </Card>
        ))}
        {scores.length === 0 && (
          <div className="col-span-4 py-12 text-center text-gray-400">
            No frameworks activated. Add frameworks to track compliance.
          </div>
        )}
      </div>

      {/* Gap Analysis */}
      {gap?.gaps && (
        <Card title="Gap Analysis" subtitle={`${gap.total} requirements · ${gap.unmapped} unmapped · ${gap.nonCompliant} non-compliant`}>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-100">
                  <th className="text-left py-2 px-3 text-xs font-semibold text-gray-500">ID</th>
                  <th className="text-left py-2 px-3 text-xs font-semibold text-gray-500">Requirement</th>
                  <th className="text-left py-2 px-3 text-xs font-semibold text-gray-500">Category</th>
                  <th className="text-left py-2 px-3 text-xs font-semibold text-gray-500">Status</th>
                  <th className="text-left py-2 px-3 text-xs font-semibold text-gray-500">Control</th>
                </tr>
              </thead>
              <tbody>
                {gap.gaps.map(g => (
                  <tr key={g.id} className="border-b border-gray-50 hover:bg-gray-50">
                    <td className="py-2.5 px-3 font-mono text-xs text-gray-500">{g.requirement_id}</td>
                    <td className="py-2.5 px-3">
                      <p className="text-gray-900 text-sm">{g.title}</p>
                    </td>
                    <td className="py-2.5 px-3 text-xs text-gray-500">{g.category}</td>
                    <td className="py-2.5 px-3">
                      <div className="flex items-center gap-1.5">
                        {STATUS_ICONS[g.compliance_status]}
                        <Badge status={g.compliance_status}/>
                      </div>
                    </td>
                    <td className="py-2.5 px-3 text-xs text-gray-500">
                      {g.control ? `${g.control.control_id} — ${g.control.title}` : <span className="text-red-400">No control mapped</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
}
