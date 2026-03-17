import { useState } from 'react';
import { BarChart3, Download, FileText, TrendingUp } from 'lucide-react';
import { LineChart, Line, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { useApi } from '../../hooks/useApi.js';
import { reportsApi, complianceApi } from '../../services/api.js';
import Card from '../../components/common/Card.jsx';
import Button from '../../components/common/Button.jsx';

export default function Reports() {
  const [months, setMonths]   = useState(6);
  const [selectedFw, setFw]   = useState('');

  const { data: board }       = useApi(() => reportsApi.board());
  const { data: trend }       = useApi(() => reportsApi.riskTrend(months), [months]);
  const { data: fws }         = useApi(() => complianceApi.frameworks());
  const { data: compReport }  = useApi(() => selectedFw ? reportsApi.compliance(selectedFw) : Promise.resolve({ data: { data: null } }), [selectedFw]);

  const exportJson = (data, name) => {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a'); a.href = url; a.download = `${name}.json`; a.click();
  };

  return (
    <div className="space-y-6">
      {/* Board Summary */}
      {board && (
        <Card title="Board-Level Summary Report"
          action={<Button size="sm" variant="outline" onClick={() => exportJson(board, 'board-report')}><Download size={14}/> Export</Button>}>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div>
              <p className="text-xs font-semibold text-gray-500 uppercase mb-3">Key Risk Indicators</p>
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600">Total Risks</span>
                  <span className="font-bold">{board.risk_summary?.total_risks || 0}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600">Critical Risks</span>
                  <span className="font-bold text-red-600">{board.risk_summary?.critical_risks || 0}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-gray-600">High Risks</span>
                  <span className="font-bold text-orange-500">{board.risk_summary?.high_risks || 0}</span>
                </div>
              </div>
            </div>
            <div>
              <p className="text-xs font-semibold text-gray-500 uppercase mb-3">Incidents (90 days)</p>
              <div className="space-y-2">
                <div className="flex justify-between text-sm"><span className="text-gray-600">Total</span><span className="font-bold">{board.incidents?.total || 0}</span></div>
                <div className="flex justify-between text-sm"><span className="text-gray-600">P1 Critical</span><span className="font-bold text-red-600">{board.incidents?.bySeverity?.p1_critical || 0}</span></div>
              </div>
            </div>
            <div>
              <p className="text-xs font-semibold text-gray-500 uppercase mb-3">Key Messages</p>
              <div className="space-y-1">
                {(board.key_messages || []).map((m, i) => <p key={i} className="text-xs text-gray-700">{m}</p>)}
              </div>
            </div>
          </div>
        </Card>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Risk Trend */}
        <Card
          title="Risk Trend Analysis"
          action={
            <select value={months} onChange={e => setMonths(+e.target.value)}
              className="text-xs border border-gray-200 rounded px-2 py-1 outline-none">
              <option value={3}>3 months</option>
              <option value={6}>6 months</option>
              <option value={12}>12 months</option>
            </select>
          }
        >
          <ResponsiveContainer width="100%" height={240}>
            <LineChart data={trend?.trend || []}>
              <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0"/>
              <XAxis dataKey="month" tick={{ fontSize: 11 }}/>
              <YAxis tick={{ fontSize: 11 }}/>
              <Tooltip/>
              <Line type="monotone" dataKey="new_risks" stroke="#ef4444" name="New Risks" strokeWidth={2} dot={false}/>
              <Line type="monotone" dataKey="closed"    stroke="#22c55e" name="Closed"    strokeWidth={2} dot={false}/>
              <Line type="monotone" dataKey="critical"  stroke="#f97316" name="Critical"  strokeWidth={2} strokeDasharray="4 4" dot={false}/>
            </LineChart>
          </ResponsiveContainer>
        </Card>

        {/* Compliance Report */}
        <Card
          title="Framework Compliance Report"
          action={
            <div className="flex items-center gap-2">
              <select value={selectedFw} onChange={e => setFw(e.target.value)}
                className="text-xs border border-gray-200 rounded px-2 py-1 outline-none">
                <option value="">Select framework</option>
                {(fws || []).map(f => <option key={f.id} value={f.id}>{f.name?.replace('_',' ')}</option>)}
              </select>
              {compReport && (
                <Button size="sm" variant="outline" onClick={() => exportJson(compReport, 'compliance-report')}>
                  <Download size={14}/>
                </Button>
              )}
            </div>
          }
        >
          {compReport ? (
            <div className="space-y-4">
              <div className="text-center">
                <p className="text-5xl font-bold text-blue-600">{compReport.score}%</p>
                <p className="text-gray-500 text-sm mt-1">{compReport.framework?.name?.replace('_',' ')} Compliance</p>
              </div>
              <div className="grid grid-cols-4 gap-2 text-center text-xs">
                {[['Compliant','bg-green-100 text-green-800'],['Partial','bg-yellow-100 text-yellow-800'],['Non-Compliant','bg-red-100 text-red-800'],['Not Assessed','bg-gray-100 text-gray-600']].map(([k, cls], i) => (
                  <div key={k} className={`${cls} rounded-lg p-2`}>
                    <p className="font-bold text-lg">{compReport.by_status?.[k.toLowerCase().replace('-','_').replace(' ','_')] || 0}</p>
                    <p>{k}</p>
                  </div>
                ))}
              </div>
              {compReport.gaps?.length > 0 && (
                <div>
                  <p className="text-xs font-semibold text-gray-500 uppercase mb-2">Top Gaps ({compReport.gaps.length})</p>
                  <div className="space-y-1 max-h-40 overflow-y-auto">
                    {compReport.gaps.slice(0, 10).map(g => (
                      <div key={g.id} className="flex items-start gap-2 text-xs p-2 bg-red-50 rounded">
                        <span className="font-mono text-gray-500 flex-shrink-0">{g.requirement?.requirement_id}</span>
                        <span className="text-gray-700">{g.requirement?.title}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="py-16 text-center text-gray-400">
              <FileText className="mx-auto mb-2" size={32}/>
              <p className="text-sm">Select a framework to generate report</p>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
