import { useState } from 'react';
import { Plus, Search, Filter } from 'lucide-react';
import { useApi, useMutation } from '../../hooks/useApi.js';
import { risksApi } from '../../services/api.js';
import Card from '../../components/common/Card.jsx';
import Badge from '../../components/common/Badge.jsx';
import Button from '../../components/common/Button.jsx';
import Modal from '../../components/common/Modal.jsx';
import RiskHeatmap from '../../components/charts/RiskHeatmap.jsx';
import { useAuth } from '../../context/AuthContext.jsx';
import { LIKELIHOOD_OPTIONS, IMPACT_OPTIONS, RISK_COLORS } from '../../utils/constants.js';

function RiskScore({ score }) {
  const rating = score >= 15 ? 'Critical' : score >= 9 ? 'High' : score >= 4 ? 'Medium' : 'Low';
  const colors = { Critical:'bg-red-500', High:'bg-orange-400', Medium:'bg-yellow-300', Low:'bg-green-400' };
  return (
    <div className="flex items-center gap-2">
      <div className={`w-8 h-8 rounded-lg ${colors[rating]} flex items-center justify-center text-white text-xs font-bold`}>{score}</div>
      <span className="text-xs text-gray-500">{rating}</span>
    </div>
  );
}

export default function RiskRegister() {
  const { canWrite } = useAuth();
  const [filters, setFilters] = useState({ search:'', status:'' });
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({ title:'', category:'cyber', likelihood:'possible', impact:'moderate', treatment_strategy:'mitigate', description:'' });

  const { data, loading, refetch } = useApi(() => risksApi.list(filters), [filters.status]);
  const { data: heatmap }          = useApi(() => risksApi.heatmap());
  const { mutate: createRisk, loading: creating } = useMutation(risksApi.create);

  const risks = Array.isArray(data) ? data : data?.data || [];

  const handleCreate = async (e) => {
    e.preventDefault();
    await createRisk(form);
    setShowCreate(false);
    refetch();
  };

  const set = (k, v) => setForm(f => ({ ...f, [k]: v }));

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <Card title="Risk Register" action={
            canWrite('risks') && (
              <Button size="sm" onClick={() => setShowCreate(true)}>
                <Plus size={14}/> New Risk
              </Button>
            )
          }>
            {/* Filters */}
            <div className="flex gap-3 mb-4">
              <div className="relative flex-1">
                <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400"/>
                <input
                  placeholder="Search risks..."
                  value={filters.search}
                  onChange={e => setFilters(f => ({ ...f, search: e.target.value }))}
                  className="w-full pl-8 pr-3 py-2 border border-gray-200 rounded-lg text-sm outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
              <select
                value={filters.status}
                onChange={e => setFilters(f => ({ ...f, status: e.target.value }))}
                className="px-3 py-2 border border-gray-200 rounded-lg text-sm outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="">All Status</option>
                <option value="open">Open</option>
                <option value="in_treatment">In Treatment</option>
                <option value="accepted">Accepted</option>
                <option value="closed">Closed</option>
              </select>
            </div>

            {loading ? (
              <div className="py-12 text-center"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto"/></div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-100">
                      <th className="text-left py-3 px-2 text-xs font-semibold text-gray-500 uppercase">ID</th>
                      <th className="text-left py-3 px-2 text-xs font-semibold text-gray-500 uppercase">Risk</th>
                      <th className="text-left py-3 px-2 text-xs font-semibold text-gray-500 uppercase">Score</th>
                      <th className="text-left py-3 px-2 text-xs font-semibold text-gray-500 uppercase">Status</th>
                      <th className="text-left py-3 px-2 text-xs font-semibold text-gray-500 uppercase">Owner</th>
                      <th className="text-left py-3 px-2 text-xs font-semibold text-gray-500 uppercase">Treatment</th>
                    </tr>
                  </thead>
                  <tbody>
                    {risks.map(r => (
                      <tr key={r.id} className="border-b border-gray-50 hover:bg-gray-50 cursor-pointer">
                        <td className="py-3 px-2 font-mono text-xs text-gray-500">{r.risk_id}</td>
                        <td className="py-3 px-2">
                          <p className="font-medium text-gray-900 line-clamp-1">{r.title}</p>
                          <p className="text-xs text-gray-400 capitalize">{r.category}</p>
                        </td>
                        <td className="py-3 px-2"><RiskScore score={r.inherent_score}/></td>
                        <td className="py-3 px-2"><Badge status={r.status}/></td>
                        <td className="py-3 px-2 text-xs text-gray-500">{r.owner ? `${r.owner.first_name} ${r.owner.last_name}` : '—'}</td>
                        <td className="py-3 px-2 text-xs text-gray-500 capitalize">{r.treatment_strategy || '—'}</td>
                      </tr>
                    ))}
                    {risks.length === 0 && (
                      <tr><td colSpan={6} className="py-12 text-center text-gray-400">No risks found</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        </div>

        {/* Heatmap */}
        <Card title="Risk Heat Map" subtitle="Click a cell to filter">
          <RiskHeatmap data={heatmap || {}}/>
        </Card>
      </div>

      {/* Create Risk Modal */}
      <Modal isOpen={showCreate} onClose={() => setShowCreate(false)} title="Register New Risk" size="lg">
        <form onSubmit={handleCreate} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Title *</label>
            <input required value={form.title} onChange={e => set('title', e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm outline-none focus:ring-2 focus:ring-blue-500"/>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Description</label>
            <textarea rows={3} value={form.description} onChange={e => set('description', e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm outline-none focus:ring-2 focus:ring-blue-500 resize-none"/>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Category</label>
              <select value={form.category} onChange={e => set('category', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm outline-none focus:ring-2 focus:ring-blue-500">
                <option value="cyber">Cyber</option>
                <option value="operational">Operational</option>
                <option value="compliance">Compliance</option>
                <option value="strategic">Strategic</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Treatment</label>
              <select value={form.treatment_strategy} onChange={e => set('treatment_strategy', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm outline-none focus:ring-2 focus:ring-blue-500">
                <option value="mitigate">Mitigate</option>
                <option value="accept">Accept</option>
                <option value="transfer">Transfer</option>
                <option value="avoid">Avoid</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Likelihood *</label>
              <select required value={form.likelihood} onChange={e => set('likelihood', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm outline-none focus:ring-2 focus:ring-blue-500">
                {LIKELIHOOD_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Impact *</label>
              <select required value={form.impact} onChange={e => set('impact', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm outline-none focus:ring-2 focus:ring-blue-500">
                {IMPACT_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
              </select>
            </div>
          </div>
          {/* Score preview */}
          {(() => {
            const l = LIKELIHOOD_OPTIONS.find(o => o.value === form.likelihood)?.score || 1;
            const i = IMPACT_OPTIONS.find(o => o.value === form.impact)?.score || 1;
            const score = l * i;
            const rating = score >= 15 ? 'Critical' : score >= 9 ? 'High' : score >= 4 ? 'Medium' : 'Low';
            return (
              <div className="bg-gray-50 rounded-lg p-3 flex items-center gap-3">
                <span className="text-sm text-gray-600">Inherent Risk Score:</span>
                <span className="font-bold text-lg text-gray-900">{score}</span>
                <Badge status={rating.toLowerCase()} label={rating}/>
              </div>
            );
          })()}
          <div className="flex justify-end gap-3 pt-2">
            <Button variant="outline" onClick={() => setShowCreate(false)}>Cancel</Button>
            <Button type="submit" loading={creating}>Create Risk</Button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
