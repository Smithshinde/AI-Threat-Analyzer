import { useState } from 'react';
import { Plus, AlertCircle } from 'lucide-react';
import { useApi, useMutation } from '../../hooks/useApi.js';
import { incidentsApi } from '../../services/api.js';
import Card from '../../components/common/Card.jsx';
import Badge from '../../components/common/Badge.jsx';
import Button from '../../components/common/Button.jsx';
import Modal from '../../components/common/Modal.jsx';
import StatCard from '../../components/common/StatCard.jsx';
import { useAuth } from '../../context/AuthContext.jsx';

const SEVERITY_OPTIONS = [
  { value: 'p1_critical', label: 'P1 — Critical', color: 'text-red-600' },
  { value: 'p2_high',     label: 'P2 — High',     color: 'text-orange-600' },
  { value: 'p3_medium',   label: 'P3 — Medium',   color: 'text-yellow-600' },
  { value: 'p4_low',      label: 'P4 — Low',      color: 'text-blue-600' },
];

export default function IncidentManagement() {
  const { canWrite } = useAuth();
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({ title:'', severity:'p3_medium', category:'', description:'', detected_at: new Date().toISOString().slice(0,16) });

  const { data, loading, refetch }          = useApi(() => incidentsApi.list());
  const { data: stats }                     = useApi(() => incidentsApi.stats());
  const { mutate: createInc, loading: creating } = useMutation(incidentsApi.create);

  const incidents = Array.isArray(data) ? data : data?.data || [];
  const set = (k, v) => setForm(f => ({ ...f, [k]: v }));

  const handleCreate = async (e) => {
    e.preventDefault();
    await createInc({ ...form, detected_at: new Date(form.detected_at).toISOString() });
    setShowCreate(false);
    refetch();
  };

  return (
    <div className="space-y-6">
      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard title="Total Incidents"  value={stats?.total                     || 0} icon={AlertCircle} color="red"/>
        <StatCard title="P1 Critical"      value={stats?.bySeverity?.p1_critical   || 0} icon={AlertCircle} color="red"/>
        <StatCard title="Open / Active"    value={stats?.open                      || 0} icon={AlertCircle} color="yellow"/>
        <StatCard title="MTTR (hours)"     value={stats?.mttr_hours                ?? '—'} icon={AlertCircle} color="blue" subtitle="Mean time to recover"/>
      </div>

      <Card title="Incidents" action={
        canWrite('incidents') && (
          <Button size="sm" onClick={() => setShowCreate(true)}><Plus size={14}/> Report Incident</Button>
        )
      }>
        {loading ? (
          <div className="py-12 text-center"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto"/></div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-100">
                  {['ID','Title','Severity','Status','Category','Detected','Assigned To'].map(h => (
                    <th key={h} className="text-left py-3 px-3 text-xs font-semibold text-gray-500 uppercase">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {incidents.map(inc => (
                  <tr key={inc.id} className="border-b border-gray-50 hover:bg-gray-50 cursor-pointer">
                    <td className="py-3 px-3 font-mono text-xs text-gray-500">{inc.incident_id}</td>
                    <td className="py-3 px-3 font-medium text-gray-900 max-w-xs truncate">{inc.title}</td>
                    <td className="py-3 px-3"><Badge status={inc.severity} label={inc.severity?.replace(/_/g,' ').toUpperCase()}/></td>
                    <td className="py-3 px-3"><Badge status={inc.status}/></td>
                    <td className="py-3 px-3 text-xs text-gray-500 capitalize">{inc.category || '—'}</td>
                    <td className="py-3 px-3 text-xs text-gray-500">{new Date(inc.detected_at).toLocaleDateString()}</td>
                    <td className="py-3 px-3 text-xs text-gray-500">
                      {inc.assigned_to ? `${inc.assigned_to.first_name} ${inc.assigned_to.last_name}` : '—'}
                    </td>
                  </tr>
                ))}
                {incidents.length === 0 && (
                  <tr><td colSpan={7} className="py-12 text-center text-gray-400">No incidents found</td></tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Create Modal */}
      <Modal isOpen={showCreate} onClose={() => setShowCreate(false)} title="Report New Incident" size="lg">
        <form onSubmit={handleCreate} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Title *</label>
            <input required value={form.title} onChange={e => set('title', e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm outline-none focus:ring-2 focus:ring-blue-500"/>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Severity *</label>
              <select required value={form.severity} onChange={e => set('severity', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm outline-none focus:ring-2 focus:ring-blue-500">
                {SEVERITY_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Category</label>
              <select value={form.category} onChange={e => set('category', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm outline-none focus:ring-2 focus:ring-blue-500">
                <option value="">Select category</option>
                <option value="data_breach">Data Breach</option>
                <option value="ransomware">Ransomware</option>
                <option value="phishing">Phishing</option>
                <option value="ddos">DDoS</option>
                <option value="insider">Insider Threat</option>
                <option value="other">Other</option>
              </select>
            </div>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Detected At *</label>
            <input required type="datetime-local" value={form.detected_at} onChange={e => set('detected_at', e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm outline-none focus:ring-2 focus:ring-blue-500"/>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Description</label>
            <textarea rows={3} value={form.description} onChange={e => set('description', e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm outline-none focus:ring-2 focus:ring-blue-500 resize-none"/>
          </div>
          <div className="flex justify-end gap-3 pt-2">
            <Button variant="outline" onClick={() => setShowCreate(false)}>Cancel</Button>
            <Button type="submit" loading={creating} variant="danger">Report Incident</Button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
