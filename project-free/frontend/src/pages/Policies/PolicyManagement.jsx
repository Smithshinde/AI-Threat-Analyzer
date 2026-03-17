import { useState } from 'react';
import { Plus, BookOpen } from 'lucide-react';
import { useApi, useMutation } from '../../hooks/useApi.js';
import { policiesApi } from '../../services/api.js';
import Card from '../../components/common/Card.jsx';
import Badge from '../../components/common/Badge.jsx';
import Button from '../../components/common/Button.jsx';
import Modal from '../../components/common/Modal.jsx';
import { useAuth } from '../../context/AuthContext.jsx';

export default function PolicyManagement() {
  const { canWrite } = useAuth();
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm]             = useState({ title:'', category:'', content:'' });

  const { data, loading, refetch }                    = useApi(() => policiesApi.list());
  const { mutate: createPolicy, loading: creating }   = useMutation(policiesApi.create);
  const { mutate: transition }                        = useMutation((id, b) => policiesApi.transition(id, b));

  const policies = Array.isArray(data) ? data : data?.data || [];
  const set      = (k, v) => setForm(f => ({ ...f, [k]: v }));

  const handleCreate = async (e) => {
    e.preventDefault();
    await createPolicy(form);
    setShowCreate(false);
    refetch();
  };

  const handleTransition = async (id, status) => {
    await transition(id, { status });
    refetch();
  };

  const nextActions = { draft: 'Submit for Review', under_review: 'Approve', approved: 'Publish' };

  return (
    <div className="space-y-6">
      <Card
        title="Policy Management"
        action={canWrite('policies') && (
          <Button size="sm" onClick={() => setShowCreate(true)}><Plus size={14}/> New Policy</Button>
        )}
      >
        {loading ? (
          <div className="py-12 text-center"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto"/></div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-100">
                  {['ID','Title','Category','Version','Status','Owner','Effective Date','Action'].map(h => (
                    <th key={h} className="text-left py-3 px-3 text-xs font-semibold text-gray-500 uppercase">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {policies.map(p => (
                  <tr key={p.id} className="border-b border-gray-50 hover:bg-gray-50">
                    <td className="py-3 px-3 font-mono text-xs text-gray-400">{p.policy_id}</td>
                    <td className="py-3 px-3">
                      <p className="font-medium text-gray-900">{p.title}</p>
                    </td>
                    <td className="py-3 px-3 text-xs text-gray-500 capitalize">{p.category || '—'}</td>
                    <td className="py-3 px-3 text-xs text-gray-500">v{p.version}</td>
                    <td className="py-3 px-3"><Badge status={p.status}/></td>
                    <td className="py-3 px-3 text-xs text-gray-500">
                      {p.owner ? `${p.owner.first_name} ${p.owner.last_name}` : '—'}
                    </td>
                    <td className="py-3 px-3 text-xs text-gray-500">{p.effective_date || '—'}</td>
                    <td className="py-3 px-3">
                      {canWrite('policies') && nextActions[p.status] && (
                        <Button size="sm" variant="ghost"
                          onClick={() => handleTransition(p.id, { draft:'under_review', under_review:'approved', approved:'published' }[p.status])}>
                          {nextActions[p.status]}
                        </Button>
                      )}
                    </td>
                  </tr>
                ))}
                {policies.length === 0 && (
                  <tr><td colSpan={8} className="py-16 text-center">
                    <BookOpen className="mx-auto text-gray-300 mb-2" size={36}/>
                    <p className="text-gray-400">No policies created yet</p>
                  </td></tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Modal isOpen={showCreate} onClose={() => setShowCreate(false)} title="Create Policy" size="lg">
        <form onSubmit={handleCreate} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Title *</label>
            <input required value={form.title} onChange={e => set('title', e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm outline-none focus:ring-2 focus:ring-blue-500"/>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Category</label>
            <input value={form.category} onChange={e => set('category', e.target.value)} placeholder="e.g. Information Security, Access Control"
              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm outline-none focus:ring-2 focus:ring-blue-500"/>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Policy Content</label>
            <textarea rows={8} value={form.content} onChange={e => set('content', e.target.value)}
              placeholder="Full policy text..."
              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm outline-none focus:ring-2 focus:ring-blue-500 resize-none font-mono"/>
          </div>
          <div className="flex justify-end gap-3 pt-2">
            <Button variant="outline" onClick={() => setShowCreate(false)}>Cancel</Button>
            <Button type="submit" loading={creating}>Create Draft</Button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
