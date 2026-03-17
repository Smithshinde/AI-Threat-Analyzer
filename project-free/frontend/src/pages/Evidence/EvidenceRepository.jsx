import { useState, useRef } from 'react';
import { Upload, File, Trash2, FolderOpen } from 'lucide-react';
import { useApi, useMutation } from '../../hooks/useApi.js';
import { evidenceApi } from '../../services/api.js';
import Card from '../../components/common/Card.jsx';
import Badge from '../../components/common/Badge.jsx';
import Button from '../../components/common/Button.jsx';
import Modal from '../../components/common/Modal.jsx';

function FileSize({ bytes }) {
  if (!bytes) return '—';
  if (bytes < 1024)       return `${bytes} B`;
  if (bytes < 1048576)    return `${(bytes/1024).toFixed(1)} KB`;
  return `${(bytes/1048576).toFixed(1)} MB`;
}

export default function EvidenceRepository() {
  const fileRef = useRef();
  const [showUpload, setShowUpload] = useState(false);
  const [form, setForm]             = useState({ title:'', description:'', evidence_type:'document', collection_date: new Date().toISOString().split('T')[0] });
  const [file, setFile]             = useState(null);

  const { data, loading, refetch }               = useApi(() => evidenceApi.list());
  const { mutate: upload, loading: uploading }    = useMutation(evidenceApi.upload);
  const { mutate: remove }                        = useMutation(evidenceApi.remove);

  const items = Array.isArray(data) ? data : data?.data || [];
  const set   = (k, v) => setForm(f => ({ ...f, [k]: v }));

  const handleUpload = async (e) => {
    e.preventDefault();
    const fd = new FormData();
    Object.entries(form).forEach(([k,v]) => fd.append(k, v));
    if (file) fd.append('file', file);
    await upload(fd);
    setShowUpload(false);
    setFile(null);
    refetch();
  };

  const handleDelete = async (id) => {
    if (!confirm('Delete this evidence item?')) return;
    await remove(id);
    refetch();
  };

  return (
    <div className="space-y-6">
      <Card
        title="Evidence Repository"
        subtitle={`${items.length} items stored`}
        action={
          <Button size="sm" onClick={() => setShowUpload(true)}>
            <Upload size={14}/> Upload Evidence
          </Button>
        }
      >
        {loading ? (
          <div className="py-12 text-center"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto"/></div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-100">
                  {['ID','Title','Type','Control','Collected By','Date','Size',''].map(h => (
                    <th key={h} className="text-left py-3 px-3 text-xs font-semibold text-gray-500 uppercase">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {items.map(ev => (
                  <tr key={ev.id} className="border-b border-gray-50 hover:bg-gray-50">
                    <td className="py-3 px-3 font-mono text-xs text-gray-400">{ev.evidence_id}</td>
                    <td className="py-3 px-3">
                      <div className="flex items-center gap-2">
                        <File size={14} className="text-blue-500 flex-shrink-0"/>
                        <div>
                          <p className="font-medium text-gray-900 text-sm">{ev.title}</p>
                          {ev.file_name && <p className="text-xs text-gray-400">{ev.file_name}</p>}
                        </div>
                      </div>
                    </td>
                    <td className="py-3 px-3"><Badge status={ev.evidence_type} label={ev.evidence_type}/></td>
                    <td className="py-3 px-3 text-xs text-gray-500">{ev.control?.title || '—'}</td>
                    <td className="py-3 px-3 text-xs text-gray-500">
                      {ev.collected_by ? `${ev.collected_by.first_name} ${ev.collected_by.last_name}` : '—'}
                    </td>
                    <td className="py-3 px-3 text-xs text-gray-500">{ev.collection_date || '—'}</td>
                    <td className="py-3 px-3 text-xs text-gray-500"><FileSize bytes={ev.file_size}/></td>
                    <td className="py-3 px-3">
                      <button onClick={() => handleDelete(ev.id)} className="p-1 text-gray-400 hover:text-red-500 transition-colors">
                        <Trash2 size={14}/>
                      </button>
                    </td>
                  </tr>
                ))}
                {items.length === 0 && (
                  <tr><td colSpan={8} className="py-16 text-center">
                    <FolderOpen className="mx-auto text-gray-300 mb-2" size={36}/>
                    <p className="text-gray-400">No evidence uploaded yet</p>
                  </td></tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Upload Modal */}
      <Modal isOpen={showUpload} onClose={() => setShowUpload(false)} title="Upload Evidence">
        <form onSubmit={handleUpload} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Title *</label>
            <input required value={form.title} onChange={e => set('title', e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm outline-none focus:ring-2 focus:ring-blue-500"/>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Type *</label>
              <select required value={form.evidence_type} onChange={e => set('evidence_type', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm outline-none focus:ring-2 focus:ring-blue-500">
                {['document','screenshot','log','report','certificate','other'].map(t =>
                  <option key={t} value={t}>{t.charAt(0).toUpperCase() + t.slice(1)}</option>
                )}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Collection Date</label>
              <input type="date" value={form.collection_date} onChange={e => set('collection_date', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm outline-none focus:ring-2 focus:ring-blue-500"/>
            </div>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">File (optional, max 50MB)</label>
            <div
              className="border-2 border-dashed border-gray-300 rounded-lg p-6 text-center cursor-pointer hover:border-blue-400 transition-colors"
              onClick={() => fileRef.current?.click()}
            >
              <Upload className="mx-auto text-gray-400 mb-2" size={24}/>
              {file ? (
                <p className="text-sm text-blue-600 font-medium">{file.name}</p>
              ) : (
                <p className="text-sm text-gray-500">Click to select or drag & drop</p>
              )}
              <input ref={fileRef} type="file" className="hidden" onChange={e => setFile(e.target.files[0])}/>
            </div>
          </div>
          <div className="flex justify-end gap-3 pt-2">
            <Button variant="outline" onClick={() => setShowUpload(false)}>Cancel</Button>
            <Button type="submit" loading={uploading}><Upload size={14}/> Upload</Button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
