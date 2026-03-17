/**
 * Clarion — AI Security Intelligence Platform
 * Complete Single-File React SPA
 *
 * Pages:  Auth · Analyze · Report · History · Public Report
 * Stack:  React 18 · Tailwind CSS · Lucide · Recharts · Supabase
 */

import { useState, useEffect, useRef, useCallback } from 'react';
import {
  Shield, Zap, Search, Upload, History, LogOut, ChevronRight,
  AlertTriangle, CheckCircle, XCircle, Info, Copy, Share2,
  Download, MessageSquare, Send, Loader2, RefreshCw, Tag,
  Globe, Lock, Eye, BarChart2, List, Terminal, Cpu,
  FileText, X, Plus, ArrowLeft, ExternalLink, Target,
  Activity, Server, Hash, Network, Database,
} from 'lucide-react';
import {
  RadarChart, Radar, PolarGrid, PolarAngleAxis, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, Tooltip, Cell,
} from 'recharts';
import { supabase, getToken } from './lib/supabase';

const API = import.meta.env.VITE_API_URL || 'http://localhost:3001';

// ── Helpers ──────────────────────────────────────────────────────

function cls(...args) { return args.filter(Boolean).join(' '); }

function severityColor(s) {
  const v = (s || '').toUpperCase();
  if (v === 'CRITICAL') return 'text-red-400 bg-red-400/10 border-red-400/30';
  if (v === 'HIGH')     return 'text-orange-400 bg-orange-400/10 border-orange-400/30';
  if (v === 'MEDIUM')   return 'text-yellow-400 bg-yellow-400/10 border-yellow-400/30';
  return 'text-green-400 bg-green-400/10 border-green-400/30';
}

function severityDot(s) {
  const v = (s || '').toUpperCase();
  if (v === 'CRITICAL' || v === 'critical') return 'bg-red-400';
  if (v === 'HIGH'     || v === 'high')     return 'bg-orange-400';
  if (v === 'MEDIUM'   || v === 'medium')   return 'bg-yellow-400';
  return 'bg-green-400';
}

function riskColor(score) {
  if (score >= 80) return '#EF4444';
  if (score >= 60) return '#F97316';
  if (score >= 40) return '#F59E0B';
  return '#22C55E';
}

function iocIcon(type) {
  const t = (type || '').toLowerCase();
  if (t === 'ip')       return <Network size={13} />;
  if (t === 'domain')   return <Globe size={13} />;
  if (t === 'hash')     return <Hash size={13} />;
  if (t === 'file')     return <FileText size={13} />;
  if (t === 'process')  return <Cpu size={13} />;
  if (t === 'registry') return <Database size={13} />;
  return <AlertTriangle size={13} />;
}

function fmtDate(iso) {
  if (!iso) return '';
  return new Date(iso).toLocaleString(undefined, {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

async function apiCall(path, opts = {}) {
  const token = await getToken();
  const headers = { 'Content-Type': 'application/json', ...opts.headers };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const res = await fetch(`${API}${path}`, { ...opts, headers });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

// ── Shared UI components ─────────────────────────────────────────

function SeverityBadge({ severity, size = 'sm' }) {
  const base = size === 'lg'
    ? 'px-3 py-1 text-sm font-bold rounded-full border'
    : 'px-2 py-0.5 text-xs font-semibold rounded-full border';
  return (
    <span className={cls(base, severityColor(severity))}>
      {(severity || 'LOW').toUpperCase()}
    </span>
  );
}

function ConfidencePill({ value }) {
  const pct = Math.round(value || 0);
  const col = pct >= 80 ? 'text-green-400' : pct >= 50 ? 'text-yellow-400' : 'text-red-400';
  return <span className={cls('text-xs font-mono', col)}>{pct}%</span>;
}

function Card({ children, className }) {
  return (
    <div className={cls('glass rounded-xl p-4', className)}>
      {children}
    </div>
  );
}

function Btn({ children, onClick, variant = 'primary', size = 'md', disabled, className, type = 'button' }) {
  const base = 'inline-flex items-center gap-2 font-semibold rounded-lg transition-all duration-150 disabled:opacity-50 disabled:cursor-not-allowed';
  const sizes = { sm: 'px-3 py-1.5 text-sm', md: 'px-4 py-2 text-sm', lg: 'px-6 py-3 text-base' };
  const variants = {
    primary:  'bg-blue-600 hover:bg-blue-500 text-white shadow-lg shadow-blue-600/20',
    accent:   'bg-cyan-600 hover:bg-cyan-500 text-white',
    purple:   'bg-purple-600 hover:bg-purple-500 text-white',
    danger:   'bg-red-600/20 hover:bg-red-600/40 text-red-400 border border-red-400/30',
    ghost:    'bg-white/5 hover:bg-white/10 text-slate-300 border border-white/10',
    outline:  'border border-blue-500/40 text-blue-400 hover:bg-blue-500/10',
  };
  return (
    <button type={type} onClick={onClick} disabled={disabled}
      className={cls(base, sizes[size], variants[variant], className)}>
      {children}
    </button>
  );
}

function Spinner({ size = 16 }) {
  return <Loader2 size={size} className="animate-spin" />;
}

function Toast({ message, type = 'info', onClose }) {
  useEffect(() => { const t = setTimeout(onClose, 4000); return () => clearTimeout(t); }, [onClose]);
  const styles = {
    info:    'bg-blue-900/80 border-blue-500/40 text-blue-200',
    success: 'bg-green-900/80 border-green-500/40 text-green-200',
    error:   'bg-red-900/80 border-red-500/40 text-red-200',
    warn:    'bg-orange-900/80 border-orange-500/40 text-orange-200',
  };
  return (
    <div className={cls('fixed bottom-4 right-4 z-50 flex items-center gap-3 px-4 py-3 rounded-xl border backdrop-blur-sm shadow-xl animate-fadeUp', styles[type])}>
      <span className="text-sm">{message}</span>
      <button onClick={onClose} className="opacity-60 hover:opacity-100"><X size={14} /></button>
    </div>
  );
}

function useToast() {
  const [toast, setToast] = useState(null);
  const show = useCallback((message, type = 'info') => setToast({ message, type }), []);
  const hide = useCallback(() => setToast(null), []);
  const el = toast ? <Toast message={toast.message} type={toast.type} onClose={hide} /> : null;
  return { show, el };
}

// ── Risk gauge ────────────────────────────────────────────────────

function RiskGauge({ score = 0 }) {
  const r = 54;
  const circ = 2 * Math.PI * r;
  const pct = Math.min(Math.max(score, 0), 100) / 100;
  const dash = pct * circ * 0.75;
  const color = riskColor(score);
  return (
    <div className="relative flex items-center justify-center w-40 h-40">
      <svg width="160" height="160" className="rotate-[-135deg]">
        <circle cx="80" cy="80" r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="10"
          strokeDasharray={`${circ * 0.75} ${circ}`} strokeLinecap="round" />
        <circle cx="80" cy="80" r={r} fill="none" stroke={color} strokeWidth="10"
          strokeDasharray={`${dash} ${circ}`} strokeLinecap="round"
          style={{ transition: 'stroke-dasharray 0.8s cubic-bezier(.4,0,.2,1)', filter: `drop-shadow(0 0 8px ${color}60)` }} />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className="text-3xl font-black tabular-nums" style={{ color }}>{score}</span>
        <span className="text-xs text-slate-500 uppercase tracking-widest">risk</span>
      </div>
    </div>
  );
}

// ── Auth page ─────────────────────────────────────────────────────

function AuthPage({ onAuth }) {
  const [mode, setMode] = useState('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  async function submit(e) {
    e.preventDefault();
    setError(''); setSuccess('');
    setLoading(true);
    try {
      if (mode === 'login') {
        const { data, error: err } = await supabase.auth.signInWithPassword({ email, password });
        if (err) throw err;
        onAuth(data.user);
      } else {
        const { error: err } = await supabase.auth.signUp({ email, password });
        if (err) throw err;
        setSuccess('Check your email to confirm your account.');
        setMode('login');
      }
    } catch (err) {
      setError(err.message || 'Authentication failed.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-4" style={{ background: 'var(--bg)' }}>
      <div className="w-full max-w-md animate-fadeUp">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center gap-3 mb-4">
            <div className="w-10 h-10 rounded-xl bg-blue-600/20 border border-blue-500/30 flex items-center justify-center">
              <Shield size={20} className="text-blue-400" />
            </div>
            <span className="text-2xl font-black tracking-tight text-white">Clarion</span>
          </div>
          <p className="text-slate-500 text-sm">AI Security Intelligence Platform</p>
        </div>

        <Card className="p-6">
          <div className="flex gap-1 mb-6 p-1 rounded-lg bg-white/5">
            {['login', 'signup'].map(m => (
              <button key={m} onClick={() => setMode(m)}
                className={cls('flex-1 py-2 text-sm font-semibold rounded-md transition-all',
                  mode === m ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-slate-200')}>
                {m === 'login' ? 'Sign In' : 'Create Account'}
              </button>
            ))}
          </div>

          {error && (
            <div className="mb-4 flex items-center gap-2 text-red-400 text-sm bg-red-400/10 border border-red-400/20 rounded-lg px-3 py-2">
              <XCircle size={14} /> {error}
            </div>
          )}
          {success && (
            <div className="mb-4 flex items-center gap-2 text-green-400 text-sm bg-green-400/10 border border-green-400/20 rounded-lg px-3 py-2">
              <CheckCircle size={14} /> {success}
            </div>
          )}

          <form onSubmit={submit} className="space-y-4">
            <div>
              <label className="block text-xs text-slate-400 mb-1.5">Email</label>
              <input type="email" value={email} onChange={e => setEmail(e.target.value)} required
                placeholder="analyst@company.com"
                className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-600" />
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1.5">Password</label>
              <input type="password" value={password} onChange={e => setPassword(e.target.value)} required
                placeholder="••••••••"
                className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-600" />
            </div>
            <Btn type="submit" size="lg" disabled={loading} className="w-full justify-center">
              {loading ? <Spinner /> : mode === 'login' ? 'Sign In' : 'Create Account'}
            </Btn>
          </form>
        </Card>

        <p className="text-center text-xs text-slate-600 mt-4">
          Powered by Groq · Llama 3.3 70B · Free forever
        </p>
      </div>
    </div>
  );
}

// ── Navbar ────────────────────────────────────────────────────────

function Navbar({ user, page, setPage, onSignOut }) {
  const nav = [
    { id: 'analyze', label: 'Analyze', icon: <Zap size={15} /> },
    { id: 'history', label: 'History', icon: <History size={15} /> },
  ];
  return (
    <header className="sticky top-0 z-40 border-b border-white/5 bg-[#07090F]/80 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 h-14 flex items-center justify-between gap-4">
        <div className="flex items-center gap-6">
          <button onClick={() => setPage('analyze')} className="flex items-center gap-2.5 group">
            <div className="w-7 h-7 rounded-lg bg-blue-600/20 border border-blue-500/30 flex items-center justify-center group-hover:bg-blue-600/30 transition-colors">
              <Shield size={14} className="text-blue-400" />
            </div>
            <span className="font-black text-white tracking-tight hidden sm:block">Clarion</span>
          </button>
          <nav className="flex gap-1">
            {nav.map(n => (
              <button key={n.id} onClick={() => setPage(n.id)}
                className={cls('flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium transition-all',
                  page === n.id
                    ? 'bg-blue-600/20 text-blue-400 border border-blue-500/25'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-white/5')}>
                {n.icon} {n.label}
              </button>
            ))}
          </nav>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-slate-600 hidden md:block truncate max-w-[200px]">{user?.email}</span>
          <button onClick={onSignOut}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm text-slate-400 hover:text-red-400 hover:bg-red-400/10 transition-all">
            <LogOut size={14} /> <span className="hidden sm:block">Sign Out</span>
          </button>
        </div>
      </div>
    </header>
  );
}

// ── Analyze page ──────────────────────────────────────────────────

const SAMPLE_LOG = `2024-01-15 03:14:22 ALERT src=192.168.1.45 dst=10.20.30.5 proto=TCP dport=445 action=ALLOW rule=smb-internal
2024-01-15 03:14:31 ALERT process=mimikatz.exe pid=4821 user=SYSTEM host=WORKSTATION-07 action=EXECUTED
2024-01-15 03:14:33 WARN  outbound dst=185.220.101.47:8080 bytes=48291 proto=HTTPS host=WORKSTATION-07
2024-01-15 03:15:01 ALERT auth=FAILED user=Administrator host=DC-01 src=WORKSTATION-07 attempts=23
2024-01-15 03:15:44 CRIT  process=cmd.exe args="net user backdoor P@ss123! /add && net localgroup administrators backdoor /add"
2024-01-15 03:16:02 WARN  dns query=c2-server.darkweb.xyz src=10.0.0.45 type=A
2024-01-15 03:17:15 ALERT scheduled_task="\\Microsoft\\Windows\\Update\\svcupdate" action=CREATED host=WORKSTATION-07`;

function AnalyzePage({ onResult }) {
  const [tab, setTab] = useState('text');
  const [input, setInput] = useState('');
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [streamLines, setStreamLines] = useState([]);
  const [streamDone, setStreamDone] = useState(false);
  const [compareResult, setCompareResult] = useState(null);
  const termRef = useRef(null);
  const { show: showToast, el: toastEl } = useToast();

  useEffect(() => {
    if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight;
  }, [streamLines]);

  async function analyzeText() {
    if (input.trim().length < 10) { setError('Please enter at least 10 characters of log data.'); return; }
    setError(''); setLoading(true);
    try {
      const data = await apiCall('/api/analyze', { method: 'POST', body: JSON.stringify({ input }) });
      onResult(data.result, data.scanId);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function analyzeFile() {
    if (!file) { setError('Select a file first.'); return; }
    setError(''); setLoading(true);
    try {
      const token = await getToken();
      const form = new FormData();
      form.append('file', file);
      const res = await fetch(`${API}/api/analyze/file`, {
        method: 'POST',
        headers: token ? { Authorization: `Bearer ${token}` } : {},
        body: form,
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Upload failed');
      onResult(data.result, data.scanId);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function streamAnalyze() {
    if (input.trim().length < 10) { setError('Please enter at least 10 characters.'); return; }
    setError(''); setStreamLines([]); setStreamDone(false); setLoading(true);

    try {
      const token = await getToken();
      const res = await fetch(`${API}/api/analyze/stream`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ input }),
      });

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const parts = buffer.split('\n\n');
        buffer = parts.pop();
        for (const part of parts) {
          if (!part.startsWith('data:')) continue;
          const msg = JSON.parse(part.slice(5).trim());
          if (msg.type === 'chunk') {
            setStreamLines(prev => {
              const lines = [...prev];
              const last = lines[lines.length - 1] || '';
              const combined = last + msg.text;
              const split = combined.split('\n');
              return [...lines.slice(0, -1), ...split];
            });
          } else if (msg.type === 'done') {
            setStreamDone(true);
            setLoading(false);
            setTimeout(() => onResult(msg.result, msg.scanId), 1200);
          } else if (msg.type === 'error') {
            setError(msg.message);
            setLoading(false);
          }
        }
      }
    } catch (err) {
      setError(err.message);
      setLoading(false);
    }
  }

  async function compareModels() {
    if (input.trim().length < 10) { setError('Please enter at least 10 characters.'); return; }
    setError(''); setCompareResult(null); setLoading(true);

    try {
      const token = await getToken();
      const res = await fetch(`${API}/api/analyze/compare`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ input }),
      });

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const parts = buffer.split('\n\n');
        buffer = parts.pop();
        for (const part of parts) {
          if (!part.startsWith('data:')) continue;
          const msg = JSON.parse(part.slice(5).trim());
          if (msg.type === 'done') {
            setCompareResult(msg.models);
            setLoading(false);
          } else if (msg.type === 'error') {
            setError(msg.message);
            setLoading(false);
          }
        }
      }
    } catch (err) {
      setError(err.message);
      setLoading(false);
    }
  }

  const tabs = [
    { id: 'text',    label: 'Paste Logs',    icon: <FileText size={14} /> },
    { id: 'file',    label: 'Upload File',   icon: <Upload size={14} /> },
    { id: 'stream',  label: 'Live Stream',   icon: <Terminal size={14} /> },
    { id: 'compare', label: 'Model Compare', icon: <Cpu size={14} /> },
  ];

  return (
    <div className="max-w-4xl mx-auto px-4 py-8 animate-fadeUp">
      {toastEl}
      {/* Header */}
      <div className="text-center mb-8">
        <div className="inline-flex items-center gap-2 bg-blue-600/10 border border-blue-500/20 rounded-full px-4 py-1.5 text-blue-400 text-xs font-semibold mb-4">
          <Zap size={12} /> Powered by Groq · Llama 3.3 70B
        </div>
        <h1 className="text-3xl font-black text-white mb-2">Analyze Security Logs</h1>
        <p className="text-slate-500 text-sm">Paste logs, upload files, or stream live — get instant MITRE ATT&CK mapping, IOC extraction, and remediation steps.</p>
      </div>

      <Card>
        {/* Tabs */}
        <div className="flex gap-1 mb-5 p-1 rounded-lg bg-white/5 overflow-x-auto">
          {tabs.map(t => (
            <button key={t.id} onClick={() => { setTab(t.id); setError(''); setCompareResult(null); setStreamLines([]); }}
              className={cls('flex items-center gap-1.5 px-3 py-2 rounded-md text-sm font-medium whitespace-nowrap transition-all flex-1 justify-center',
                tab === t.id ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-slate-200')}>
              {t.icon} {t.label}
            </button>
          ))}
        </div>

        {/* Text / Stream / Compare input */}
        {(tab === 'text' || tab === 'stream' || tab === 'compare') && (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <label className="text-xs text-slate-400">Security Log Data</label>
              <button onClick={() => setInput(SAMPLE_LOG)}
                className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1 transition-colors">
                <RefreshCw size={11} /> Use sample
              </button>
            </div>
            <textarea value={input} onChange={e => setInput(e.target.value)}
              rows={10}
              placeholder="Paste firewall logs, SIEM events, EDR alerts, auth logs, network captures…"
              className="w-full bg-[#07090F] border border-white/10 rounded-lg px-4 py-3 text-sm text-slate-200 placeholder-slate-700 font-mono resize-none" />
            <div className="text-xs text-slate-600">{input.length.toLocaleString()} chars · {input.split('\n').filter(l => l.trim()).length} lines</div>
          </div>
        )}

        {/* File upload */}
        {tab === 'file' && (
          <div className="space-y-4">
            <label className="block border-2 border-dashed border-white/10 rounded-xl p-8 text-center cursor-pointer hover:border-blue-500/40 transition-colors group"
              onDragOver={e => e.preventDefault()}
              onDrop={e => { e.preventDefault(); const f = e.dataTransfer.files[0]; if (f) setFile(f); }}>
              <input type="file" accept=".txt,.log,.json,.csv" className="sr-only"
                onChange={e => setFile(e.target.files[0])} />
              <Upload size={32} className="mx-auto mb-3 text-slate-600 group-hover:text-blue-400 transition-colors" />
              {file ? (
                <div>
                  <p className="text-blue-400 font-semibold">{file.name}</p>
                  <p className="text-slate-500 text-sm">{(file.size / 1024).toFixed(1)} KB</p>
                </div>
              ) : (
                <div>
                  <p className="text-slate-400 font-medium">Drop file here or click to browse</p>
                  <p className="text-slate-600 text-sm mt-1">.txt · .log · .json · .csv · max 5 MB</p>
                </div>
              )}
            </label>
          </div>
        )}

        {/* Stream terminal output */}
        {tab === 'stream' && streamLines.length > 0 && (
          <div ref={termRef} className="mt-4 bg-black/60 border border-white/5 rounded-xl p-4 h-56 overflow-y-auto font-mono text-xs leading-relaxed">
            <div className="flex items-center gap-2 mb-3 pb-2 border-b border-white/5">
              <div className="flex gap-1.5">
                <div className="w-2.5 h-2.5 rounded-full bg-red-500/60" />
                <div className="w-2.5 h-2.5 rounded-full bg-yellow-500/60" />
                <div className="w-2.5 h-2.5 rounded-full bg-green-500/60" />
              </div>
              <span className="text-slate-600">clarion — live analysis</span>
            </div>
            {streamLines.map((line, i) => (
              <div key={i} className="text-green-400/90">
                {i === streamLines.length - 1 && !streamDone
                  ? <>{line}<span className="inline-block w-1.5 h-3.5 bg-green-400 ml-0.5 align-middle" style={{ animation: 'blink 1s step-end infinite' }} /></>
                  : line || '\u00A0'}
              </div>
            ))}
            {streamDone && <div className="text-cyan-400 mt-2">✓ Analysis complete — loading report…</div>}
          </div>
        )}

        {/* Compare result */}
        {tab === 'compare' && compareResult && (
          <div className="mt-5 grid md:grid-cols-2 gap-4">
            {compareResult.map(model => (
              <div key={model.id} className="bg-white/3 border border-white/8 rounded-xl p-4">
                <div className="flex items-center justify-between mb-3">
                  <span className="font-bold text-sm text-white">{model.label}</span>
                  {model.result && <SeverityBadge severity={model.result.severity} />}
                </div>
                {model.error ? (
                  <p className="text-red-400 text-xs">{model.error}</p>
                ) : model.result ? (
                  <div className="space-y-2">
                    <div className="flex items-center gap-3">
                      <span className="text-2xl font-black tabular-nums" style={{ color: riskColor(model.result.riskScore) }}>{model.result.riskScore}</span>
                      <span className="text-xs text-slate-500">risk score</span>
                    </div>
                    <p className="text-xs text-slate-400 leading-relaxed">{model.result.summary?.substring(0, 160)}…</p>
                    <div className="text-xs text-slate-500">{model.result.iocs?.length || 0} IOCs · {model.result.mitreMapping?.length || 0} techniques</div>
                    <Btn size="sm" variant="outline" onClick={() => onResult(model.result, model.scanId)}>
                      View Full Report <ChevronRight size={12} />
                    </Btn>
                  </div>
                ) : null}
              </div>
            ))}
          </div>
        )}

        {error && (
          <div className="mt-4 flex items-center gap-2 text-red-400 text-sm bg-red-400/10 border border-red-400/20 rounded-lg px-3 py-2">
            <XCircle size={14} /> {error}
          </div>
        )}

        <div className="mt-5 flex justify-end">
          <Btn size="lg" disabled={loading}
            onClick={tab === 'text' ? analyzeText : tab === 'file' ? analyzeFile : tab === 'stream' ? streamAnalyze : compareModels}>
            {loading ? <><Spinner /> Analyzing…</> : tab === 'stream' ? <><Terminal size={16} /> Start Live Stream</> : tab === 'compare' ? <><Cpu size={16} /> Compare Models</> : <><Zap size={16} /> Analyze Now</>}
          </Btn>
        </div>
      </Card>

      {/* Feature grid */}
      <div className="grid sm:grid-cols-3 gap-3 mt-6">
        {[
          { icon: <Target size={16} className="text-purple-400" />, title: 'MITRE ATT&CK', desc: 'Full framework mapping with confidence scores' },
          { icon: <Search size={16} className="text-cyan-400" />,   title: 'IOC Extraction', desc: 'IPs, domains, hashes, files, processes, registry' },
          { icon: <CheckCircle size={16} className="text-green-400" />, title: 'Remediation', desc: 'Actionable steps for containment & recovery' },
        ].map(f => (
          <div key={f.title} className="glass rounded-xl p-4">
            <div className="flex items-center gap-2 mb-1.5">{f.icon}<span className="font-semibold text-sm">{f.title}</span></div>
            <p className="text-xs text-slate-500">{f.desc}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Report page ───────────────────────────────────────────────────

function ReportPage({ result, scanId, onBack, user }) {
  const [activeSection, setActiveSection] = useState('overview');
  const [iocMatches, setIocMatches] = useState([]);
  const [tags, setTags] = useState(result?.tags || []);
  const [tagInput, setTagInput] = useState('');
  const [isPublic, setIsPublic] = useState(result?.is_public || false);
  const [chat, setChat] = useState([]);
  const [chatQ, setChatQ] = useState('');
  const [chatLoading, setChatLoading] = useState(false);
  const chatRef = useRef(null);
  const { show: showToast, el: toastEl } = useToast();

  useEffect(() => {
    if (scanId) loadIocMatches();
    if (scanId) loadChatHistory();
  }, [scanId]);

  useEffect(() => {
    if (chatRef.current) chatRef.current.scrollTop = chatRef.current.scrollHeight;
  }, [chat]);

  async function loadIocMatches() {
    try {
      const data = await apiCall(`/api/scans/${scanId}/matches`);
      setIocMatches(data.matches || []);
    } catch (_) {}
  }

  async function loadChatHistory() {
    try {
      const data = await apiCall(`/api/chat/${scanId}`);
      setChat(data.messages || []);
    } catch (_) {}
  }

  async function sendChat(e) {
    e.preventDefault();
    if (!chatQ.trim() || chatLoading || !scanId) return;
    const q = chatQ.trim();
    setChatQ('');
    setChat(prev => [...prev, { role: 'user', content: q, id: Date.now() }]);
    setChatLoading(true);

    try {
      const token = await getToken();
      const res = await fetch(`${API}/api/chat/${scanId}/stream`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ question: q }),
      });

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      let answerText = '';
      const msgId = Date.now() + 1;
      setChat(prev => [...prev, { role: 'assistant', content: '', id: msgId }]);

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const parts = buffer.split('\n\n');
        buffer = parts.pop();
        for (const part of parts) {
          if (!part.startsWith('data:')) continue;
          const msg = JSON.parse(part.slice(5).trim());
          if (msg.type === 'chunk') {
            answerText += msg.text;
            setChat(prev => prev.map(m => m.id === msgId ? { ...m, content: answerText } : m));
          } else if (msg.type === 'done' || msg.type === 'error') {
            setChatLoading(false);
          }
        }
      }
    } catch (err) {
      showToast(err.message, 'error');
    } finally {
      setChatLoading(false);
    }
  }

  async function addTag() {
    const t = tagInput.trim();
    if (!t || tags.includes(t) || !scanId) return;
    const newTags = [...tags, t];
    setTags(newTags); setTagInput('');
    try { await apiCall(`/api/scans/${scanId}/tags`, { method: 'PATCH', body: JSON.stringify({ tags: newTags }) }); }
    catch (_) { setTags(tags); }
  }

  async function removeTag(t) {
    const newTags = tags.filter(x => x !== t);
    setTags(newTags);
    if (scanId) {
      try { await apiCall(`/api/scans/${scanId}/tags`, { method: 'PATCH', body: JSON.stringify({ tags: newTags }) }); }
      catch (_) { setTags(tags); }
    }
  }

  async function toggleShare() {
    if (!scanId) return;
    try {
      const data = await apiCall(`/api/scans/${scanId}/share`, { method: 'PATCH' });
      setIsPublic(data.is_public);
      if (data.is_public) {
        await navigator.clipboard.writeText(`${window.location.origin}?share=${scanId}`);
        showToast('Public link copied to clipboard!', 'success');
      } else {
        showToast('Report is now private.', 'info');
      }
    } catch (err) {
      showToast(err.message, 'error');
    }
  }

  const r = result;
  if (!r) return null;

  const sections = [
    { id: 'overview',     label: 'Overview',    icon: <Activity size={14} /> },
    { id: 'timeline',     label: 'Timeline',    icon: <List size={14} /> },
    { id: 'iocs',         label: `IOCs (${r.iocs?.length || 0})`, icon: <Search size={14} /> },
    { id: 'mitre',        label: 'ATT&CK',      icon: <Target size={14} /> },
    { id: 'systems',      label: 'Systems',     icon: <Server size={14} /> },
    { id: 'remediation',  label: 'Remediation', icon: <CheckCircle size={14} /> },
    { id: 'chat',         label: 'AI Chat',     icon: <MessageSquare size={14} /> },
  ];

  const mitreForRadar = (r.mitreMapping || []).slice(0, 8).map(m => ({
    technique: m.name?.split(' ').slice(0, 2).join(' '),
    confidence: m.confidence || 0,
  }));

  return (
    <div className="max-w-6xl mx-auto px-4 py-6 animate-fadeUp">
      {toastEl}

      {/* Top bar */}
      <div className="flex items-center justify-between mb-5 flex-wrap gap-3">
        <button onClick={onBack} className="flex items-center gap-2 text-slate-400 hover:text-white text-sm transition-colors">
          <ArrowLeft size={16} /> Back
        </button>
        <div className="flex items-center gap-2 flex-wrap">
          {tags.map(t => (
            <span key={t} className="flex items-center gap-1 bg-purple-600/20 text-purple-300 text-xs px-2 py-0.5 rounded-full border border-purple-500/20">
              <Tag size={10} /> {t}
              <button onClick={() => removeTag(t)} className="ml-1 opacity-60 hover:opacity-100"><X size={9} /></button>
            </span>
          ))}
          <div className="flex items-center gap-1">
            <input value={tagInput} onChange={e => setTagInput(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && addTag()}
              placeholder="Add tag…" className="bg-white/5 border border-white/10 rounded-lg px-2 py-1 text-xs text-white placeholder-slate-600 w-24" />
            <button onClick={addTag} className="p-1 rounded-md hover:bg-white/10 text-slate-400 hover:text-white transition-colors">
              <Plus size={13} />
            </button>
          </div>
          <Btn size="sm" variant="ghost" onClick={toggleShare}>
            {isPublic ? <><Globe size={13} className="text-green-400" /> Public</> : <><Lock size={13} /> Share</>}
          </Btn>
          <Btn size="sm" variant="ghost" onClick={() => window.print()} className="no-print">
            <Download size={13} /> PDF
          </Btn>
        </div>
      </div>

      {/* Hero */}
      <Card className="mb-5">
        <div className="flex flex-col md:flex-row gap-6 items-start md:items-center">
          <RiskGauge score={r.riskScore} />
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-3 mb-2 flex-wrap">
              <SeverityBadge severity={r.severity} size="lg" />
              <span className="text-xs text-slate-500 font-mono">
                Confidence: <ConfidencePill value={r.confidence} />
              </span>
            </div>
            <h2 className="text-xl font-black text-white mb-2">{r.title || 'Security Analysis Report'}</h2>
            <p className="text-slate-400 text-sm leading-relaxed">{r.summary}</p>
            <div className="flex gap-4 mt-3 text-xs text-slate-500">
              <span><span className="text-white font-semibold">{r.iocs?.length || 0}</span> IOCs</span>
              <span><span className="text-white font-semibold">{r.mitreMapping?.length || 0}</span> Techniques</span>
              <span><span className="text-white font-semibold">{r.affectedSystems?.length || 0}</span> Systems</span>
              <span><span className="text-white font-semibold">{r.remediation?.length || 0}</span> Actions</span>
            </div>
          </div>
        </div>
      </Card>

      {/* Section nav */}
      <div className="flex gap-1 mb-5 overflow-x-auto pb-1 no-print">
        {sections.map(s => (
          <button key={s.id} onClick={() => setActiveSection(s.id)}
            className={cls('flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium whitespace-nowrap transition-all',
              activeSection === s.id
                ? 'bg-blue-600/20 text-blue-400 border border-blue-500/25'
                : 'text-slate-400 hover:text-slate-200 hover:bg-white/5')}>
            {s.icon} {s.label}
          </button>
        ))}
      </div>

      {/* Overview */}
      {activeSection === 'overview' && (
        <div className="space-y-5 animate-fadeUp">
          {/* MITRE radar + top IOCs */}
          <div className="grid md:grid-cols-2 gap-5">
            {mitreForRadar.length > 2 && (
              <Card>
                <h3 className="text-sm font-bold text-white mb-3 flex items-center gap-2"><Target size={14} className="text-purple-400" /> ATT&CK Coverage</h3>
                <ResponsiveContainer width="100%" height={200}>
                  <RadarChart data={mitreForRadar}>
                    <PolarGrid stroke="rgba(255,255,255,0.05)" />
                    <PolarAngleAxis dataKey="technique" tick={{ fill: '#64748b', fontSize: 10 }} />
                    <Radar dataKey="confidence" stroke="#8B5CF6" fill="#8B5CF6" fillOpacity={0.2} strokeWidth={1.5} />
                  </RadarChart>
                </ResponsiveContainer>
              </Card>
            )}
            <Card>
              <h3 className="text-sm font-bold text-white mb-3 flex items-center gap-2"><AlertTriangle size={14} className="text-orange-400" /> Top IOCs</h3>
              <div className="space-y-2">
                {(r.iocs || []).slice(0, 5).map((ioc, i) => (
                  <div key={i} className="flex items-center gap-2 text-xs">
                    <span className={cls('flex items-center gap-1 px-1.5 py-0.5 rounded text-slate-300 bg-white/5', `dot-${ioc.threat}`)}>
                      {iocIcon(ioc.type)} {ioc.type}
                    </span>
                    <span className="font-mono text-slate-300 truncate flex-1">{ioc.value}</span>
                    <span className={cls('w-1.5 h-1.5 rounded-full', severityDot(ioc.threat))} />
                  </div>
                ))}
                {(r.iocs?.length || 0) > 5 && (
                  <button onClick={() => setActiveSection('iocs')} className="text-xs text-blue-400 hover:text-blue-300 mt-1">
                    +{r.iocs.length - 5} more IOCs →
                  </button>
                )}
              </div>
            </Card>
          </div>

          {/* Severity bar chart */}
          {(r.mitreMapping?.length || 0) > 0 && (
            <Card>
              <h3 className="text-sm font-bold text-white mb-3 flex items-center gap-2"><BarChart2 size={14} className="text-blue-400" /> Technique Confidence</h3>
              <ResponsiveContainer width="100%" height={180}>
                <BarChart data={(r.mitreMapping || []).slice(0, 8)} margin={{ left: -20 }}>
                  <XAxis dataKey="name" tick={{ fill: '#475569', fontSize: 10 }} interval={0} angle={-20} textAnchor="end" height={50} />
                  <YAxis tick={{ fill: '#475569', fontSize: 10 }} domain={[0, 100]} />
                  <Tooltip contentStyle={{ background: '#0F1929', border: '1px solid rgba(59,130,246,0.2)', borderRadius: 8, fontSize: 12 }} />
                  <Bar dataKey="confidence" radius={[4, 4, 0, 0]}>
                    {(r.mitreMapping || []).slice(0, 8).map((entry, i) => (
                      <Cell key={i} fill={entry.confidence >= 80 ? '#EF4444' : entry.confidence >= 60 ? '#F97316' : entry.confidence >= 40 ? '#F59E0B' : '#22C55E'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </Card>
          )}
        </div>
      )}

      {/* Timeline */}
      {activeSection === 'timeline' && (
        <Card className="animate-fadeUp">
          <h3 className="text-sm font-bold text-white mb-4 flex items-center gap-2"><List size={14} className="text-blue-400" /> Attack Timeline</h3>
          <div className="relative pl-6 space-y-4">
            <div className="absolute left-2 top-0 bottom-0 w-px bg-white/5" />
            {(r.timeline || []).map((ev, i) => (
              <div key={i} className="relative animate-slideIn" style={{ animationDelay: `${i * 50}ms` }}>
                <div className={cls('absolute -left-4 top-1.5 w-2 h-2 rounded-full ring-2 ring-[#07090F]', severityDot(ev.severity))} />
                <div className="glass rounded-xl p-3">
                  <div className="flex items-center justify-between flex-wrap gap-2 mb-1">
                    <code className="text-xs text-cyan-400 font-mono">{ev.time}</code>
                    <div className="flex items-center gap-2">
                      {ev.tactic && <span className="text-xs bg-purple-600/20 text-purple-300 px-1.5 py-0.5 rounded border border-purple-500/20">{ev.tactic}</span>}
                      <SeverityBadge severity={ev.severity} />
                      <ConfidencePill value={ev.confidence} />
                    </div>
                  </div>
                  <p className="text-sm text-slate-300">{ev.event}</p>
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* IOCs */}
      {activeSection === 'iocs' && (
        <div className="space-y-3 animate-fadeUp">
          {iocMatches.length > 0 && (
            <div className="flex items-center gap-2 bg-orange-400/10 border border-orange-400/20 rounded-xl px-4 py-3">
              <AlertTriangle size={15} className="text-orange-400" />
              <span className="text-sm text-orange-300">
                <span className="font-bold">{iocMatches.length} IOC{iocMatches.length !== 1 ? 's' : ''}</span> seen across multiple scans — pattern detected
              </span>
            </div>
          )}
          <div className="grid sm:grid-cols-2 gap-3">
            {(r.iocs || []).map((ioc, i) => {
              const repeated = iocMatches.find(m => m.ioc_value === ioc.value);
              return (
                <Card key={i} className={cls('space-y-2', repeated && 'border-orange-400/20')}>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="flex items-center gap-1 bg-white/5 px-2 py-0.5 rounded text-xs text-slate-300">
                        {iocIcon(ioc.type)} {ioc.type}
                      </span>
                      <SeverityBadge severity={ioc.threat} />
                      {repeated && (
                        <span className="text-xs text-orange-400 flex items-center gap-1">
                          <Eye size={10} /> ×{repeated.hit_count}
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-1">
                      <ConfidencePill value={ioc.confidence} />
                      <button onClick={() => { navigator.clipboard.writeText(ioc.value); }}
                        className="p-1 rounded hover:bg-white/10 text-slate-500 hover:text-slate-300 transition-colors">
                        <Copy size={11} />
                      </button>
                    </div>
                  </div>
                  <code className="block text-xs font-mono text-cyan-300 break-all">{ioc.value}</code>
                  {ioc.description && <p className="text-xs text-slate-400">{ioc.description}</p>}
                  {ioc.reasoning && <p className="text-xs text-slate-500 italic">{ioc.reasoning}</p>}
                </Card>
              );
            })}
          </div>
        </div>
      )}

      {/* MITRE ATT&CK */}
      {activeSection === 'mitre' && (
        <div className="space-y-3 animate-fadeUp">
          {(r.mitreMapping || []).map((m, i) => (
            <Card key={i} className="space-y-2">
              <div className="flex items-center justify-between flex-wrap gap-2">
                <div className="flex items-center gap-2">
                  <code className="text-blue-400 font-mono text-xs bg-blue-400/10 px-2 py-0.5 rounded">{m.technique}</code>
                  <span className="font-semibold text-sm text-white">{m.name}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs text-purple-300 bg-purple-600/20 border border-purple-500/20 px-2 py-0.5 rounded">{m.tactic}</span>
                  <ConfidencePill value={m.confidence} />
                </div>
              </div>
              {m.evidence && (
                <p className="text-xs text-slate-400 bg-white/3 rounded-lg px-3 py-2 border-l-2 border-blue-500/30">
                  <span className="text-slate-500">Evidence: </span>{m.evidence}
                </p>
              )}
            </Card>
          ))}
        </div>
      )}

      {/* Affected Systems */}
      {activeSection === 'systems' && (
        <div className="grid sm:grid-cols-2 gap-3 animate-fadeUp">
          {(r.affectedSystems || []).map((sys, i) => (
            <Card key={i} className="flex items-start gap-3">
              <div className="w-8 h-8 rounded-lg bg-blue-600/10 flex items-center justify-center flex-shrink-0">
                <Server size={14} className="text-blue-400" />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <code className="text-sm font-mono text-cyan-300">{sys.host}</code>
                  <ConfidencePill value={sys.confidence} />
                </div>
                <div className="flex items-center gap-2 mt-1">
                  <span className={cls('text-xs px-2 py-0.5 rounded-full border', severityColor(sys.status === 'Compromised' ? 'HIGH' : sys.status === 'Potentially Compromised' ? 'MEDIUM' : 'LOW'))}>
                    {sys.status}
                  </span>
                  <div className="flex-1 bg-white/5 rounded-full h-1.5">
                    <div className="h-full rounded-full transition-all" style={{ width: `${sys.risk}%`, background: riskColor(sys.risk) }} />
                  </div>
                  <span className="text-xs text-slate-500 font-mono">{sys.risk}</span>
                </div>
              </div>
            </Card>
          ))}
        </div>
      )}

      {/* Remediation */}
      {activeSection === 'remediation' && (
        <div className="space-y-3 animate-fadeUp">
          {(r.remediation || []).map((step, i) => (
            <Card key={i} className={cls('flex items-start gap-3', step.urgent && 'border-red-400/25')}>
              <div className={cls('w-7 h-7 rounded-lg flex items-center justify-center text-xs font-black flex-shrink-0',
                step.urgent ? 'bg-red-600/20 text-red-400' : 'bg-blue-600/15 text-blue-400')}>
                {step.priority}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap mb-1">
                  <span className="text-xs bg-white/5 text-slate-400 px-2 py-0.5 rounded border border-white/8">{step.category}</span>
                  {step.urgent && <span className="text-xs text-red-400 flex items-center gap-1"><AlertTriangle size={10} /> Urgent</span>}
                  <ConfidencePill value={step.confidence} />
                </div>
                <p className="text-sm text-slate-300">{step.action}</p>
              </div>
            </Card>
          ))}
        </div>
      )}

      {/* AI Chat */}
      {activeSection === 'chat' && (
        <Card className="flex flex-col h-[560px] animate-fadeUp">
          <div className="flex items-center gap-2 mb-4 pb-3 border-b border-white/5">
            <div className="w-7 h-7 rounded-lg bg-purple-600/20 flex items-center justify-center">
              <MessageSquare size={13} className="text-purple-400" />
            </div>
            <div>
              <div className="text-sm font-bold text-white">AI Threat Analyst</div>
              <div className="text-xs text-slate-500">Ask questions about this incident</div>
            </div>
          </div>

          <div ref={chatRef} className="flex-1 overflow-y-auto space-y-3 mb-4 pr-1">
            {chat.length === 0 && (
              <div className="space-y-2">
                <p className="text-xs text-slate-500 text-center py-4">Start a conversation about this incident</p>
                {['What is the most critical finding?', 'Explain the lateral movement detected.', 'What should I do first?'].map(q => (
                  <button key={q} onClick={() => setChatQ(q)}
                    className="w-full text-left text-xs text-slate-400 bg-white/3 hover:bg-white/6 border border-white/8 rounded-lg px-3 py-2 transition-colors">
                    {q}
                  </button>
                ))}
              </div>
            )}
            {chat.map((msg, i) => (
              <div key={msg.id || i} className={cls('flex gap-2', msg.role === 'user' ? 'justify-end' : 'justify-start')}>
                {msg.role === 'assistant' && (
                  <div className="w-6 h-6 rounded-full bg-purple-600/20 flex items-center justify-center flex-shrink-0 mt-0.5">
                    <Shield size={11} className="text-purple-400" />
                  </div>
                )}
                <div className={cls('max-w-[80%] rounded-xl px-3 py-2 text-sm leading-relaxed',
                  msg.role === 'user'
                    ? 'bg-blue-600/20 text-blue-100 border border-blue-500/20'
                    : 'bg-white/5 text-slate-300 border border-white/8')}>
                  {msg.content || (chatLoading && msg.role === 'assistant' && i === chat.length - 1 ? <Spinner size={12} /> : '')}
                </div>
              </div>
            ))}
          </div>

          {!scanId && (
            <p className="text-xs text-slate-600 text-center mb-2">Sign in to save scans and use chat</p>
          )}

          <form onSubmit={sendChat} className="flex gap-2">
            <input value={chatQ} onChange={e => setChatQ(e.target.value)}
              disabled={!scanId || chatLoading}
              placeholder={scanId ? 'Ask about this incident…' : 'Sign in to use chat'}
              className="flex-1 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-600" />
            <Btn type="submit" disabled={!chatQ.trim() || chatLoading || !scanId} size="md">
              {chatLoading ? <Spinner size={14} /> : <Send size={14} />}
            </Btn>
          </form>
        </Card>
      )}
    </div>
  );
}

// ── History page ──────────────────────────────────────────────────

function HistoryPage({ onOpenScan }) {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState('all');

  useEffect(() => { load(); }, []);

  async function load() {
    setLoading(true);
    try {
      const data = await apiCall('/api/scans');
      setScans(data.scans || []);
    } catch (_) {}
    setLoading(false);
  }

  const filtered = scans.filter(s => {
    const matchSearch = !search || s.title?.toLowerCase().includes(search.toLowerCase()) ||
      s.tags?.some(t => t.toLowerCase().includes(search.toLowerCase()));
    const matchFilter = filter === 'all' || s.severity === filter;
    return matchSearch && matchFilter;
  });

  return (
    <div className="max-w-4xl mx-auto px-4 py-8 animate-fadeUp">
      <div className="flex items-center justify-between mb-6 flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-black text-white">Scan History</h1>
          <p className="text-slate-500 text-sm mt-1">{scans.length} analyses</p>
        </div>
        <Btn variant="ghost" onClick={load}><RefreshCw size={13} /> Refresh</Btn>
      </div>

      {/* Filters */}
      <div className="flex gap-3 mb-5 flex-wrap">
        <div className="relative flex-1 min-w-[200px]">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search scans…"
            className="w-full bg-white/5 border border-white/10 rounded-lg pl-9 pr-3 py-2 text-sm text-white placeholder-slate-600" />
        </div>
        <div className="flex gap-1">
          {['all', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(f => (
            <button key={f} onClick={() => setFilter(f)}
              className={cls('px-3 py-2 text-xs font-medium rounded-lg transition-all',
                filter === f ? 'bg-blue-600/20 text-blue-400 border border-blue-500/25' : 'text-slate-500 hover:text-slate-300 hover:bg-white/5')}>
              {f}
            </button>
          ))}
        </div>
      </div>

      {loading ? (
        <div className="space-y-3">
          {[1, 2, 3].map(i => <div key={i} className="skeleton h-20 w-full rounded-xl" />)}
        </div>
      ) : filtered.length === 0 ? (
        <div className="text-center py-16 text-slate-600">
          <History size={40} className="mx-auto mb-3 opacity-30" />
          <p>{scans.length === 0 ? 'No scans yet. Analyze your first log above.' : 'No scans match your filter.'}</p>
        </div>
      ) : (
        <div className="space-y-2">
          {filtered.map(scan => (
            <button key={scan.id} onClick={() => onOpenScan(scan.id)}
              className="w-full glass rounded-xl p-4 text-left hover:border-blue-500/25 transition-all group">
              <div className="flex items-center justify-between gap-3">
                <div className="flex items-center gap-3 flex-1 min-w-0">
                  <div className="w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0 font-black text-sm"
                    style={{ background: `${riskColor(scan.risk_score)}18`, color: riskColor(scan.risk_score) }}>
                    {scan.risk_score}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-semibold text-sm text-white truncate">{scan.title || 'Security Analysis'}</span>
                      <SeverityBadge severity={scan.severity} />
                      {scan.is_public && <Globe size={11} className="text-green-400" />}
                    </div>
                    <div className="flex items-center gap-3 mt-1">
                      <span className="text-xs text-slate-500">{fmtDate(scan.created_at)}</span>
                      {scan.tags?.map(t => (
                        <span key={t} className="text-xs bg-purple-600/15 text-purple-400 px-1.5 py-0.5 rounded">{t}</span>
                      ))}
                    </div>
                  </div>
                </div>
                <ChevronRight size={16} className="text-slate-600 group-hover:text-blue-400 transition-colors flex-shrink-0" />
              </div>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Public report page ────────────────────────────────────────────

function PublicReportPage({ scanId }) {
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    fetch(`${API}/api/public/${scanId}`)
      .then(r => r.json())
      .then(d => { if (d.scan) setScan(d.scan); else setError('Report not found or not public.'); })
      .catch(() => setError('Failed to load report.'))
      .finally(() => setLoading(false));
  }, [scanId]);

  if (loading) return (
    <div className="min-h-screen flex items-center justify-center">
      <Spinner size={24} />
    </div>
  );

  if (error) return (
    <div className="min-h-screen flex items-center justify-center text-slate-400">
      <div className="text-center">
        <Lock size={40} className="mx-auto mb-3 opacity-30" />
        <p>{error}</p>
      </div>
    </div>
  );

  const r = scan?.result;
  return (
    <div className="min-h-screen" style={{ background: 'var(--bg)' }}>
      <header className="border-b border-white/5 px-4 py-3 flex items-center gap-3">
        <Shield size={18} className="text-blue-400" />
        <span className="font-black text-white">Clarion</span>
        <span className="text-slate-600 text-sm">· Public Report</span>
        <span className="ml-auto text-xs text-slate-600">{fmtDate(scan.created_at)}</span>
      </header>
      <div className="max-w-4xl mx-auto px-4 py-8">
        <ReportPage result={r} scanId={null} onBack={() => {}} user={null} />
      </div>
    </div>
  );
}

// ── Main App ──────────────────────────────────────────────────────

export default function App() {
  const [user, setUser] = useState(null);
  const [authLoading, setAuthLoading] = useState(true);
  const [page, setPage] = useState('analyze');
  const [report, setReport] = useState(null);    // { result, scanId }
  const [loadingScan, setLoadingScan] = useState(false);

  // Check for public share URL
  const urlParams = new URLSearchParams(window.location.search);
  const shareId = urlParams.get('share');

  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => {
      setUser(data?.session?.user || null);
      setAuthLoading(false);
    });
    const { data: { subscription } } = supabase.auth.onAuthStateChange((_e, session) => {
      setUser(session?.user || null);
    });
    return () => subscription.unsubscribe();
  }, []);

  async function openScan(id) {
    setLoadingScan(true);
    try {
      const data = await apiCall(`/api/scans/${id}`);
      setReport({ result: { ...data.scan.result, tags: data.scan.tags, is_public: data.scan.is_public }, scanId: id });
      setPage('report');
    } catch (_) {}
    setLoadingScan(false);
  }

  async function signOut() {
    await supabase.auth.signOut();
    setUser(null); setReport(null); setPage('analyze');
  }

  // Public share view — no auth required
  if (shareId) return <PublicReportPage scanId={shareId} />;

  if (authLoading) return (
    <div className="min-h-screen flex items-center justify-center" style={{ background: 'var(--bg)' }}>
      <Spinner size={24} />
    </div>
  );

  if (!user) return <AuthPage onAuth={setUser} />;

  return (
    <div className="min-h-screen" style={{ background: 'var(--bg)' }}>
      <Navbar user={user} page={page} setPage={p => { setPage(p); setReport(null); }} onSignOut={signOut} />

      {loadingScan ? (
        <div className="flex items-center justify-center py-20"><Spinner size={24} /></div>
      ) : page === 'report' && report ? (
        <ReportPage
          result={report.result}
          scanId={report.scanId}
          user={user}
          onBack={() => { setReport(null); setPage('analyze'); }}
        />
      ) : page === 'history' ? (
        <HistoryPage onOpenScan={openScan} />
      ) : (
        <AnalyzePage onResult={(result, scanId) => {
          setReport({ result, scanId });
          setPage('report');
        }} />
      )}
    </div>
  );
}
