/**
 * AI Threat Analyzer — Backend Server (No Subscription Edition)
 * Stack: Express · Anthropic Claude · Supabase
 *
 * Routes:
 *   POST /api/analyze          — Analyse text input with Claude
 *   POST /api/analyze/file     — Analyse uploaded log file
 *   GET  /api/scans            — List user's scan history
 *   GET  /api/scans/:id        — Get single scan result
 *   GET  /api/health           — Health check
 */

import express   from 'express';
import cors      from 'cors';
import helmet    from 'helmet';
import rateLimit from 'express-rate-limit';
import multer    from 'multer';
import Anthropic from '@anthropic-ai/sdk';
import { createClient } from '@supabase/supabase-js';
import dotenv    from 'dotenv';
dotenv.config();

// ── Clients ────────────────────────────────────────────────────
const app = express();

const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// ── Middleware ─────────────────────────────────────────────────
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5173',
  credentials: true,
}));
app.use(express.json({ limit: '10mb' }));

// ── Rate limiting ──────────────────────────────────────────────
// Global: 100 requests per 15 minutes per IP
const globalLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests. Please try again in a few minutes.' },
});

// Analysis: max 30 scans per hour per user (generous, abuse prevention only)
const scanLimit = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 30,
  keyGenerator: (req) => req.user?.id || req.ip,
  message: { error: 'Too many scans this hour. Please wait a few minutes.' },
});

app.use('/api', globalLimit);

// ── Auth middleware ────────────────────────────────────────────
async function authenticate(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return next();
  try {
    const { data, error } = await supabase.auth.getUser(token);
    if (!error && data.user) req.user = data.user;
  } catch (_) {}
  next();
}

// ── File upload ────────────────────────────────────────────────
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB
  fileFilter: (_req, file, cb) => {
    if (!/\.(txt|log|json|csv)$/i.test(file.originalname)) {
      return cb(new Error('Only .txt .log .json .csv files are allowed.'));
    }
    cb(null, true);
  },
});

// ── Claude prompt ──────────────────────────────────────────────
const SYSTEM_PROMPT = `You are an elite threat intelligence analyst with deep expertise in:
- MITRE ATT&CK framework v14 (all tactics, techniques, sub-techniques)
- Incident response, digital forensics, and log analysis
- Malware behavior, lateral movement, and C2 communications
- Network security, endpoint detection, and threat hunting

Be precise, technical, and actionable. Return only valid JSON — no markdown, no preamble.`;

function buildPrompt(input) {
  return `Analyse the following security data and return ONLY a JSON object.

Security Data:
\`\`\`
${input.substring(0, 8000)}
\`\`\`

Return this exact structure:
{
  "riskScore": <integer 0-100>,
  "severity": "<LOW|MEDIUM|HIGH|CRITICAL>",
  "summary": "<2-3 sentence executive summary>",
  "timeline": [
    { "time": "<timestamp>", "event": "<what happened>", "severity": "<low|medium|high|critical>", "tactic": "<MITRE tactic>" }
  ],
  "affectedSystems": [
    { "host": "<ip or hostname>", "status": "<Compromised|Potentially Compromised|Under Investigation>", "risk": <0-100> }
  ],
  "iocs": [
    { "type": "<IP|Domain|Hash|File|Process|Registry>", "value": "<indicator>", "description": "<context>", "threat": "<low|medium|high|critical>" }
  ],
  "mitreMapping": [
    { "tactic": "<tactic name>", "technique": "<T-code>", "name": "<technique name>", "confidence": <0-100> }
  ],
  "remediation": [
    { "priority": <1-N>, "action": "<specific step>", "category": "<Containment|Eradication|Recovery|Hardening>", "urgent": <true|false> }
  ]
}`;
}

// Strip prompt injection patterns before sending to Claude
function sanitize(raw) {
  return raw
    .replace(/<\|.*?\|>/g, '')
    .replace(/\[INST\]|\[\/INST\]/gi, '')
    .replace(/###\s*(?:System|Assistant|Human|User):/gi, '')
    .replace(/^(system|assistant|human|user):\s*/gim, '')
    .substring(0, 10000);
}

async function runAnalysis(input) {
  const message = await anthropic.messages.create({
    model: 'claude-opus-4-6',
    max_tokens: 4096,
    system: SYSTEM_PROMPT,
    messages: [{ role: 'user', content: buildPrompt(input) }],
  });
  const raw = message.content[0]?.text || '';
  return JSON.parse(raw.replace(/```json\n?|\n?```/g, '').trim());
}

// ── Routes ─────────────────────────────────────────────────────

app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Analyse text input
app.post('/api/analyze', authenticate, scanLimit, async (req, res) => {
  const { input } = req.body;
  if (!input || input.trim().length < 10) {
    return res.status(400).json({ error: 'Input must be at least 10 characters.' });
  }
  try {
    const result = await runAnalysis(sanitize(input));
    let scanId = null;
    if (req.user?.id) {
      const { data } = await supabase.from('scans').insert({
        user_id: req.user.id, risk_score: result.riskScore,
        severity: result.severity, result, input_size: input.length,
      }).select('id').single();
      scanId = data?.id;
    }
    res.json({ success: true, scanId, result });
  } catch (err) {
    console.error('Analysis error:', err.message);
    if (err.status === 429) return res.status(429).json({ error: 'AI rate limit. Please wait a moment.' });
    res.status(500).json({ error: 'Analysis failed. Please try again.' });
  }
});

// Analyse uploaded file
app.post('/api/analyze/file', authenticate, scanLimit, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded.' });
  const input = req.file.buffer.toString('utf-8');
  if (input.trim().length < 10) return res.status(400).json({ error: 'File is empty.' });
  try {
    const result = await runAnalysis(sanitize(input));
    let scanId = null;
    if (req.user?.id) {
      const { data } = await supabase.from('scans').insert({
        user_id: req.user.id, risk_score: result.riskScore,
        severity: result.severity, result, input_size: input.length,
      }).select('id').single();
      scanId = data?.id;
    }
    res.json({ success: true, scanId, result });
  } catch (err) {
    console.error('File analysis error:', err.message);
    res.status(500).json({ error: 'Analysis failed. Please try again.' });
  }
});

// Scan history
app.get('/api/scans', authenticate, async (req, res) => {
  if (!req.user?.id) return res.status(401).json({ error: 'Login required.' });
  const { data, error } = await supabase
    .from('scans')
    .select('id, risk_score, severity, input_size, created_at')
    .eq('user_id', req.user.id)
    .order('created_at', { ascending: false })
    .limit(50);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ scans: data });
});

// Single scan
app.get('/api/scans/:id', authenticate, async (req, res) => {
  if (!req.user?.id) return res.status(401).json({ error: 'Login required.' });
  const { data, error } = await supabase
    .from('scans').select('*')
    .eq('id', req.params.id).eq('user_id', req.user.id).single();
  if (error || !data) return res.status(404).json({ error: 'Scan not found.' });
  res.json({ scan: data });
});

// ── Error handler ──────────────────────────────────────────────
app.use((err, _req, res, _next) => {
  if (err.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ error: 'File too large. Max 5 MB.' });
  if (err.message?.includes('Only .txt')) return res.status(400).json({ error: err.message });
  console.error('Unhandled error:', err.message);
  res.status(500).json({ error: 'Internal server error.' });
});

// ── Start ──────────────────────────────────────────────────────
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`\n🛡  AI Threat Analyzer API`);
  console.log(`   Running on http://localhost:${PORT}\n`);
});
