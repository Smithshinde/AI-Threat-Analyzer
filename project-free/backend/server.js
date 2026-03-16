/**
 * AI Threat Analyzer — Backend Server
 * Stack: Express · Groq (Llama) · Supabase
 *
 * Routes:
 *   POST /api/analyze            — Analyse text (standard)
 *   POST /api/analyze/file       — Analyse uploaded file
 *   POST /api/analyze/stream     — Analyse with live SSE streaming
 *   GET  /api/scans              — List scan history
 *   GET  /api/scans/:id          — Get single scan
 *   PATCH /api/scans/:id/tags    — Update tags on a scan
 *   PATCH /api/scans/:id/share   — Toggle public sharing
 *   GET  /api/public/:id         — Get a public scan (no auth)
 *   GET  /api/health             — Health check
 */

import 'dotenv/config';
import express   from 'express';
import cors      from 'cors';
import helmet    from 'helmet';
import rateLimit from 'express-rate-limit';
import multer    from 'multer';
import Groq      from 'groq-sdk';
import { createClient } from '@supabase/supabase-js';

// ── Clients ────────────────────────────────────────────────────
const app = express();

const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

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

const globalLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: { error: 'Too many requests. Please try again in a few minutes.' },
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
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    if (!/\.(txt|log|json|csv)$/i.test(file.originalname)) {
      return cb(new Error('Only .txt, .log, .json and .csv files are allowed.'));
    }
    cb(null, true);
  },
});

// ── AI prompts ─────────────────────────────────────────────────
const SYSTEM_PROMPT = `You are an elite threat intelligence analyst with deep expertise in:
- MITRE ATT&CK framework v14 (all tactics, techniques, and sub-techniques)
- Incident response, digital forensics, and log analysis
- Malware behavior, lateral movement patterns, and C2 communications
- Network security, endpoint detection, and threat hunting

Always be precise, technical, and actionable. Return ONLY valid JSON — no markdown, no explanation.`;

function buildPrompt(input) {
  return `Analyze the following security data and return ONLY a JSON object.

Security Data:
\`\`\`
${input.substring(0, 8000)}
\`\`\`

Return this exact JSON structure:
{
  "riskScore": <integer 0-100>,
  "severity": "<LOW|MEDIUM|HIGH|CRITICAL>",
  "summary": "<2-3 sentence executive summary>",
  "title": "<short 5-8 word incident title>",
  "timeline": [
    { "time": "<timestamp>", "event": "<description>", "severity": "<low|medium|high|critical>", "tactic": "<MITRE tactic>" }
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
    { "priority": <1-N>, "action": "<actionable step>", "category": "<Containment|Eradication|Recovery|Hardening>", "urgent": <true|false> }
  ]
}`;
}

function sanitize(raw) {
  return raw
    .replace(/<\|.*?\|>/g, '')
    .replace(/\[INST\]|\[\/INST\]/gi, '')
    .replace(/###\s*(?:System|Assistant|Human|User):/gi, '')
    .replace(/^(system|assistant|human|user):\s*/gim, '')
    .substring(0, 10000);
}

function parseResult(text) {
  const cleaned = text.replace(/```json\n?|\n?```/g, '').trim();
  const start = cleaned.indexOf('{');
  const end = cleaned.lastIndexOf('}');
  if (start === -1 || end === -1) throw new Error('No JSON found in response');
  return JSON.parse(cleaned.substring(start, end + 1));
}

async function saveToDb(userId, result, inputSize) {
  if (!userId) return null;
  const { data } = await supabase.from('scans').insert({
    user_id:    userId,
    risk_score: result.riskScore,
    severity:   result.severity,
    title:      result.title || null,
    result,
    input_size: inputSize,
    tags:       [],
    is_public:  false,
    created_at: new Date().toISOString(),
  }).select('id').single();
  return data?.id || null;
}

// ══════════════════════════════════════════════════════════════
// ROUTES
// ══════════════════════════════════════════════════════════════

// Health check
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ── Standard analysis ──────────────────────────────────────────
app.post('/api/analyze', authenticate, async (req, res) => {
  const { input } = req.body;
  if (!input || input.trim().length < 10) {
    return res.status(400).json({ error: 'Input must be at least 10 characters.' });
  }
  const sanitized = sanitize(input);
  try {
    const message = await groq.chat.completions.create({
      model: 'llama-3.3-70b-versatile',
      max_tokens: 4096,
      messages: [
        { role: 'system', content: SYSTEM_PROMPT },
        { role: 'user',   content: buildPrompt(sanitized) },
      ],
    });
    const rawText = message.choices[0]?.message?.content || '';
    const result = parseResult(rawText);
    const scanId = await saveToDb(req.user?.id, result, sanitized.length);
    res.json({ success: true, scanId, result });
  } catch (err) {
    console.error('Analysis error:', err.message);
    res.status(500).json({ error: err.message || 'Analysis failed.' });
  }
});

// ── File analysis ──────────────────────────────────────────────
app.post('/api/analyze/file', authenticate, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded.' });
  const input = req.file.buffer.toString('utf-8');
  if (input.trim().length < 10) return res.status(400).json({ error: 'File is empty.' });
  const sanitized = sanitize(input);
  try {
    const message = await groq.chat.completions.create({
      model: 'llama-3.3-70b-versatile',
      max_tokens: 4096,
      messages: [
        { role: 'system', content: SYSTEM_PROMPT },
        { role: 'user',   content: buildPrompt(sanitized) },
      ],
    });
    const rawText = message.choices[0]?.message?.content || '';
    const result = parseResult(rawText);
    const scanId = await saveToDb(req.user?.id, result, sanitized.length);
    res.json({ success: true, scanId, result });
  } catch (err) {
    console.error('File analysis error:', err.message);
    res.status(500).json({ error: err.message || 'Analysis failed.' });
  }
});

// ── Streaming analysis (SSE) ───────────────────────────────────
app.post('/api/analyze/stream', authenticate, async (req, res) => {
  const { input } = req.body;
  if (!input || input.trim().length < 10) {
    return res.status(400).json({ error: 'Input must be at least 10 characters.' });
  }
  const sanitized = sanitize(input);

  // Set SSE headers
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('Access-Control-Allow-Origin', process.env.FRONTEND_URL || 'http://localhost:5173');
  res.flushHeaders();

  const send = (data) => res.write(`data: ${JSON.stringify(data)}\n\n`);

  try {
    const stream = await groq.chat.completions.create({
      model: 'llama-3.3-70b-versatile',
      max_tokens: 4096,
      stream: true,
      messages: [
        { role: 'system', content: SYSTEM_PROMPT },
        { role: 'user',   content: buildPrompt(sanitized) },
      ],
    });

    let fullText = '';
    let charCount = 0;

    for await (const chunk of stream) {
      const text = chunk.choices[0]?.delta?.content || '';
      if (text) {
        fullText += text;
        charCount += text.length;
        send({ type: 'chunk', text, total: charCount });
      }
    }

    // Parse and save
    const result = parseResult(fullText);
    const scanId = await saveToDb(req.user?.id, result, sanitized.length);
    send({ type: 'done', result, scanId });

  } catch (err) {
    console.error('Streaming error:', err.message);
    send({ type: 'error', message: err.message || 'Analysis failed.' });
  }

  res.end();
});

// ── Scan history ───────────────────────────────────────────────
app.get('/api/scans', authenticate, async (req, res) => {
  if (!req.user?.id) return res.status(401).json({ error: 'Login required.' });
  const { data, error } = await supabase
    .from('scans')
    .select('id, risk_score, severity, title, tags, is_public, input_size, created_at')
    .eq('user_id', req.user.id)
    .order('created_at', { ascending: false })
    .limit(100);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ scans: data });
});

app.get('/api/scans/:id', authenticate, async (req, res) => {
  if (!req.user?.id) return res.status(401).json({ error: 'Login required.' });
  const { data, error } = await supabase
    .from('scans').select('*')
    .eq('id', req.params.id).eq('user_id', req.user.id).single();
  if (error || !data) return res.status(404).json({ error: 'Scan not found.' });
  res.json({ scan: data });
});

// ── Update tags ────────────────────────────────────────────────
app.patch('/api/scans/:id/tags', authenticate, async (req, res) => {
  if (!req.user?.id) return res.status(401).json({ error: 'Login required.' });
  const { tags } = req.body;
  if (!Array.isArray(tags)) return res.status(400).json({ error: 'Tags must be an array.' });
  const { error } = await supabase
    .from('scans').update({ tags })
    .eq('id', req.params.id).eq('user_id', req.user.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true, tags });
});

// ── Toggle public sharing ──────────────────────────────────────
app.patch('/api/scans/:id/share', authenticate, async (req, res) => {
  if (!req.user?.id) return res.status(401).json({ error: 'Login required.' });
  const { data: current } = await supabase
    .from('scans').select('is_public')
    .eq('id', req.params.id).eq('user_id', req.user.id).single();
  if (!current) return res.status(404).json({ error: 'Scan not found.' });
  const newValue = !current.is_public;
  const { error } = await supabase
    .from('scans').update({ is_public: newValue })
    .eq('id', req.params.id).eq('user_id', req.user.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true, is_public: newValue });
});

// ── Public scan (no auth) ──────────────────────────────────────
app.get('/api/public/:id', async (req, res) => {
  const { data, error } = await supabase
    .from('scans').select('id, risk_score, severity, title, tags, result, created_at')
    .eq('id', req.params.id).eq('is_public', true).single();
  if (error || !data) return res.status(404).json({ error: 'Report not found or not public.' });
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
  console.log(`   Running on http://localhost:${PORT}`);
  console.log(`   Groq model: llama-3.3-70b-versatile\n`);
});
