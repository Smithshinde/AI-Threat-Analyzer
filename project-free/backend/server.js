/**
 * AI Threat Analyzer — Enhanced Backend
 * Stack: Express · Groq (multi-model) · Supabase
 *
 * Routes:
 *   POST /api/analyze              — Standard analysis
 *   POST /api/analyze/file         — File analysis
 *   POST /api/analyze/stream       — Live streaming analysis
 *   POST /api/analyze/compare      — Multi-model side-by-side comparison
 *   GET  /api/scans                — Scan history
 *   GET  /api/scans/:id            — Single scan
 *   GET  /api/scans/:id/matches    — Historical IOC matches
 *   PATCH /api/scans/:id/tags      — Update tags
 *   PATCH /api/scans/:id/share     — Toggle public sharing
 *   GET  /api/public/:id           — Public scan (no auth)
 *   GET  /api/chat/:scanId         — Get chat history
 *   POST /api/chat/:scanId/stream  — Streaming AI chat about a scan
 *   GET  /api/health               — Health check
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

// ── Available models for comparison ───────────────────────────
const MODELS = {
  primary:   { id: 'llama-3.3-70b-versatile',  label: 'Llama 3.3 70B' },
  secondary: { id: 'mixtral-8x7b-32768',        label: 'Mixtral 8x7B'  },
};

// ── Middleware ─────────────────────────────────────────────────
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5173',
  credentials: true,
}));
app.use(express.json({ limit: '10mb' }));

const globalLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
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

// ── AI System prompts ──────────────────────────────────────────
const ANALYSIS_SYSTEM = `You are an elite threat intelligence analyst with deep expertise in:
- MITRE ATT&CK framework v14 (all tactics, techniques, and sub-techniques)
- Incident response, digital forensics, and log analysis
- Malware behavior, lateral movement patterns, and C2 communications
- Network security, endpoint detection, and threat hunting

Always be precise, technical, and actionable. Return ONLY valid JSON — no markdown, no explanation, no preamble.`;

const CHAT_SYSTEM = (scanContext) => `You are an expert threat intelligence analyst reviewing a specific security incident.

Here is the full threat report for this incident:
${JSON.stringify(scanContext, null, 2)}

Your role:
- Answer questions about this specific incident clearly and precisely
- Explain technical terms in plain English when asked
- Give actionable advice based on the actual findings in this report
- Reference specific IOCs, techniques, and timeline events from the report when relevant
- Be concise but thorough

Always ground your answers in the actual data from this report. Do not make up information not present in the report.`;

function buildAnalysisPrompt(input) {
  return `Analyze the following security data and return ONLY a JSON object.

Security Data:
\`\`\`
${input.substring(0, 8000)}
\`\`\`

Return this EXACT JSON structure (all fields required):
{
  "riskScore": <integer 0-100>,
  "severity": "<LOW|MEDIUM|HIGH|CRITICAL>",
  "summary": "<2-3 sentence executive summary>",
  "title": "<short 5-8 word incident title>",
  "confidence": <overall confidence 0-100>,
  "timeline": [
    {
      "time": "<timestamp>",
      "event": "<description>",
      "severity": "<low|medium|high|critical>",
      "tactic": "<MITRE tactic>",
      "confidence": <0-100>
    }
  ],
  "affectedSystems": [
    {
      "host": "<ip or hostname>",
      "status": "<Compromised|Potentially Compromised|Under Investigation>",
      "risk": <0-100>,
      "confidence": <0-100>
    }
  ],
  "iocs": [
    {
      "type": "<IP|Domain|Hash|File|Process|Registry>",
      "value": "<indicator>",
      "description": "<context>",
      "threat": "<low|medium|high|critical>",
      "confidence": <0-100>,
      "reasoning": "<one sentence explaining why this is an IOC>"
    }
  ],
  "mitreMapping": [
    {
      "tactic": "<tactic name>",
      "technique": "<T-code>",
      "name": "<technique name>",
      "confidence": <0-100>,
      "evidence": "<what in the logs supports this technique>"
    }
  ],
  "remediation": [
    {
      "priority": <1-N>,
      "action": "<actionable step>",
      "category": "<Containment|Eradication|Recovery|Hardening>",
      "urgent": <true|false>,
      "confidence": <0-100>
    }
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

// ── Save scan + index IOCs for pattern matching ────────────────
async function saveToDb(userId, result, inputSize, model = 'llama-3.3-70b-versatile') {
  if (!userId) return null;

  const { data } = await supabase.from('scans').insert({
    user_id:    userId,
    risk_score: result.riskScore,
    severity:   result.severity,
    title:      result.title || null,
    result,
    input_size: inputSize,
    model,
    tags:       [],
    is_public:  false,
    created_at: new Date().toISOString(),
  }).select('id').single();

  const scanId = data?.id;
  if (!scanId) return null;

  // Index IOCs for pattern matching
  if (result.iocs?.length && userId) {
    for (const ioc of result.iocs) {
      if (!ioc.value) continue;

      const { data: existing } = await supabase
        .from('ioc_matches')
        .select('id, scan_ids, hit_count')
        .eq('user_id', userId)
        .eq('ioc_value', ioc.value)
        .single();

      if (existing) {
        const scanIds = [...new Set([...(existing.scan_ids || []), scanId])];
        await supabase.from('ioc_matches').update({
          scan_ids:  scanIds,
          hit_count: scanIds.length,
          last_seen: new Date().toISOString(),
        }).eq('id', existing.id);
      } else {
        await supabase.from('ioc_matches').insert({
          user_id:   userId,
          ioc_value: ioc.value,
          ioc_type:  ioc.type,
          scan_ids:  [scanId],
          hit_count: 1,
          first_seen: new Date().toISOString(),
          last_seen:  new Date().toISOString(),
        });
      }
    }
  }

  return scanId;
}

// ── SSE helper ─────────────────────────────────────────────────
function initSSE(res) {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('Access-Control-Allow-Origin', process.env.FRONTEND_URL || 'http://localhost:5173');
  res.flushHeaders();
  return (data) => res.write(`data: ${JSON.stringify(data)}\n\n`);
}

// ══════════════════════════════════════════════════════════════
// ROUTES
// ══════════════════════════════════════════════════════════════

// Health
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', models: Object.values(MODELS).map(m => m.label), timestamp: new Date().toISOString() });
});

// ── Standard analysis ──────────────────────────────────────────
app.post('/api/analyze', authenticate, async (req, res) => {
  const { input } = req.body;
  if (!input || input.trim().length < 10) return res.status(400).json({ error: 'Input too short.' });
  const sanitized = sanitize(input);
  try {
    const message = await groq.chat.completions.create({
      model: MODELS.primary.id,
      max_tokens: 4096,
      messages: [
        { role: 'system', content: ANALYSIS_SYSTEM },
        { role: 'user',   content: buildAnalysisPrompt(sanitized) },
      ],
    });
    const result = parseResult(message.choices[0]?.message?.content || '');
    const scanId = await saveToDb(req.user?.id, result, sanitized.length, MODELS.primary.id);
    res.json({ success: true, scanId, result });
  } catch (err) {
    console.error('Analysis error:', err.message);
    res.status(500).json({ error: err.message || 'Analysis failed.' });
  }
});

// ── File analysis ──────────────────────────────────────────────
app.post('/api/analyze/file', authenticate, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded.' });
  const sanitized = sanitize(req.file.buffer.toString('utf-8'));
  try {
    const message = await groq.chat.completions.create({
      model: MODELS.primary.id,
      max_tokens: 4096,
      messages: [
        { role: 'system', content: ANALYSIS_SYSTEM },
        { role: 'user',   content: buildAnalysisPrompt(sanitized) },
      ],
    });
    const result = parseResult(message.choices[0]?.message?.content || '');
    const scanId = await saveToDb(req.user?.id, result, sanitized.length, MODELS.primary.id);
    res.json({ success: true, scanId, result });
  } catch (err) {
    res.status(500).json({ error: err.message || 'Analysis failed.' });
  }
});

// ── Streaming analysis ─────────────────────────────────────────
app.post('/api/analyze/stream', authenticate, async (req, res) => {
  const { input } = req.body;
  if (!input || input.trim().length < 10) return res.status(400).json({ error: 'Input too short.' });
  const sanitized = sanitize(input);
  const send = initSSE(res);

  try {
    const stream = await groq.chat.completions.create({
      model: MODELS.primary.id,
      max_tokens: 4096,
      stream: true,
      messages: [
        { role: 'system', content: ANALYSIS_SYSTEM },
        { role: 'user',   content: buildAnalysisPrompt(sanitized) },
      ],
    });

    let fullText = '';
    for await (const chunk of stream) {
      const text = chunk.choices[0]?.delta?.content || '';
      if (text) { fullText += text; send({ type: 'chunk', text }); }
    }

    const result = parseResult(fullText);
    const scanId = await saveToDb(req.user?.id, result, sanitized.length, MODELS.primary.id);
    send({ type: 'done', result, scanId });
  } catch (err) {
    send({ type: 'error', message: err.message || 'Analysis failed.' });
  }
  res.end();
});

// ── Multi-model comparison ─────────────────────────────────────
app.post('/api/analyze/compare', authenticate, async (req, res) => {
  const { input } = req.body;
  if (!input || input.trim().length < 10) return res.status(400).json({ error: 'Input too short.' });
  const sanitized = sanitize(input);
  const send = initSSE(res);

  try {
    send({ type: 'status', message: 'Running both models in parallel…' });

    // Run both models simultaneously
    const [r1, r2] = await Promise.allSettled([
      groq.chat.completions.create({
        model: MODELS.primary.id,
        max_tokens: 4096,
        messages: [
          { role: 'system', content: ANALYSIS_SYSTEM },
          { role: 'user',   content: buildAnalysisPrompt(sanitized) },
        ],
      }),
      groq.chat.completions.create({
        model: MODELS.secondary.id,
        max_tokens: 4096,
        messages: [
          { role: 'system', content: ANALYSIS_SYSTEM },
          { role: 'user',   content: buildAnalysisPrompt(sanitized) },
        ],
      }),
    ]);

    const primaryResult   = r1.status === 'fulfilled' ? parseResult(r1.value.choices[0]?.message?.content || '') : null;
    const secondaryResult = r2.status === 'fulfilled' ? parseResult(r2.value.choices[0]?.message?.content || '') : null;

    // Save primary to DB
    const scanId = primaryResult
      ? await saveToDb(req.user?.id, primaryResult, sanitized.length, MODELS.primary.id)
      : null;

    send({
      type: 'done',
      models: [
        { ...MODELS.primary,   result: primaryResult,   scanId, error: r1.status === 'rejected' ? r1.reason?.message : null },
        { ...MODELS.secondary, result: secondaryResult, scanId: null, error: r2.status === 'rejected' ? r2.reason?.message : null },
      ],
    });

  } catch (err) {
    send({ type: 'error', message: err.message || 'Comparison failed.' });
  }
  res.end();
});

// ── Scan history ───────────────────────────────────────────────
app.get('/api/scans', authenticate, async (req, res) => {
  if (!req.user?.id) return res.status(401).json({ error: 'Login required.' });
  const { data, error } = await supabase
    .from('scans')
    .select('id, risk_score, severity, title, tags, is_public, model, input_size, created_at')
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

// ── IOC matches for a scan ─────────────────────────────────────
app.get('/api/scans/:id/matches', authenticate, async (req, res) => {
  if (!req.user?.id) return res.status(401).json({ error: 'Login required.' });

  // Get the scan first to extract IOC values
  const { data: scan } = await supabase
    .from('scans').select('result')
    .eq('id', req.params.id).eq('user_id', req.user.id).single();

  if (!scan) return res.status(404).json({ error: 'Scan not found.' });

  const iocValues = (scan.result?.iocs || []).map(i => i.value).filter(Boolean);
  if (!iocValues.length) return res.json({ matches: [] });

  // Find any of these IOCs that appeared in more than one scan
  const { data: matches } = await supabase
    .from('ioc_matches')
    .select('ioc_value, ioc_type, hit_count, scan_ids, first_seen, last_seen')
    .eq('user_id', req.user.id)
    .in('ioc_value', iocValues)
    .gt('hit_count', 1)
    .order('hit_count', { ascending: false });

  res.json({ matches: matches || [] });
});

// ── Tags ───────────────────────────────────────────────────────
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

// ── Toggle sharing ─────────────────────────────────────────────
app.patch('/api/scans/:id/share', authenticate, async (req, res) => {
  if (!req.user?.id) return res.status(401).json({ error: 'Login required.' });
  const { data: current } = await supabase
    .from('scans').select('is_public')
    .eq('id', req.params.id).eq('user_id', req.user.id).single();
  if (!current) return res.status(404).json({ error: 'Scan not found.' });
  const newValue = !current.is_public;
  await supabase.from('scans').update({ is_public: newValue })
    .eq('id', req.params.id).eq('user_id', req.user.id);
  res.json({ success: true, is_public: newValue });
});

// ── Public scan ────────────────────────────────────────────────
app.get('/api/public/:id', async (req, res) => {
  const { data, error } = await supabase
    .from('scans').select('id, risk_score, severity, title, tags, result, created_at')
    .eq('id', req.params.id).eq('is_public', true).single();
  if (error || !data) return res.status(404).json({ error: 'Report not found or not public.' });
  res.json({ scan: data });
});

// ── Chat history ───────────────────────────────────────────────
app.get('/api/chat/:scanId', authenticate, async (req, res) => {
  if (!req.user?.id) return res.status(401).json({ error: 'Login required.' });
  const { data } = await supabase
    .from('chat_messages')
    .select('id, role, content, created_at')
    .eq('scan_id', req.params.scanId)
    .eq('user_id', req.user.id)
    .order('created_at', { ascending: true });
  res.json({ messages: data || [] });
});

// ── Streaming chat ─────────────────────────────────────────────
app.post('/api/chat/:scanId/stream', authenticate, async (req, res) => {
  if (!req.user?.id) return res.status(401).json({ error: 'Login required.' });
  const { question } = req.body;
  if (!question?.trim()) return res.status(400).json({ error: 'Question is required.' });

  // Load the scan for context
  const { data: scan } = await supabase
    .from('scans').select('result, title')
    .eq('id', req.params.scanId).eq('user_id', req.user.id).single();
  if (!scan) return res.status(404).json({ error: 'Scan not found.' });

  // Load previous chat messages for this scan (last 10 for context)
  const { data: history } = await supabase
    .from('chat_messages')
    .select('role, content')
    .eq('scan_id', req.params.scanId)
    .eq('user_id', req.user.id)
    .order('created_at', { ascending: true })
    .limit(10);

  const send = initSSE(res);

  try {
    // Save user message
    await supabase.from('chat_messages').insert({
      scan_id: req.params.scanId,
      user_id: req.user.id,
      role:    'user',
      content: question,
    });

    // Build message history for context
    const messages = [
      { role: 'system', content: CHAT_SYSTEM(scan.result) },
      ...(history || []).map(m => ({ role: m.role, content: m.content })),
      { role: 'user', content: question },
    ];

    const stream = await groq.chat.completions.create({
      model: MODELS.primary.id,
      max_tokens: 1024,
      stream: true,
      messages,
    });

    let fullAnswer = '';
    for await (const chunk of stream) {
      const text = chunk.choices[0]?.delta?.content || '';
      if (text) { fullAnswer += text; send({ type: 'chunk', text }); }
    }

    // Save assistant reply
    await supabase.from('chat_messages').insert({
      scan_id: req.params.scanId,
      user_id: req.user.id,
      role:    'assistant',
      content: fullAnswer,
    });

    send({ type: 'done' });
  } catch (err) {
    send({ type: 'error', message: err.message || 'Chat failed.' });
  }
  res.end();
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
  console.log(`   Primary model:   ${MODELS.primary.label}`);
  console.log(`   Secondary model: ${MODELS.secondary.label}\n`);
});
