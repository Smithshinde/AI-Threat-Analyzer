import 'dotenv/config';
import express   from 'express';
import cors      from 'cors';
import helmet    from 'helmet';
import rateLimit from 'express-rate-limit';
import multer    from 'multer';
import Groq from 'groq-sdk';
import { createClient } from '@supabase/supabase-js';

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

// Global throttle — prevents abuse, allows generous use
const globalLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
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

// ── File upload config ─────────────────────────────────────────
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB
  fileFilter: (_req, file, cb) => {
    if (!/\.(txt|log|json|csv)$/i.test(file.originalname)) {
      return cb(new Error('Only .txt, .log, .json and .csv files are allowed.'));
    }
    cb(null, true);
  },
});

// ── AI system prompt ───────────────────────────────────────────
const SYSTEM_PROMPT = `You are an elite threat intelligence analyst with deep expertise in:
- MITRE ATT&CK framework v14 (all tactics, techniques, and sub-techniques)
- Incident response, digital forensics, and log analysis
- Malware behavior, lateral movement patterns, and C2 communications
- Network security, endpoint detection, and threat hunting

Always be precise, technical, and actionable in your analysis.
Return only valid JSON — no markdown, no explanation, no preamble.`;

function buildAnalysisPrompt(input) {
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
  "timeline": [
    {
      "time": "<HH:MM:SS or timestamp>",
      "event": "<description>",
      "severity": "<low|medium|high|critical>",
      "tactic": "<MITRE tactic name>"
    }
  ],
  "affectedSystems": [
    {
      "host": "<ip or hostname>",
      "status": "<Compromised|Potentially Compromised|Under Investigation>",
      "risk": <0-100>
    }
  ],
  "iocs": [
    {
      "type": "<IP|Domain|Hash|File|Process|Registry>",
      "value": "<the indicator>",
      "description": "<context and significance>",
      "threat": "<low|medium|high|critical>"
    }
  ],
  "mitreMapping": [
    {
      "tactic": "<MITRE tactic name>",
      "technique": "<T-code e.g. T1078>",
      "name": "<technique name>",
      "confidence": <0-100>
    }
  ],
  "remediation": [
    {
      "priority": <1-N>,
      "action": "<specific actionable step>",
      "category": "<Containment|Eradication|Recovery|Hardening>",
      "urgent": <true|false>
    }
  ]
}`;
}

// Strip prompt-injection patterns before sending to Claude
function sanitizeInput(raw) {
  return raw
    .replace(/<\|.*?\|>/g, '')
    .replace(/\[INST\]|\[\/INST\]/gi, '')
    .replace(/###\s*(?:System|Assistant|Human|User):/gi, '')
    .replace(/^(system|assistant|human|user):\s*/gim, '')
    .substring(0, 10000);
}

// Shared analysis logic used by both routes
async function runAnalysis(input, userId) {
  const sanitized = sanitizeInput(input);

const message = await groq.chat.completions.create({
  model: 'llama-3.3-70b-versatile',
  max_tokens: 4096,
  messages: [
    { role: 'system', content: SYSTEM_PROMPT },
    { role: 'user', content: buildAnalysisPrompt(sanitized) }
  ],
});

const rawText = message.choices[0]?.message?.content || '';
  let result;
  try {
    result = JSON.parse(rawText.replace(/```json\n?|\n?```/g, '').trim());
  } catch {
    throw new Error('AI returned an unexpected format. Please retry.');
  }

  // Persist scan if user is logged in (raw input never stored)
  let scanId = null;
  if (userId) {
    const { data: scan } = await supabase.from('scans').insert({
      user_id:    userId,
      risk_score: result.riskScore,
      severity:   result.severity,
      result,
      input_size: sanitized.length,
      created_at: new Date().toISOString(),
    }).select('id').single();
    scanId = scan?.id;
  }

  return { result, scanId };
}

// ──────────────────────────────────────────────────────────────
// ROUTES
// ──────────────────────────────────────────────────────────────

app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Analyse text input
app.post('/api/analyze', authenticate, async (req, res) => {
  const { input } = req.body;
  if (!input || input.trim().length < 10) {
    return res.status(400).json({ error: 'Input must be at least 10 characters.' });
  }
  try {
    const { result, scanId } = await runAnalysis(input, req.user?.id);
    res.json({ success: true, scanId, result });
  } catch (err) {
    if (err.status === 429) return res.status(429).json({ error: 'AI rate limit reached. Please wait a moment.' });
    console.error('Analysis error:', err.message);
    res.status(500).json({ error: err.message || 'Analysis failed. Please try again.' });
  }
});

// Analyse uploaded file
app.post('/api/analyze/file', authenticate, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded or invalid file type.' });
  const input = req.file.buffer.toString('utf-8');
  if (input.trim().length < 10) return res.status(400).json({ error: 'File is empty or too short.' });
  try {
    const { result, scanId } = await runAnalysis(input, req.user?.id);
    res.json({ success: true, scanId, result });
  } catch (err) {
    console.error('File analysis error:', err.message);
    res.status(500).json({ error: err.message || 'Analysis failed. Please try again.' });
  }
});

// Scan history
app.get('/api/scans', authenticate, async (req, res) => {
  if (!req.user?.id) return res.status(401).json({ error: 'Login required to view history.' });
  const { data, error } = await supabase
    .from('scans')
    .select('id, risk_score, severity, input_size, created_at')
    .eq('user_id', req.user.id)
    .order('created_at', { ascending: false })
    .limit(100);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ scans: data });
});

app.get('/api/scans/:id', authenticate, async (req, res) => {
  if (!req.user?.id) return res.status(401).json({ error: 'Login required.' });
  const { data, error } = await supabase
    .from('scans')
    .select('*')
    .eq('id', req.params.id)
    .eq('user_id', req.user.id)
    .single();
  if (error || !data) return res.status(404).json({ error: 'Scan not found.' });
  res.json({ scan: data });
});

// ── Error handler ──────────────────────────────────────────────
app.use((err, _req, res, _next) => {
  if (err.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ error: 'File too large. Maximum 5 MB.' });
  if (err.message?.includes('Only .txt')) return res.status(400).json({ error: err.message });
  console.error('Unhandled error:', err.message);
  res.status(500).json({ error: 'Internal server error.' });
});

// ── Start ──────────────────────────────────────────────────────
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`\n🛡  AI Threat Analyzer API`);
  console.log(`   Running on http://localhost:${PORT}`);
  console.log(`   Environment: ${process.env.NODE_ENV || 'development'}\n`);
});
