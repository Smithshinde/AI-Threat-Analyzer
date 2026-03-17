import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import { globalLimiter } from './src/middleware/rateLimiter.js';
import { errorHandler, notFoundHandler } from './src/middleware/errorHandler.js';
import { auditMiddleware } from './src/middleware/auditLog.js';
import { healthCheck } from './src/config/database.js';
import logger from './src/utils/logger.js';

// Routes
import authRoutes       from './src/modules/auth/auth.routes.js';
import riskRoutes       from './src/modules/risks/risks.routes.js';
import controlRoutes    from './src/modules/controls/controls.routes.js';
import complianceRoutes from './src/modules/compliance/compliance.routes.js';
import policyRoutes     from './src/modules/policies/policies.routes.js';
import incidentRoutes   from './src/modules/incidents/incidents.routes.js';
import evidenceRoutes   from './src/modules/evidence/evidence.routes.js';
import auditRoutes      from './src/modules/audit/audit.routes.js';
import dashboardRoutes  from './src/modules/dashboard/dashboard.routes.js';
import reportRoutes     from './src/modules/reports/reports.routes.js';

const app  = express();
const PORT = process.env.PORT || 4000;

// ── Security headers ──────────────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'"],
      styleSrc:   ["'self'", "'unsafe-inline'"],
      imgSrc:     ["'self'", 'data:', 'blob:'],
    },
  },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
}));

// ── CORS ──────────────────────────────────────────────────────────────────────
const ALLOWED_ORIGINS = (process.env.CORS_ORIGINS || 'http://localhost:5173').split(',');
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    cb(new Error(`CORS: origin ${origin} not allowed`));
  },
  credentials: true,
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization'],
}));

// ── Body parsing ──────────────────────────────────────────────────────────────
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ── Global rate limit ─────────────────────────────────────────────────────────
app.use(globalLimiter);

// ── Request logging ───────────────────────────────────────────────────────────
app.use((req, _res, next) => {
  logger.info(`${req.method} ${req.path}`, { ip: req.ip, ua: req.headers['user-agent']?.slice(0, 80) });
  next();
});

// ── Audit middleware ───────────────────────────────────────────────────────────
app.use(auditMiddleware);

// ── Health check ──────────────────────────────────────────────────────────────
app.get('/health', async (_req, res) => {
  try {
    await healthCheck();
    res.json({ status: 'healthy', ts: new Date().toISOString(), version: process.env.npm_package_version || '1.0.0' });
  } catch {
    res.status(503).json({ status: 'unhealthy' });
  }
});

// ── API routes ────────────────────────────────────────────────────────────────
const API = '/api/v1';
app.use(`${API}/auth`,       authRoutes);
app.use(`${API}/risks`,      riskRoutes);
app.use(`${API}/controls`,   controlRoutes);
app.use(`${API}/compliance`, complianceRoutes);
app.use(`${API}/policies`,   policyRoutes);
app.use(`${API}/incidents`,  incidentRoutes);
app.use(`${API}/evidence`,   evidenceRoutes);
app.use(`${API}/audit`,      auditRoutes);
app.use(`${API}/dashboard`,  dashboardRoutes);
app.use(`${API}/reports`,    reportRoutes);

// ── Error handling ────────────────────────────────────────────────────────────
app.use(notFoundHandler);
app.use(errorHandler);

// ── Start ──────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  logger.info(`GRC Platform API running on port ${PORT}`, { env: process.env.NODE_ENV || 'development' });
});

// Graceful shutdown
process.on('SIGTERM', () => { logger.info('SIGTERM received — shutting down'); process.exit(0); });
process.on('SIGINT',  () => { logger.info('SIGINT received — shutting down');  process.exit(0); });

export default app;
