# GRC Platform — Deployment Guide

## Prerequisites

- Node.js >= 20
- Docker + Docker Compose (for containerized deployment)
- Supabase project (free tier sufficient for development)
- PostgreSQL 16 (production)

---

## Quick Start (Local Development)

### 1. Clone and configure

```bash
cd project-free
cp .env.example .env
# Edit .env with your Supabase credentials and JWT secrets
```

### 2. Apply database schema

In your Supabase SQL editor, paste and run `docs/DATABASE_SCHEMA.sql`.

### 3. Start the backend

```bash
cd backend
npm install
npm run dev
# API available at http://localhost:4000
```

### 4. Start the frontend

```bash
cd frontend
npm install
npm run dev
# App available at http://localhost:5173
```

---

## Docker Compose Deployment

```bash
# From project-free/
cp .env.example .env
# Edit .env

docker-compose up -d

# Verify all services are healthy
docker-compose ps
docker-compose logs backend
```

Services:
- Frontend:  http://localhost:5173
- Backend API: http://localhost:4000
- PostgreSQL:  localhost:5432
- Redis:       localhost:6379

---

## Production (Cloud) Deployment

### AWS / GCP / Azure

**Backend (ECS / Cloud Run / App Service):**
```bash
docker build -t grc-backend ./backend
docker tag grc-backend your-registry/grc-backend:latest
docker push your-registry/grc-backend:latest
```

**Frontend (S3 + CloudFront / Cloud Storage + CDN):**
```bash
cd frontend
npm run build
# Upload dist/ to your CDN/bucket
```

### Environment Variables (Production)

| Variable | Description | Required |
|----------|-------------|----------|
| `SUPABASE_URL` | Supabase project URL | ✅ |
| `SUPABASE_SERVICE_ROLE_KEY` | Supabase service role key | ✅ |
| `JWT_SECRET` | 64+ char random secret | ✅ |
| `JWT_REFRESH_SECRET` | Different 64+ char secret | ✅ |
| `CORS_ORIGINS` | Comma-separated allowed origins | ✅ |
| `NODE_ENV` | Set to `production` | ✅ |

---

## Security Checklist for Production

- [ ] Change all default passwords in `.env`
- [ ] Enable HTTPS/TLS on nginx
- [ ] Set `NODE_ENV=production`
- [ ] Configure Supabase Row Level Security (RLS)
- [ ] Enable Supabase email verification
- [ ] Set up automated backups for PostgreSQL
- [ ] Configure log aggregation (CloudWatch, GCP Logging, etc.)
- [ ] Enable rate limiting at the load balancer level
- [ ] Run `npm audit` and fix vulnerabilities
- [ ] Configure WAF rules
- [ ] Enable MFA for all admin accounts

---

## API Endpoint Summary

| Module | Base Path | Key Endpoints |
|--------|-----------|---------------|
| Auth | `/api/v1/auth` | `POST /login`, `POST /refresh`, `POST /mfa/setup` |
| Risks | `/api/v1/risks` | CRUD + `/heatmap` + `/:id/controls` |
| Controls | `/api/v1/controls` | CRUD + `/stats` |
| Compliance | `/api/v1/compliance` | `/dashboard`, `/score`, `/gap-analysis`, `/mappings` |
| Incidents | `/api/v1/incidents` | CRUD + `/:id/transition` + `/:id/timeline` |
| Policies | `/api/v1/policies` | CRUD + `/:id/transition` + `/:id/acknowledge` |
| Evidence | `/api/v1/evidence` | List + Upload (multipart) + Delete |
| Dashboard | `/api/v1/dashboard` | `/executive`, `/ciso` |
| Reports | `/api/v1/reports` | `/board`, `/compliance`, `/risk-trend` |
| Audit | `/api/v1/audit` | `/engagements`, `/findings`, `/logs` |
