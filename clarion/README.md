# Clarion — AI Security Intelligence Platform

> **Analyze threats. Map ATT&CK. Remediate instantly. Free forever.**

Clarion is an open-source, AI-powered security log analysis platform. It uses Groq's ultra-fast AI inference to analyze security logs, extract IOCs, map MITRE ATT&CK techniques, and deliver actionable remediation steps — with no subscription required.

---

## Features

| Feature | Description |
|---------|-------------|
| **Live Analysis** | Real-time streaming analysis with terminal output |
| **MITRE ATT&CK** | Full framework mapping with confidence scores |
| **IOC Extraction** | IPs, domains, hashes, files, processes, registry keys |
| **Model Compare** | Side-by-side: Llama 3.3 70B vs Mixtral 8x7B |
| **AI Chat** | Ask follow-up questions about any incident |
| **IOC Pattern Matching** | Flags IOCs seen across multiple scans |
| **Public Sharing** | Shareable read-only report links |
| **PDF Export** | Professional PDF reports via browser print |
| **Scan History** | Search, filter, tag, and organize all analyses |
| **Privacy First** | Raw logs never persisted — only analysis results |

---

## Tech Stack

### Frontend
- **React 18** + **Vite** — Fast development and build
- **Lucide React** — Modern icon library
- **Recharts** — Data visualization
- **Supabase JS** — Auth + real-time
- **Tailwind CSS** — Utility-first styling
- **Inter + JetBrains Mono** — Typography

### Backend
- **Node.js + Express** — REST API
- **Groq SDK** — Llama 3.3 70B + Mixtral 8x7B
- **Supabase** — PostgreSQL + Row-Level Security
- **Helmet + CORS + Rate Limiting** — Security hardening

---

## Quick Start

### 1. Prerequisites
- Node.js 20+
- [Supabase](https://supabase.com) project (free tier works)
- [Groq](https://console.groq.com) API key (free)

### 2. Database Setup
Run `docs/schema.sql` in your Supabase SQL editor to create all tables.

### 3. Backend Setup
```bash
cd backend
cp .env.example .env  # Fill in your keys
npm install
npm start
```

**Backend `.env`:**
```env
PORT=3001
GROQ_API_KEY=your_groq_api_key
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_ROLE_KEY=your_service_role_key
FRONTEND_URL=http://localhost:5173
```

### 4. Frontend Setup
```bash
cd frontend
cp .env.example .env  # Fill in your Supabase public keys
npm install
npm run dev
```

**Frontend `.env`:**
```env
VITE_API_URL=http://localhost:3001
VITE_SUPABASE_URL=https://your-project.supabase.co
VITE_SUPABASE_ANON_KEY=your_anon_key
```

### 5. Open the app
Visit [http://localhost:5173](http://localhost:5173)

---

## Deployment

### Backend → Render
1. Create a new Web Service on [Render](https://render.com)
2. Root directory: `backend/`
3. Build command: `npm install`
4. Start command: `node server.js`
5. Add environment variables

### Frontend → Vercel
1. Import the repo on [Vercel](https://vercel.com)
2. Root directory: `frontend/`
3. Add `VITE_*` environment variables
4. Deploy

---

## Architecture

```
clarion/
├── backend/          # Express API server
│   ├── server.js     # All routes + AI logic
│   └── package.json
├── frontend/         # React SPA
│   ├── src/
│   │   ├── App.jsx   # Complete UI (all pages + components)
│   │   ├── main.jsx
│   │   ├── index.css # Dark theme + animations
│   │   └── lib/
│   │       └── supabase.js
│   └── package.json
└── docs/
    ├── schema.sql    # Supabase database schema
    └── sample-logs.txt
```

---

## License

MIT — Free to use, modify, and distribute.

---

*Built with Groq AI · Powered by Llama 3.3 70B · No subscription required*
