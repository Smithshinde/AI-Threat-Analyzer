# 🛡 AI Threat Analyzer (No Subscription)

AI-powered security log analysis — free to use, no payments, no limits.

**Stack:** React 18 · Node.js/Express · Supabase · Anthropic Claude

---

## Quick Start

### Prerequisites
- Node.js 20+
- Supabase project (supabase.com — free)
- Anthropic API key (console.anthropic.com)

### 1. Install
```bash
cd backend && npm install
cd ../frontend && npm install
```

### 2. Set up Supabase
Run `docs/schema.sql` in Supabase SQL Editor.

### 3. Configure environment
```bash
cp backend/.env.example backend/.env    # fill in your keys
cp frontend/.env.example frontend/.env  # fill in your keys
```

### 4. Run
```bash
# Terminal 1
cd backend && npm run dev

# Terminal 2
cd frontend && npm run dev
```

Open http://localhost:5173

---

## Deployment

- **Backend** → Render: Root=`backend`, Build=`npm install`, Start=`node server.js`
- **Frontend** → Vercel: Root=`frontend`, add VITE_ env vars

---

## Structure
```
ai-threat-analyzer/
├── backend/
│   ├── server.js       # Express API
│   ├── package.json
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── App.jsx     # Full React app
│   │   ├── main.jsx
│   │   ├── index.css
│   │   └── lib/supabase.js
│   ├── index.html
│   ├── vite.config.js
│   ├── tailwind.config.js
│   ├── package.json
│   └── .env.example
└── docs/
    ├── schema.sql
    └── sample-logs.txt
```
