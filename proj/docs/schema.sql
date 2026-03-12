-- ============================================================
-- AI Threat Analyzer — Supabase Schema (No Subscription Edition)
-- Run in: Supabase Dashboard → SQL Editor → New Query
-- ============================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ── Scans ─────────────────────────────────────────────────────
-- Stores structured analysis results only.
-- Raw log input is NEVER stored (privacy & storage reasons).
CREATE TABLE scans (
  id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id    UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  risk_score INTEGER CHECK (risk_score BETWEEN 0 AND 100),
  severity   TEXT CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
  result     JSONB NOT NULL,
  input_size INTEGER,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ── Row-Level Security ────────────────────────────────────────
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;

-- Users can only read and write their own scan rows
CREATE POLICY "Users access own scans" ON scans
  FOR ALL USING (auth.uid() = user_id);

-- ── Indexes ───────────────────────────────────────────────────
CREATE INDEX idx_scans_user_created
  ON scans(user_id, created_at DESC);
