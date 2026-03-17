-- Clarion — AI Security Intelligence Platform
-- Database Schema for Supabase PostgreSQL
-- Run this in the Supabase SQL editor to set up all tables

-- ── Enable UUID extension ────────────────────────────────────────
create extension if not exists "uuid-ossp";

-- ── Scans table ──────────────────────────────────────────────────
create table if not exists scans (
  id          uuid primary key default uuid_generate_v4(),
  user_id     uuid references auth.users(id) on delete cascade not null,
  risk_score  integer not null check (risk_score between 0 and 100),
  severity    text not null check (severity in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
  title       text,
  result      jsonb not null,
  input_size  integer not null default 0,
  model       text not null default 'llama-3.3-70b-versatile',
  tags        text[] not null default '{}',
  is_public   boolean not null default false,
  created_at  timestamptz not null default now()
);

-- Index for user's scans sorted by date (most common query)
create index if not exists scans_user_date_idx on scans(user_id, created_at desc);
-- Index for public scans lookup
create index if not exists scans_public_idx on scans(id) where is_public = true;

-- Row-Level Security: users can only access their own scans
alter table scans enable row level security;

create policy "Users can read own scans"
  on scans for select
  using (auth.uid() = user_id);

create policy "Users can insert own scans"
  on scans for insert
  with check (auth.uid() = user_id);

create policy "Users can update own scans"
  on scans for update
  using (auth.uid() = user_id);

create policy "Users can delete own scans"
  on scans for delete
  using (auth.uid() = user_id);

-- ── IOC matches table ────────────────────────────────────────────
-- Tracks IOC occurrences across multiple scans for pattern detection
create table if not exists ioc_matches (
  id          uuid primary key default uuid_generate_v4(),
  user_id     uuid references auth.users(id) on delete cascade not null,
  ioc_value   text not null,
  ioc_type    text not null,
  scan_ids    uuid[] not null default '{}',
  hit_count   integer not null default 1,
  first_seen  timestamptz not null default now(),
  last_seen   timestamptz not null default now()
);

-- Index for looking up IOCs by user + value
create unique index if not exists ioc_matches_user_value_idx on ioc_matches(user_id, ioc_value);
create index if not exists ioc_matches_user_hits_idx on ioc_matches(user_id, hit_count desc);

-- Row-Level Security
alter table ioc_matches enable row level security;

create policy "Users can read own IOC matches"
  on ioc_matches for select
  using (auth.uid() = user_id);

create policy "Users can insert own IOC matches"
  on ioc_matches for insert
  with check (auth.uid() = user_id);

create policy "Users can update own IOC matches"
  on ioc_matches for update
  using (auth.uid() = user_id);

-- ── Chat messages table ──────────────────────────────────────────
create table if not exists chat_messages (
  id         uuid primary key default uuid_generate_v4(),
  scan_id    uuid references scans(id) on delete cascade not null,
  user_id    uuid references auth.users(id) on delete cascade not null,
  role       text not null check (role in ('user', 'assistant')),
  content    text not null,
  created_at timestamptz not null default now()
);

-- Index for chat history retrieval
create index if not exists chat_messages_scan_idx on chat_messages(scan_id, created_at asc);

-- Row-Level Security
alter table chat_messages enable row level security;

create policy "Users can read own chat messages"
  on chat_messages for select
  using (auth.uid() = user_id);

create policy "Users can insert own chat messages"
  on chat_messages for insert
  with check (auth.uid() = user_id);
