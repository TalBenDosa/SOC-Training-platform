-- HACK THE SOC :: 0002 — app-progress tables aligned to the SHIPPED product
-- ---------------------------------------------------------------------------
-- The original 0001_init.sql was scaffolded speculatively and drifted from how
-- the app actually works today. The live product is Rooms + Dashboard sessions +
-- Scenario history + streaks, currently persisted in localStorage. This migration
-- adds tables that map 1:1 to src/lib/storage/progress.ts (the facade) and the
-- LEARNER_KEYS in src/lib/storage/keys.ts, so Phase 1 is a direct swap:
-- each facade function becomes one query against the table noted below.
--
-- RLS: every row is owned by a user; a user can only see/modify their own rows.
-- Run in the Supabase SQL editor or via `supabase db push` AFTER 0001.

create extension if not exists "pgcrypto";

-- =========================================================================
-- Per-user misc progress  →  LEARNER_KEYS.clearedCompanies + streakFreezes
-- (total XP already lives on profiles.xp from 0001; keep that as the source
--  of truth for getTotalXp()/addTotalXp().)
-- =========================================================================
create table if not exists public.user_progress (
    user_id            uuid primary key references auth.users(id) on delete cascade,
    cleared_companies  jsonb  not null default '[]'::jsonb,   -- string[] of company ids
    streak_freezes     jsonb  not null default '[]'::jsonb,   -- ISO date[]
    last_session       jsonb,                                  -- LEARNER_KEYS.lastSession
    updated_at         timestamptz not null default now()
);

-- =========================================================================
-- Room progress  →  LEARNER_KEYS.roomProgress (Map<roomId, RoomProgressEntry>)
-- One row per (user, room). Mirrors RoomProgressEntry in RoomClient.tsx.
-- =========================================================================
create table if not exists public.room_progress (
    user_id            uuid not null references auth.users(id) on delete cascade,
    room_id            text not null,
    completed_task_ids jsonb   not null default '[]'::jsonb,
    xp_earned          integer not null default 0,
    per_task_xp        jsonb   not null default '{}'::jsonb,   -- Record<taskId, xp>
    telemetry          jsonb   not null default '[]'::jsonb,   -- TaskTelemetryEntry[]
    completed_at       timestamptz,                             -- null = in progress / not yet passed
    updated_at         timestamptz not null default now(),
    primary key (user_id, room_id)
);
create index if not exists room_progress_user_idx on public.room_progress(user_id);

-- =========================================================================
-- Dashboard sessions  →  LEARNER_KEYS.dashboardSessions (DashboardSessionRecord[])
-- Mirrors DashboardSessionRecord in useLiveEvents.ts (post-classify-cleanup shape).
-- =========================================================================
create table if not exists public.dashboard_sessions (
    id                       uuid primary key default gen_random_uuid(),
    user_id                  uuid not null references auth.users(id) on delete cascade,
    played_at                timestamptz not null default now(),
    xp_earned                integer not null default 0,
    detect_rate              integer not null default 0,       -- caught / presented, %
    fn_count                 integer not null default 0,
    avg_catch_ms             integer,
    attacks_caught_count     integer not null default 0,
    attacks_presented_count  integer not null default 0,
    events_opened_count      integer not null default 0,
    duration_ms              integer not null default 0
);
create index if not exists dashboard_sessions_user_idx on public.dashboard_sessions(user_id, played_at desc);

-- =========================================================================
-- Scenario history  →  LEARNER_KEYS.scenarioHistory (ScenarioRecord[])
-- Mirrors ScenarioRecord in progress.ts / ScenarioClient.tsx.
-- =========================================================================
create table if not exists public.scenario_history (
    id           uuid primary key default gen_random_uuid(),
    user_id      uuid not null references auth.users(id) on delete cascade,
    slug         text not null,
    title        text not null,
    score        integer not null default 0,
    xp_earned    integer not null default 0,
    time_taken   integer not null default 0,   -- seconds
    completed_at timestamptz not null default now()
);
create index if not exists scenario_history_user_idx on public.scenario_history(user_id, completed_at desc);

-- =========================================================================
-- AI usage metering  →  caps CRITICAL-1 (financial DoS) per plan (Phase 2)
-- =========================================================================
create table if not exists public.ai_usage (
    id           uuid primary key default gen_random_uuid(),
    user_id      uuid references auth.users(id) on delete set null,
    route        text not null,                 -- e.g. /api/scenarios/generate
    provider     text not null,                 -- anthropic | openai
    model        text,
    input_tokens integer,
    output_tokens integer,
    cost_usd     numeric(10,4),
    created_at   timestamptz not null default now()
);
create index if not exists ai_usage_user_time_idx on public.ai_usage(user_id, created_at desc);

-- =========================================================================
-- RLS — owner-only access on every per-user table
-- =========================================================================
alter table public.user_progress      enable row level security;
alter table public.room_progress      enable row level security;
alter table public.dashboard_sessions enable row level security;
alter table public.scenario_history   enable row level security;
alter table public.ai_usage           enable row level security;

do $$
declare t text;
begin
  foreach t in array array[
    'user_progress','room_progress','dashboard_sessions','scenario_history','ai_usage'
  ]
  loop
    execute format($f$
      drop policy if exists "%1$s own select" on public.%1$s;
      create policy "%1$s own select" on public.%1$s for select using (auth.uid() = user_id);
      drop policy if exists "%1$s own write" on public.%1$s;
      create policy "%1$s own write" on public.%1$s for all using (auth.uid() = user_id) with check (auth.uid() = user_id);
    $f$, t);
  end loop;
end $$;

-- Keep updated_at fresh on the mutable per-user tables.
create or replace function public.touch_updated_at() returns trigger as $$
begin new.updated_at = now(); return new; end;
$$ language plpgsql;

drop trigger if exists user_progress_touch on public.user_progress;
create trigger user_progress_touch before update on public.user_progress
  for each row execute function public.touch_updated_at();

drop trigger if exists room_progress_touch on public.room_progress;
create trigger room_progress_touch before update on public.room_progress
  for each row execute function public.touch_updated_at();
