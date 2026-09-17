-- HACK THE SOC :: 0049 — Team SOC (multiplayer) foundations — Phase 0.1
-- ===========================================================================
-- The append-only spine for the team-training feature (docs/SPEC-team-soc-
-- multiplayer.md §8.4, §13). Creates the five core tables + the membership /
-- staff / realtime-topic helper functions + RLS. ADDITIVE and idempotent — it
-- touches nothing the single-player app uses.
--
-- Model (one org's instructor runs a shared incident room):
--   team_sessions          one exercise (company + scenario + difficulty)
--   team_session_members   who is in it, their role, and lobby ready-state
--   session_events         APPEND-ONLY action log — the single source of truth
--                          (feed events, clicks, escalations, reports, grades,
--                          the lobby ready-check). Replay + AAR derive from it.
--   session_state          projection of the current case/escalation state
--   session_injects        the MSEL — scheduled/adaptive injects; STAFF-ONLY
--                          readable (they carry expected_action = spoilers).
--
-- Writes to the log/state/injects go through a server RPC with the service role
-- (added in 0.2), which bypasses RLS. The policies here govern what a signed-in
-- CLIENT may read/do directly: members read their session; staff manage it;
-- students can never read injects. The realtime.messages policy lives in 0050.
--
-- NOTE: tables are created BEFORE the SQL helper functions that reference them —
-- a `language sql` body is validated at creation time, so the order matters.
-- ===========================================================================

-- ── 1. team_sessions ────────────────────────────────────────────────────────
create table if not exists public.team_sessions (
  id          uuid primary key default gen_random_uuid(),
  org_id      uuid not null references public.organizations(id) on delete cascade,
  created_by  uuid references auth.users(id) on delete set null,
  company_id  text not null,
  scenario_id text,
  seed        text not null default gen_random_uuid()::text,
  format      text not null default 'team_shift'
              check (format in ('team_shift','handover','vs','rotation')),
  difficulty  text not null default 'medium'
              check (difficulty in ('easy','medium','hard')),
  max_size    integer not null default 6,
  status      text not null default 'lobby'
              check (status in ('lobby','running','paused','ended','debriefed')),
  config      jsonb not null default '{}'::jsonb,
  started_at  timestamptz,
  ended_at    timestamptz,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);
create index if not exists team_sessions_org_idx        on public.team_sessions (org_id);
create index if not exists team_sessions_org_status_idx  on public.team_sessions (org_id, status);

drop trigger if exists team_sessions_touch on public.team_sessions;
create trigger team_sessions_touch before update on public.team_sessions
  for each row execute function public.touch_updated_at();

-- ── 2. team_session_members (roster + lobby ready-state §13.11) ──────────────
create table if not exists public.team_session_members (
  session_id         uuid not null references public.team_sessions(id) on delete cascade,
  user_id            uuid not null references auth.users(id) on delete cascade,
  role               text not null default 'observer'
                     check (role in ('t1','t2','t3','lead','de','ti','mgr','instructor','observer')),
  status             text not null default 'invited'
                     check (status in ('invited','ready','active','left')),
  invited_by         uuid references auth.users(id) on delete set null,
  invited_at         timestamptz not null default now(),
  ready_at           timestamptz,           -- set when the member clicks "I'm ready"
  confirmed_entry_at timestamptz,           -- ROE acknowledgement (folded into ready)
  primary key (session_id, user_id)
);
create index if not exists tsm_user_idx           on public.team_session_members (user_id);
create index if not exists tsm_session_status_idx on public.team_session_members (session_id, status);

-- ── 3. session_events (APPEND-ONLY — source of truth) ───────────────────────
create table if not exists public.session_events (
  position        bigserial primary key,               -- global insert order
  session_id      uuid not null references public.team_sessions(id) on delete cascade,
  seq             bigint not null,                      -- per-session sequence (RPC-assigned)
  actor_id        uuid references auth.users(id) on delete set null,  -- null = system/AI
  role            text,
  type            text not null,                        -- e.g. feed.event, event.opened, escalation.requested
  payload         jsonb not null default '{}'::jsonb,
  occurred_at     timestamptz not null default now(),
  idempotency_key text,
  unique (session_id, seq),                             -- optimistic-concurrency lock
  unique (session_id, actor_id, idempotency_key)        -- de-dupe client retries
);
create index if not exists session_events_session_seq_idx  on public.session_events (session_id, seq);
create index if not exists session_events_session_type_idx on public.session_events (session_id, type);

-- ── 4. session_state (projection rebuilt from the event log) ────────────────
create table if not exists public.session_state (
  session_id   uuid primary key references public.team_sessions(id) on delete cascade,
  seq          bigint not null default 0,
  cases        jsonb not null default '[]'::jsonb,
  escalations  jsonb not null default '[]'::jsonb,
  containment  jsonb not null default '{}'::jsonb,
  milestones   jsonb not null default '{}'::jsonb,
  updated_at   timestamptz not null default now()
);

-- ── 5. session_injects (the MSEL — STAFF-ONLY readable) ─────────────────────
create table if not exists public.session_injects (
  id              uuid primary key default gen_random_uuid(),
  session_id      uuid not null references public.team_sessions(id) on delete cascade,
  due_offset_ms   bigint not null default 0,
  trigger         jsonb not null default '{}'::jsonb,   -- {kind:'at_time'|'on_milestone'|'on_action'|'manual', ...}
  to_roles        text[] not null default '{}',
  persona         text,
  channel         text,
  body            jsonb not null default '{}'::jsonb,
  expected_action jsonb,                                 -- SPOILER — never sent to students
  status          text not null default 'pending'
                  check (status in ('pending','fired','skipped')),
  fired_seq       bigint,
  created_at      timestamptz not null default now()
);
create index if not exists session_injects_due_idx on public.session_injects (session_id, status, due_offset_ms);

-- ── Helpers (created AFTER the tables they read; SECURITY DEFINER so they can
--    read membership without tripping the tables' own RLS — no policy recursion) ─
create or replace function public.is_team_member(p_session uuid, p_user uuid)
  returns boolean language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from public.team_session_members m
    where m.session_id = p_session and m.user_id = p_user
  )
$$;

-- Caller is org_admin/instructor of the org that owns p_session.
create or replace function public.is_session_staff(p_session uuid)
  returns boolean language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from public.team_sessions s
    where s.id = p_session
      and s.org_id = public.current_org()
      and public.current_org_role() in ('org_admin','instructor')
  )
$$;

-- Parse a realtime topic "session:<uuid>" → uuid, or NULL if it isn't one.
-- Used by the 0050 realtime.messages policy; NULL safely denies access.
create or replace function public.team_topic_session(p_topic text)
  returns uuid language plpgsql immutable set search_path = public as $$
begin
  if p_topic is null or p_topic !~ '^session:[0-9a-fA-F-]{36}$' then
    return null;
  end if;
  return substring(p_topic from 9)::uuid;
exception when others then
  return null;
end $$;

grant execute on function public.is_team_member(uuid, uuid)   to authenticated;
grant execute on function public.is_session_staff(uuid)       to authenticated;
grant execute on function public.team_topic_session(text)     to authenticated;

-- ── RLS ──────────────────────────────────────────────────────────────────────
alter table public.team_sessions        enable row level security;
alter table public.team_session_members enable row level security;
alter table public.session_events       enable row level security;
alter table public.session_state        enable row level security;
alter table public.session_injects      enable row level security;

-- team_sessions: members read their own; staff read + manage their org's.
drop policy if exists team_sessions_read on public.team_sessions;
create policy team_sessions_read on public.team_sessions for select to authenticated
  using (public.is_team_member(id, auth.uid()) or (org_id = public.current_org()
         and public.current_org_role() in ('org_admin','instructor')));
drop policy if exists team_sessions_write on public.team_sessions;
create policy team_sessions_write on public.team_sessions for all to authenticated
  using      (org_id = public.current_org() and public.current_org_role() in ('org_admin','instructor'))
  with check (org_id = public.current_org() and public.current_org_role() in ('org_admin','instructor'));

-- team_session_members: members see the roster of their session; staff manage it.
drop policy if exists tsm_read on public.team_session_members;
create policy tsm_read on public.team_session_members for select to authenticated
  using (public.is_team_member(session_id, auth.uid()) or public.is_session_staff(session_id));
drop policy if exists tsm_write on public.team_session_members;
create policy tsm_write on public.team_session_members for all to authenticated
  using (public.is_session_staff(session_id))
  with check (public.is_session_staff(session_id));

-- session_events: members + staff READ; writes are service-role only (append-only via RPC).
drop policy if exists session_events_read on public.session_events;
create policy session_events_read on public.session_events for select to authenticated
  using (public.is_team_member(session_id, auth.uid()) or public.is_session_staff(session_id));

-- session_state: members + staff READ; writes service-role only.
drop policy if exists session_state_read on public.session_state;
create policy session_state_read on public.session_state for select to authenticated
  using (public.is_team_member(session_id, auth.uid()) or public.is_session_staff(session_id));

-- session_injects: STAFF ONLY read (spoilers); writes service-role only.
drop policy if exists session_injects_staff_read on public.session_injects;
create policy session_injects_staff_read on public.session_injects for select to authenticated
  using (public.is_session_staff(session_id));

-- ── Grants (RLS still gates every row) ───────────────────────────────────────
revoke all on public.team_sessions, public.team_session_members, public.session_events,
              public.session_state, public.session_injects from anon;
grant select, insert, update, delete on public.team_sessions        to authenticated;
grant select, insert, update, delete on public.team_session_members to authenticated;
grant select on public.session_events to authenticated;   -- inserts via service role only
grant select on public.session_state  to authenticated;   -- writes  via service role only
grant select on public.session_injects to authenticated;  -- writes  via service role only
grant usage, select on sequence public.session_events_position_seq to authenticated;

comment on table public.session_events is
  'Append-only action log for a team session — the single source of truth. Clicks (event.opened), escalations, reports, lobby ready-check, grades. Replay/AAR derive from it. Client-readable by members/staff; writes only via the server RPC (service role).';
comment on table public.session_injects is
  'The MSEL. STAFF-ONLY readable — expected_action carries spoilers a student must never see; fired injects reach students only as session_events.';
