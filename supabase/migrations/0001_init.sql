-- HACK THE SOC :: enterprise SOC training platform
-- Initial schema. Run in Supabase SQL editor or via `supabase db push`.
-- All multi-tenant data is keyed by user_id for RLS.

create extension if not exists "pgcrypto";
create extension if not exists "uuid-ossp";

-- =========================================================================
-- 1. USERS / PROFILES
-- =========================================================================
create table if not exists public.profiles (
    id              uuid primary key references auth.users(id) on delete cascade,
    handle          text unique not null,
    display_name    text,
    avatar_url      text,
    role            text not null default 'analyst' check (role in ('analyst','senior_analyst','threat_hunter','admin','instructor')),
    rank            text not null default 'Recruit',
    xp              integer not null default 0,
    level           integer not null default 1,
    streak_days     integer not null default 0,
    last_active_at  timestamptz default now(),
    bio             text,
    onboarded       boolean not null default false,
    created_at      timestamptz not null default now()
);

create index if not exists profiles_xp_idx on public.profiles(xp desc);

-- =========================================================================
-- 2. LEARNING PATHS / MODULES / LESSONS
-- =========================================================================
create table if not exists public.learning_paths (
    id            uuid primary key default gen_random_uuid(),
    slug          text unique not null,
    title         text not null,
    description   text,
    difficulty    text not null check (difficulty in ('beginner','intermediate','advanced','expert')),
    track         text not null check (track in ('soc_analyst','threat_hunter','incident_responder','detection_engineer','purple_team')),
    icon          text,
    cover_url     text,
    estimated_hours integer default 0,
    xp_reward     integer default 0,
    is_published  boolean not null default true,
    created_at    timestamptz not null default now()
);

create table if not exists public.modules (
    id            uuid primary key default gen_random_uuid(),
    path_id       uuid references public.learning_paths(id) on delete cascade,
    slug          text not null,
    title         text not null,
    description   text,
    sort_order    integer not null default 0,
    xp_reward     integer default 0,
    unique (path_id, slug)
);

create table if not exists public.lessons (
    id            uuid primary key default gen_random_uuid(),
    module_id     uuid references public.modules(id) on delete cascade,
    slug          text not null,
    title         text not null,
    content_md    text,
    kind          text not null default 'lesson' check (kind in ('lesson','lab','quiz','simulation','reading')),
    duration_min  integer default 10,
    xp_reward     integer default 0,
    sort_order    integer not null default 0,
    mitre_techniques text[] default '{}',
    unique (module_id, slug)
);

create table if not exists public.lesson_progress (
    user_id       uuid references public.profiles(id) on delete cascade,
    lesson_id     uuid references public.lessons(id) on delete cascade,
    status        text not null default 'in_progress' check (status in ('in_progress','completed','failed')),
    score         integer,
    attempts      integer not null default 0,
    completed_at  timestamptz,
    primary key (user_id, lesson_id)
);

-- =========================================================================
-- 3. SCENARIOS / ATTACK SIMULATIONS
-- =========================================================================
create table if not exists public.scenarios (
    id              uuid primary key default gen_random_uuid(),
    slug            text unique not null,
    title           text not null,
    summary         text not null,
    narrative_md    text,
    difficulty      text not null check (difficulty in ('beginner','intermediate','advanced','expert')),
    threat_actor    text,           -- e.g. APT29, FIN7, LockBit, Insider
    attack_kind     text not null,  -- ransomware, phishing, supply_chain, lateral_movement, exfil, insider, c2
    mitre_tactics   text[] default '{}',
    mitre_techniques text[] default '{}',
    industries      text[] default '{}',
    xp_reward       integer default 250,
    estimated_min   integer default 45,
    cover_url       text,
    is_published    boolean not null default true,
    created_at      timestamptz not null default now()
);

create table if not exists public.scenario_runs (
    id              uuid primary key default gen_random_uuid(),
    scenario_id     uuid references public.scenarios(id) on delete cascade,
    user_id         uuid references public.profiles(id) on delete cascade,
    status          text not null default 'active' check (status in ('active','completed','failed','abandoned')),
    score           integer default 0,
    xp_earned       integer default 0,
    correct_answers integer default 0,
    total_questions integer default 0,
    started_at      timestamptz not null default now(),
    finished_at     timestamptz,
    notes           text
);

create index if not exists scenario_runs_user_idx on public.scenario_runs(user_id, started_at desc);

-- =========================================================================
-- 4. ALERTS / SIEM EVENTS / TELEMETRY
-- =========================================================================
create table if not exists public.alerts (
    id              uuid primary key default gen_random_uuid(),
    run_id          uuid references public.scenario_runs(id) on delete cascade,
    scenario_id     uuid references public.scenarios(id) on delete cascade,
    alert_uid       text not null,                  -- vendor-style id e.g. CRWD-9F3A...
    title           text not null,
    description     text,
    source          text not null,                  -- EDR, SIEM, Firewall, AD, O365, VPN, DNS, Cloud
    vendor          text,                           -- CrowdStrike, Sentinel, Splunk, Palo Alto, Okta...
    severity        text not null check (severity in ('critical','high','medium','low','informational')),
    status          text not null default 'new' check (status in ('new','triaging','investigating','contained','resolved','false_positive','escalated')),
    confidence      integer default 70,             -- 0..100
    risk_score      integer default 50,             -- 0..100
    mitre_tactic    text,
    mitre_technique text,
    hostname        text,
    user_email      text,
    src_ip          inet,
    dst_ip          inet,
    src_country     text,
    dst_country     text,
    process_name    text,
    process_path    text,
    process_cmdline text,
    parent_process  text,
    file_path       text,
    sha256          text,
    url             text,
    domain          text,
    raw             jsonb default '{}'::jsonb,
    detected_at     timestamptz not null default now(),
    assigned_to     uuid references public.profiles(id),
    created_at      timestamptz not null default now()
);

create index if not exists alerts_run_idx on public.alerts(run_id, detected_at desc);
create index if not exists alerts_severity_idx on public.alerts(severity, status);
create index if not exists alerts_mitre_idx on public.alerts(mitre_technique);

create table if not exists public.telemetry_events (
    id              bigserial primary key,
    run_id          uuid references public.scenario_runs(id) on delete cascade,
    alert_id        uuid references public.alerts(id) on delete set null,
    source          text not null,            -- edr, sysmon, o365, ad, fw, vpn, dns, cloudtrail
    event_type      text not null,            -- process_create, file_write, net_conn, login, dns_query...
    ts              timestamptz not null,
    hostname        text,
    user_email      text,
    src_ip          inet,
    dst_ip          inet,
    src_port        integer,
    dst_port        integer,
    protocol        text,
    process_name    text,
    process_pid     integer,
    parent_pid      integer,
    cmdline         text,
    sha256          text,
    file_path       text,
    url             text,
    domain          text,
    http_method     text,
    http_status     integer,
    bytes_in        bigint,
    bytes_out       bigint,
    mitre_technique text,
    severity        text,
    raw             jsonb default '{}'::jsonb
);

create index if not exists telemetry_run_ts_idx on public.telemetry_events(run_id, ts desc);
create index if not exists telemetry_hostname_idx on public.telemetry_events(hostname);
create index if not exists telemetry_source_idx on public.telemetry_events(source, event_type);

-- =========================================================================
-- 5. INVESTIGATIONS / IR / NOTES
-- =========================================================================
create table if not exists public.investigations (
    id              uuid primary key default gen_random_uuid(),
    run_id          uuid references public.scenario_runs(id) on delete cascade,
    user_id         uuid references public.profiles(id) on delete cascade,
    title           text not null,
    summary         text,
    severity        text not null default 'medium',
    status          text not null default 'open' check (status in ('open','in_progress','contained','closed')),
    verdict         text check (verdict in ('true_positive','false_positive','benign','undetermined')),
    iocs            jsonb default '[]'::jsonb,
    affected_assets text[] default '{}',
    timeline        jsonb default '[]'::jsonb,
    created_at      timestamptz not null default now(),
    closed_at       timestamptz
);

create table if not exists public.investigation_notes (
    id              uuid primary key default gen_random_uuid(),
    investigation_id uuid references public.investigations(id) on delete cascade,
    user_id         uuid references public.profiles(id) on delete cascade,
    body_md         text not null,
    kind            text default 'note' check (kind in ('note','finding','action','question','hypothesis')),
    created_at      timestamptz not null default now()
);

-- =========================================================================
-- 6. THREAT HUNTING
-- =========================================================================
create table if not exists public.hunts (
    id              uuid primary key default gen_random_uuid(),
    user_id         uuid references public.profiles(id) on delete cascade,
    title           text not null,
    hypothesis      text not null,
    query           text not null,                -- KQL/SPL-like
    query_lang      text not null default 'kql',  -- kql, spl, sigma, eql
    mitre_techniques text[] default '{}',
    status          text not null default 'draft' check (status in ('draft','running','complete','archived')),
    findings        jsonb default '[]'::jsonb,
    created_at      timestamptz not null default now()
);

-- =========================================================================
-- 7. DETECTION ENGINEERING
-- =========================================================================
create table if not exists public.detections (
    id              uuid primary key default gen_random_uuid(),
    user_id         uuid references public.profiles(id) on delete cascade,
    name            text not null,
    description     text,
    rule_lang       text not null default 'sigma' check (rule_lang in ('sigma','kql','spl','eql','yara')),
    rule_yaml       text not null,
    severity        text not null default 'medium',
    mitre_techniques text[] default '{}',
    status          text not null default 'draft' check (status in ('draft','testing','validated','deployed','retired')),
    true_positives  integer default 0,
    false_positives integer default 0,
    last_tested_at  timestamptz,
    created_at      timestamptz not null default now()
);

-- =========================================================================
-- 8. GAMIFICATION (XP, BADGES, ACHIEVEMENTS)
-- =========================================================================
create table if not exists public.badges (
    id            uuid primary key default gen_random_uuid(),
    slug          text unique not null,
    name          text not null,
    description   text,
    icon          text,
    tier          text not null default 'bronze' check (tier in ('bronze','silver','gold','platinum','legendary')),
    xp_reward     integer default 100
);

create table if not exists public.user_badges (
    user_id       uuid references public.profiles(id) on delete cascade,
    badge_id      uuid references public.badges(id) on delete cascade,
    awarded_at    timestamptz not null default now(),
    primary key (user_id, badge_id)
);

create table if not exists public.xp_events (
    id            bigserial primary key,
    user_id       uuid references public.profiles(id) on delete cascade,
    amount        integer not null,
    reason        text not null,
    ref_table     text,
    ref_id        uuid,
    created_at    timestamptz not null default now()
);

-- =========================================================================
-- 9. AI ASSISTANT CONVERSATIONS
-- =========================================================================
create table if not exists public.ai_conversations (
    id            uuid primary key default gen_random_uuid(),
    user_id       uuid references public.profiles(id) on delete cascade,
    investigation_id uuid references public.investigations(id) on delete cascade,
    title         text,
    created_at    timestamptz not null default now()
);

create table if not exists public.ai_messages (
    id            bigserial primary key,
    conversation_id uuid references public.ai_conversations(id) on delete cascade,
    role          text not null check (role in ('user','assistant','system','tool')),
    content       text not null,
    tokens_in     integer,
    tokens_out    integer,
    created_at    timestamptz not null default now()
);

-- =========================================================================
-- 10. ADMIN AUDIT
-- =========================================================================
create table if not exists public.audit_log (
    id            bigserial primary key,
    actor_id      uuid references public.profiles(id) on delete set null,
    action        text not null,
    target_table  text,
    target_id     uuid,
    metadata      jsonb default '{}'::jsonb,
    created_at    timestamptz not null default now()
);

-- =========================================================================
-- 11. LEADERBOARD VIEW
-- =========================================================================
create or replace view public.leaderboard as
select
    p.id,
    p.handle,
    p.display_name,
    p.avatar_url,
    p.rank,
    p.level,
    p.xp,
    p.streak_days,
    coalesce(b.badge_count, 0) as badge_count,
    coalesce(r.completed_runs, 0) as scenarios_completed,
    rank() over (order by p.xp desc) as global_rank
from public.profiles p
left join (
    select user_id, count(*)::int as badge_count
    from public.user_badges group by user_id
) b on b.user_id = p.id
left join (
    select user_id, count(*)::int as completed_runs
    from public.scenario_runs where status = 'completed'
    group by user_id
) r on r.user_id = p.id;

-- =========================================================================
-- 12. ROW LEVEL SECURITY
-- =========================================================================
alter table public.profiles            enable row level security;
alter table public.lesson_progress     enable row level security;
alter table public.scenario_runs       enable row level security;
alter table public.alerts              enable row level security;
alter table public.telemetry_events    enable row level security;
alter table public.investigations      enable row level security;
alter table public.investigation_notes enable row level security;
alter table public.hunts               enable row level security;
alter table public.detections          enable row level security;
alter table public.user_badges         enable row level security;
alter table public.xp_events           enable row level security;
alter table public.ai_conversations    enable row level security;
alter table public.ai_messages         enable row level security;

-- profiles: users can read all, edit only themselves
drop policy if exists "profiles read"    on public.profiles;
drop policy if exists "profiles update"  on public.profiles;
create policy "profiles read"   on public.profiles for select using (true);
create policy "profiles update" on public.profiles for update using (auth.uid() = id);

-- own-data policies for the rest
do $$
declare t text;
begin
    for t in select unnest(array[
        'lesson_progress','scenario_runs','alerts','telemetry_events',
        'investigations','investigation_notes','hunts','detections',
        'user_badges','xp_events','ai_conversations','ai_messages'
    ]) loop
        execute format('drop policy if exists "%1$s own" on public.%1$s', t);
        if t in ('alerts','telemetry_events') then
            -- Reach user_id through scenario_runs.run_id
            execute format($p$
                create policy "%1$s own" on public.%1$s
                for all using (
                    run_id in (select id from public.scenario_runs where user_id = auth.uid())
                ) with check (
                    run_id in (select id from public.scenario_runs where user_id = auth.uid())
                );$p$, t);
        elsif t = 'investigation_notes' then
            execute format($p$
                create policy "%1$s own" on public.%1$s
                for all using (user_id = auth.uid())
                with check (user_id = auth.uid());$p$, t);
        elsif t = 'ai_messages' then
            execute format($p$
                create policy "%1$s own" on public.%1$s
                for all using (
                    conversation_id in (select id from public.ai_conversations where user_id = auth.uid())
                );$p$, t);
        else
            execute format($p$
                create policy "%1$s own" on public.%1$s
                for all using (user_id = auth.uid())
                with check (user_id = auth.uid());$p$, t);
        end if;
    end loop;
end$$;

-- =========================================================================
-- 13. TRIGGERS
-- =========================================================================
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
    insert into public.profiles (id, handle, display_name)
    values (
        new.id,
        coalesce(split_part(new.email, '@', 1), 'analyst-' || substr(new.id::text, 1, 6)),
        coalesce(new.raw_user_meta_data->>'display_name', split_part(new.email, '@', 1))
    )
    on conflict (id) do nothing;
    return new;
end$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
    for each row execute function public.handle_new_user();

create or replace function public.recompute_level() returns trigger
language plpgsql as $$
begin
    -- Level curve: every 1000 XP = +1 level, soft cap at 99
    new.level := least(99, 1 + floor(new.xp / 1000.0)::int);
    new.rank := case
        when new.xp <  1000 then 'Recruit'
        when new.xp <  3000 then 'Tier 1 Analyst'
        when new.xp <  7000 then 'Tier 2 Analyst'
        when new.xp < 15000 then 'Tier 3 Analyst'
        when new.xp < 30000 then 'Threat Hunter'
        when new.xp < 60000 then 'IR Lead'
        else                     'SOC Architect'
    end;
    return new;
end$$;

drop trigger if exists trg_profiles_level on public.profiles;
create trigger trg_profiles_level before update of xp on public.profiles
    for each row execute function public.recompute_level();
