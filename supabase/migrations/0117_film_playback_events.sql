-- HACK THE SOC :: 0117 — room-film playback events
-- ---------------------------------------------------------------------------
-- Learners reported that room story films stall (feedback 2026-11-21). To see how often, for
-- whom and on which films, the film player (src/components/operation/StoryPlayer.tsx) sends a
-- small event when a film starts, stalls, recovers, is retried, ends, is skipped or fails.
--
-- Written ONLY by the server (POST /api/media/film-event, which validates and caps every field
-- and rate-limits per learner); signed-in learners only. Nobody reads it through the API: RLS is
-- on with no policies, and only the service role (the platform owner's SQL Editor) queries it.
--
-- Org isolation: org_id references organizations with ON DELETE CASCADE, so purge_org removes
-- these rows too; a user deletion cascades from auth.users.
--
-- NON-DESTRUCTIVE: a new, empty table. Idempotent.

create table if not exists public.film_playback_events (
  id            bigserial primary key,
  user_id       uuid not null references auth.users(id) on delete cascade,
  org_id        uuid references public.organizations(id) on delete cascade,
  room_id       text check (room_id is null or char_length(room_id) between 1 and 120),
  clip_key      text check (clip_key is null or char_length(clip_key) between 1 and 60),
  src_path      text not null check (char_length(src_path) between 1 and 300),
  kind          text not null check (kind in ('start', 'stall', 'recovered', 'retry', 'continue', 'error', 'ended', 'skipped')),
  wait_ms       integer check (wait_ms is null or (wait_ms >= 0 and wait_ms <= 3600000)),
  position_s    real check (position_s is null or (position_s >= 0 and position_s <= 86400)),
  duration_s    real check (duration_s is null or (duration_s >= 0 and duration_s <= 86400)),
  net_type      text check (net_type is null or char_length(net_type) <= 16),
  downlink_mbps real check (downlink_mbps is null or (downlink_mbps >= 0 and downlink_mbps <= 100000)),
  created_at    timestamptz not null default now()
);
create index if not exists film_playback_events_created_idx on public.film_playback_events (created_at desc);
create index if not exists film_playback_events_user_idx on public.film_playback_events (user_id, created_at desc);
create index if not exists film_playback_events_src_idx on public.film_playback_events (src_path, kind);

alter table public.film_playback_events enable row level security;
revoke all on public.film_playback_events from anon, authenticated;
grant select, insert on public.film_playback_events to service_role;
grant usage, select on sequence public.film_playback_events_id_seq to service_role;
