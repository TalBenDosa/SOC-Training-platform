-- HACK THE SOC :: 0070 — standalone quizzes count toward the overall score
-- ---------------------------------------------------------------------------
-- User report (2026-09-24): "When finishing a quiz (at the quiz section), you
-- don't get the points to your overall score."
--
-- ROOT CAUSE: profiles.xp (the overall score / rank / leaderboard) is
-- server-authoritative — recompute_user_xp() sums xp_earned from room_progress +
-- scenario_history only (0035). The quiz page computed "+N XP earned" for the
-- results screen but never recorded a completion anywhere, so it could never
-- reach profiles.xp.
--
-- FIX: a per-user, per-quiz BEST-score record (quiz_progress) that feeds the
-- recompute. Only the BEST attempt counts (retries can't farm XP). Rows are
-- written ONLY server-side by POST /api/quizzes/[slug]/finish, which re-grades
-- the answers against the key — clients get SELECT on their own rows and no
-- write grants, so xp_earned can't be forged from the browser (the residual gap
-- 0025 documents for the client-written completion tables does not apply here).
--
-- NON-DESTRUCTIVE: the table starts empty, so every profiles.xp is unchanged
-- the instant this runs; no xp_offset re-seed is needed.
-- Idempotent.

-- ── 1. Table ─────────────────────────────────────────────────────────────────
create table if not exists public.quiz_progress (
    user_id            uuid    not null references auth.users(id) on delete cascade,
    quiz_slug          text    not null check (char_length(quiz_slug) between 1 and 200),
    org_id             uuid,
    xp_earned          integer not null default 0 check (xp_earned >= 0 and xp_earned <= 1000),  -- BEST attempt
    best_score_pct     integer not null default 0 check (best_score_pct between 0 and 100),
    passed             boolean not null default false,  -- ever scored >= 70%
    attempts           integer not null default 0 check (attempts >= 0),
    first_completed_at timestamptz not null default now(),
    last_completed_at  timestamptz not null default now(),
    primary key (user_id, quiz_slug)
);
create index if not exists quiz_progress_user_idx on public.quiz_progress(user_id);

-- ── 2. RLS: read your own rows; no client writes at all ──────────────────────
alter table public.quiz_progress enable row level security;
drop policy if exists quiz_progress_read_own on public.quiz_progress;
create policy quiz_progress_read_own on public.quiz_progress
  for select to authenticated
  using (user_id = auth.uid());
revoke all on public.quiz_progress from anon;
revoke insert, update, delete on public.quiz_progress from authenticated;
grant select on public.quiz_progress to authenticated;

-- ── 3. Recompute: add the quiz term (rooms + scenarios + quizzes) ────────────
create or replace function public.recompute_user_xp(p_user uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_records integer;
  v_offset  integer;
begin
  -- Rooms + scenarios (gated mastery, 0035) + standalone quizzes (best attempt,
  -- server-graded). Dashboard practice stays excluded.
  select
      coalesce((select sum(xp_earned) from public.room_progress    where user_id = p_user), 0)
    + coalesce((select sum(xp_earned) from public.scenario_history where user_id = p_user), 0)
    + coalesce((select sum(xp_earned) from public.quiz_progress    where user_id = p_user), 0)
  into v_records;

  select coalesce(xp_offset, 0) into v_offset from public.profiles where id = p_user;

  update public.profiles
     set xp = greatest(0, v_offset + v_records)
   where id = p_user;
end;
$$;

comment on function public.recompute_user_xp(uuid) is
  'Sets profiles.xp = xp_offset + sum(xp_earned) across room_progress + scenario_history + quiz_progress (best attempt per quiz, server-graded). Dashboard practice is excluded. Sole writer of profiles.xp.';

-- ── 4. Keep xp current whenever a quiz record changes ────────────────────────
drop trigger if exists quiz_progress_recompute_xp on public.quiz_progress;
create trigger quiz_progress_recompute_xp
  after insert or update or delete on public.quiz_progress
  for each row execute function public.trg_recompute_user_xp();

-- ── 5. Atomic best-attempt write (called by the finish route, service role) ──
-- One upsert with greatest(): two attempts finishing at once can't lower the
-- best, and attempts is incremented exactly once each. Returns the previous
-- best, the new best, and the recomputed overall score (the trigger above has
-- already updated profiles.xp inside this same statement's transaction).
create or replace function public.record_quiz_attempt(
  p_user uuid, p_slug text, p_org uuid, p_xp integer, p_pct integer)
returns table(prev_best integer, best integer, total_xp integer)
language plpgsql
security definer
set search_path = public
as $$
declare v_prev integer;
begin
  select q.xp_earned into v_prev from public.quiz_progress q
   where q.user_id = p_user and q.quiz_slug = p_slug;

  insert into public.quiz_progress as q
      (user_id, quiz_slug, org_id, xp_earned, best_score_pct, passed, attempts)
  values (p_user, p_slug, p_org,
          least(greatest(coalesce(p_xp, 0), 0), 1000),
          least(greatest(coalesce(p_pct, 0), 0), 100),
          coalesce(p_pct, 0) >= 70, 1)
  on conflict (user_id, quiz_slug) do update set
      xp_earned         = greatest(q.xp_earned, excluded.xp_earned),
      best_score_pct    = greatest(q.best_score_pct, excluded.best_score_pct),
      passed            = q.passed or excluded.passed,
      attempts          = q.attempts + 1,
      org_id            = coalesce(q.org_id, excluded.org_id),
      last_completed_at = now();

  return query
    select coalesce(v_prev, 0), q.xp_earned, p.xp
      from public.quiz_progress q join public.profiles p on p.id = q.user_id
     where q.user_id = p_user and q.quiz_slug = p_slug;
end;
$$;
revoke execute on function public.record_quiz_attempt(uuid, text, uuid, integer, integer) from public, anon, authenticated;
grant  execute on function public.record_quiz_attempt(uuid, text, uuid, integer, integer) to service_role;

-- ── Verification ─────────────────────────────────────────────────────────────
-- 1. No totals changed:  select count(*) from public.quiz_progress;  -- 0
-- 2. Client can't write: as an authenticated user, insert into quiz_progress → permission denied.
-- 3. Server write moves xp: upsert a row with xp_earned=50 (service role) → profiles.xp rises by 50.
