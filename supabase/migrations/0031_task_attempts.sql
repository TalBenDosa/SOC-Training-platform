-- 0031 — task_attempts: capture WHERE a student erred (P2)
--
-- Until now the room submit route was stateless: it graded a task and returned
-- {correct, xpEarned, reveal} but recorded nothing, so only PASSED task ids were
-- ever stored (room_progress.completed_task_ids). An instructor could see that a
-- student finished a room but never what they got wrong, what they chose, or how
-- many tries it took. This table records every graded submission so the
-- per-student drill-down can show real mistakes.
--
-- Written by the submit route via the service role (user_id + org_id stamped
-- from the authed session); RLS below is defence-in-depth for any direct client
-- read: a student sees their own, org staff see their org's.

create table if not exists public.task_attempts (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid not null references auth.users(id) on delete cascade,
  org_id      uuid references public.organizations(id) on delete set null,
  room_id     text not null,
  task_id     text not null,
  task_type   text,
  correct     boolean not null,
  -- what the student actually submitted (the wrong choice, the filled blanks,
  -- the verdict…) — enough to see the mistake, whatever the task type.
  submitted   jsonb,
  attempt_no  int not null default 1,
  latency_ms  int,
  created_at  timestamptz not null default now()
);

create index if not exists task_attempts_user_room_idx on public.task_attempts (user_id, room_id, created_at desc);
create index if not exists task_attempts_org_idx        on public.task_attempts (org_id);

alter table public.task_attempts enable row level security;

-- student: insert + read their own attempts
drop policy if exists task_attempts_own_ins on public.task_attempts;
create policy task_attempts_own_ins on public.task_attempts
  for insert to authenticated with check (user_id = auth.uid());

drop policy if exists task_attempts_own_sel on public.task_attempts;
create policy task_attempts_own_sel on public.task_attempts
  for select to authenticated using (user_id = auth.uid());

-- org staff (org_admin / instructor): read their own org's attempts
drop policy if exists task_attempts_org_sel on public.task_attempts;
create policy task_attempts_org_sel on public.task_attempts
  for select to authenticated using (
    exists (
      select 1 from public.org_members om
      where om.org_id = task_attempts.org_id
        and om.user_id = auth.uid()
        and om.role in ('org_admin', 'instructor')
        and om.status = 'active'
    )
  );

grant select, insert on public.task_attempts to authenticated;
