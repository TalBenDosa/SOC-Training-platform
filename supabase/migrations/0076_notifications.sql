-- ─────────────────────────────────────────────────────────────────────────────
-- 0076 — In-app notifications (learning plans v2 follow-up)
-- ─────────────────────────────────────────────────────────────────────────────
-- 0075 let an org admin assign learning plans to the whole org, to groups, to
-- specific people and as a learner's personal plan — but the learner only found
-- out by happening to open /learn. This adds a per-user notification inbox that
-- backs the (now functional) bell in the Topbar:
--
--   plan_assigned — a plan now reaches you (new plan, or you were added to one)
--   plan_updated  — a plan you already had gained new items
--   personal_plan — your personal priorities changed
--
-- WRITES ARE SERVER-ONLY. Rows are inserted by the plan API routes with the
-- service role (src/lib/plans/notify.ts), after they have resolved the plan's
-- real recipients. There is deliberately NO insert/delete grant or policy for
-- clients: a learner cannot forge a notification for anyone (including
-- themselves), and cannot delete the record. The only client write is marking
-- one's OWN rows read — enforced twice: the UPDATE policy pins user_id =
-- auth.uid(), and the column-level grant allows only read_at to change.
--
-- Tenant integrity is structural (mirrors 0075): the composite FK to
-- org_members (org_id, user_id) means a notification can only exist for a
-- member of that org, and leaving the org deletes them. The composite FK to
-- assignments (assignment_id, org_id) pins a notification to a plan of the SAME
-- org; deleting the plan removes its notifications (nothing is sent for a
-- delete, and a stale "new plan" pointing at nothing is noise).
--
-- BACKWARD COMPATIBLE: a new table only. Code deployed ahead of this migration
-- degrades cleanly — the notify step logs and skips, GET /api/notifications
-- answers an empty inbox — and plan saves are unaffected.
--
-- Idempotent: safe to re-run.
-- ─────────────────────────────────────────────────────────────────────────────

create table if not exists public.notifications (
  id            uuid primary key default gen_random_uuid(),
  org_id        uuid not null,
  user_id       uuid not null,
  kind          text not null,
  title         text not null,
  body          text,
  link          text,
  assignment_id uuid,
  created_at    timestamptz not null default now(),
  read_at       timestamptz
);

do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'notifications_kind_chk') then
    alter table public.notifications add constraint notifications_kind_chk
      check (kind in ('plan_assigned', 'plan_updated', 'personal_plan'));
  end if;
  if not exists (select 1 from pg_constraint where conname = 'notifications_title_chk') then
    alter table public.notifications add constraint notifications_title_chk
      check (char_length(btrim(title)) between 1 and 200);
  end if;
  if not exists (select 1 from pg_constraint where conname = 'notifications_body_chk') then
    alter table public.notifications add constraint notifications_body_chk
      check (body is null or char_length(body) <= 500);
  end if;
  -- Links are in-app paths only ("/learn", "/rooms/x") — never an absolute or
  -- protocol-relative URL, so a notification can't become an open redirect.
  if not exists (select 1 from pg_constraint where conname = 'notifications_link_chk') then
    alter table public.notifications add constraint notifications_link_chk
      check (link is null or (char_length(link) <= 300 and left(link, 1) = '/' and substr(link, 2, 1) not in ('/', '\')));
  end if;
  -- Only a member of the org can hold one of its notifications; leaving the
  -- org removes them.
  if not exists (select 1 from pg_constraint where conname = 'notifications_member_fk') then
    alter table public.notifications add constraint notifications_member_fk
      foreign key (org_id, user_id) references public.org_members (org_id, user_id) on delete cascade;
  end if;
  -- The plan must be in the same org (assignments_id_org_uq from 0075).
  if not exists (select 1 from pg_constraint where conname = 'notifications_assignment_fk') then
    alter table public.notifications add constraint notifications_assignment_fk
      foreign key (assignment_id, org_id) references public.assignments (id, org_id) on delete cascade;
  end if;
end $$;

-- The bell's two reads: newest-first page, and the unread count.
create index if not exists notifications_user_read_created_idx
  on public.notifications (user_id, read_at, created_at desc);
-- FK helpers (cascade deletes from assignments / org_members).
create index if not exists notifications_assignment_idx
  on public.notifications (assignment_id) where assignment_id is not null;
create index if not exists notifications_org_user_idx
  on public.notifications (org_id, user_id);

-- ── RLS ──────────────────────────────────────────────────────────────────────
alter table public.notifications enable row level security;

drop policy if exists "notifications own read" on public.notifications;
create policy "notifications own read" on public.notifications
  for select to authenticated using (user_id = auth.uid());

drop policy if exists "notifications own mark read" on public.notifications;
create policy "notifications own mark read" on public.notifications
  for update to authenticated
  using (user_id = auth.uid())
  with check (user_id = auth.uid());

-- No insert / delete policy: those stay service-role only.

-- Revoke everything first (Supabase's default privileges hand authenticated
-- INSERT/DELETE/TRUNCATE/REFERENCES/TRIGGER on new tables), then grant back only
-- SELECT and an UPDATE limited to the read_at column.
revoke all on public.notifications from anon, authenticated;
grant select on public.notifications to authenticated;
grant update (read_at) on public.notifications to authenticated;

comment on table public.notifications is
  'Per-user in-app notifications (learning plans). Written by the service role only; a user can read and mark read (read_at only) their own rows.';
comment on column public.notifications.link is
  'In-app path to open on click (must start with a single "/").';

-- Verification (run on STAGING):
--   set local role authenticated;
--   select set_config('request.jwt.claims', '{"sub":"<user>","role":"authenticated"}', true);
--   select * from public.notifications;                              -- own rows only
--   update public.notifications set read_at = now();                 -- own rows only
--   update public.notifications set title = 'x';                     -- permission denied
--   insert into public.notifications (...) values (...);             -- permission denied
