-- HACK THE SOC :: 0110 — the figures behind each student progress report
-- ---------------------------------------------------------------------------
-- An org admin downloads a PDF progress report per student (or for the whole class). The
-- report compares the learner with the PREVIOUS report ("+320 XP, right first try 68% -> 74%
-- since the report of 2 Nov"), so the figures of each report are kept here.
--
-- Server-only: written and read by POST /api/org/students/[id]/report-snapshot with the
-- service role, after requireOrgAdmin and an org-membership check. No client policy at all
-- (RLS on, no grants to anon / authenticated): a learner never reads a manager's report.
--
-- Org isolation: org_id references organizations ON DELETE CASCADE (purge_org deletes the
-- organization row), user_id references auth.users ON DELETE CASCADE.
--
-- NON-DESTRUCTIVE: a new, empty table. Idempotent.

create table if not exists public.student_report_snapshots (
  id          bigint generated always as identity primary key,
  org_id      uuid not null references public.organizations(id) on delete cascade,
  user_id     uuid not null references auth.users(id) on delete cascade,
  created_by  uuid references auth.users(id) on delete set null,
  created_at  timestamptz not null default now(),
  metrics     jsonb not null check (jsonb_typeof(metrics) = 'object' and pg_column_size(metrics) <= 16384)
);
create index if not exists student_report_snapshots_lookup on public.student_report_snapshots (org_id, user_id, created_at desc);

alter table public.student_report_snapshots enable row level security;
revoke all on public.student_report_snapshots from anon, authenticated;
grant select, insert on public.student_report_snapshots to service_role;
