-- ─────────────────────────────────────────────────────────────────────────────
-- 0027 — Right to deletion (זכות למחיקה, חוק הגנת הפרטיות + תיקון 13)
--
-- Closes the gap recorded in docs/PPA-COMPLIANCE-ASSESSMENT.md §5.1: a student
-- could not delete their own account, so the right to deletion existed only as
-- a manual request with no mechanism behind it.
--
-- WHY A REQUEST QUEUE AND NOT A BIG RED BUTTON FOR EVERYONE
--
-- The two populations differ, and collapsing them would be wrong in one
-- direction or the other:
--
--   * A solo learner has no counterparty. Their data is theirs; making them
--     wait on a human to approve a deletion is friction with no justification.
--     They delete immediately, in-product.
--
--   * A student enrolled through a college is different: their room/scenario
--     results ARE the college's assessment record for a course they may still
--     be taking. A unilateral self-delete would destroy the institution's
--     record mid-course. So they file a request, and their org admin — who is
--     the controller for that cohort and already administers the account —
--     actions it. The law's 30-day response window is what this queue exists
--     to make measurable, and the request is visible to the admin immediately.
--
-- HOW THE DELETE ITSELF WORKS
--
-- There is deliberately NO hand-written list of tables to purge here. Every
-- per-user table already declares `on delete cascade` from auth.users or
-- public.profiles (and profiles.id itself cascades from auth.users), so
-- deleting the auth user removes the whole graph atomically. A hand-maintained
-- delete list is exactly the thing that silently rots when someone adds table
-- number 33 and forgets — the FK graph cannot rot, because the database
-- enforces it. Deletion is therefore performed by the API through
-- auth.admin.deleteUser(); this migration only carries the request queue.
--
-- WHAT SURVIVES ON PURPOSE
--
-- public.audit_log.actor_id is `on delete set null`, so records of privileged
-- actions survive the person. That is intentional and required: the Information
-- Security Regulations (תקנות אבטחת מידע 2017) want access records retained
-- ~24 months, and a null actor keeps the security record without keeping the
-- personal identifier. Same for content `created_by` — authored lessons must
-- not vanish because their author closed an account.
-- ─────────────────────────────────────────────────────────────────────────────

create table if not exists public.account_deletion_requests (
  id           uuid primary key default gen_random_uuid(),
  user_id      uuid not null references public.profiles(id) on delete cascade,
  org_id       uuid not null references public.organizations(id) on delete cascade,
  status       text not null default 'pending'
                 check (status in ('pending', 'completed', 'rejected')),
  reason       text,
  requested_at timestamptz not null default now(),
  decided_by   uuid references public.profiles(id) on delete set null,
  decided_at   timestamptz,
  decision_note text
);

-- One open request per person. A student who clicks twice should not create a
-- second row for the same decision, and the org admin should not have to
-- reconcile duplicates. Partial index so historical rows don't block a NEW
-- request after a rejection.
create unique index if not exists account_deletion_requests_one_open
  on public.account_deletion_requests (user_id)
  where status = 'pending';

create index if not exists account_deletion_requests_org_pending
  on public.account_deletion_requests (org_id, status, requested_at desc);

alter table public.account_deletion_requests enable row level security;

-- The subject sees their own request, whatever its state.
drop policy if exists adr_select_own on public.account_deletion_requests;
create policy adr_select_own on public.account_deletion_requests
  for select to authenticated
  using (user_id = auth.uid());

-- The subject files their own request, and only their own — user_id is pinned
-- to auth.uid() so the row cannot be filed on someone else's behalf.
drop policy if exists adr_insert_own on public.account_deletion_requests;
create policy adr_insert_own on public.account_deletion_requests
  for insert to authenticated
  with check (user_id = auth.uid());

-- An org admin sees requests from their OWN org only. Membership is checked
-- against org_members rather than a JWT claim so a stale token cannot widen
-- the scope.
drop policy if exists adr_select_org_admin on public.account_deletion_requests;
create policy adr_select_org_admin on public.account_deletion_requests
  for select to authenticated
  using (
    exists (
      select 1 from public.org_members m
      where m.org_id = account_deletion_requests.org_id
        and m.user_id = auth.uid()
        and m.role in ('org_admin', 'instructor')
        and m.status = 'active'
    )
  );

-- No UPDATE or DELETE policy for anyone. Deciding a request is a service-role
-- operation behind requireOrgAdmin (see /api/org/deletion-requests), because
-- approving one triggers an irreversible auth-user deletion — that must not be
-- reachable by a client that merely holds a session.
revoke update, delete on public.account_deletion_requests from authenticated, anon;

comment on table public.account_deletion_requests is
  'Right-to-deletion queue for org-enrolled students. Solo learners delete directly via DELETE /api/account and never appear here.';
