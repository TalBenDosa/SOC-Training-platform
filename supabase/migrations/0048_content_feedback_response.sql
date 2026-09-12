-- 0048 — let a platform/super-admin reply to a reporter from the reports inbox.
--
-- content_feedback (0022) had no place to record a human response, so a report
-- could only be triaged by status — the reporter who took the time to write it
-- never heard back. Add an optional free-text admin response + who/when, stored
-- for an audit trail; the actual delivery to the reporter is an email sent by
-- the reply API route (POST /api/feedback/[id]/reply), which resolves the
-- reporter's address server-side from user_id and never exposes it to a client.
-- Additive + idempotent.

alter table public.content_feedback
  add column if not exists admin_response text,
  add column if not exists responded_at   timestamptz,
  add column if not exists responded_by   uuid references auth.users(id) on delete set null;
