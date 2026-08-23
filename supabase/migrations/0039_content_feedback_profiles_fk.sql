-- 0039_content_feedback_profiles_fk.sql
--
-- Fix: the "Report a problem" / "Report an issue" inbox showed nothing to the
-- super-admin, and its "Content Reports" sidebar link never even appeared —
-- even though students DID submit reports (they got the "Thanks" confirmation
-- and the rows landed in content_feedback).
--
-- Root cause (the identical defect 0033 fixed for org_members, never applied
-- here): content_feedback.user_id referenced auth.users, not public.profiles.
-- GET /api/feedback selects `... profiles:user_id(handle, display_name)`, which
-- needs a PostgREST-detectable FK from content_feedback to public.profiles.
-- With the FK pointing at auth.users, PostgREST returns PGRST200 ("could not
-- find a relationship"), the route 500s, FeedbackInbox renders an error with
-- zero items, and ContentFeedbackLink (which only renders on a 200 response)
-- stays hidden — so the owner has no entry point at all.
--
-- Fix: repoint the FK at public.profiles. profiles.id is 1:1 with auth.users.id
-- and itself references auth.users(id) on delete cascade, so transitively the
-- auth referential integrity is preserved. Then reload the PostgREST schema
-- cache so the embed resolves immediately. (No data migration: every existing
-- content_feedback.user_id already exists in profiles — verified 0 orphans.)

alter table public.content_feedback
  drop constraint if exists content_feedback_user_id_fkey;

alter table public.content_feedback
  drop constraint if exists content_feedback_user_id_profiles_fkey;

alter table public.content_feedback
  add constraint content_feedback_user_id_profiles_fkey
  foreign key (user_id) references public.profiles(id) on delete set null;

notify pgrst, 'reload schema';
