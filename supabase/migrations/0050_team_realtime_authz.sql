-- HACK THE SOC :: 0050 — Realtime authorization for team sessions — Phase 0.1
-- ===========================================================================
-- Private-channel access control for the shared incident room. Clients connect
-- to a private topic "session:<uuid>" (config { private: true }); Supabase
-- Realtime enforces access by running RLS on realtime.messages. A user may
-- receive (SELECT) and send / track presence (INSERT) on a session topic ONLY
-- if they are a member of that session (public.is_team_member).
--
-- Split from 0049 so a permissions hiccup on the realtime schema can't roll back
-- the core tables. Idempotent. See docs/SPEC-team-soc-multiplayer.md §8.2/§13.11.
-- ===========================================================================

-- RLS is already enabled on realtime.messages by default in Supabase (and the
-- project's postgres role is not its owner, so we must NOT re-run ALTER TABLE …
-- ENABLE RLS here — it errors with "must be owner of table messages"). We only
-- add policies, which the role IS permitted to create.

-- Receive broadcast + presence on a session topic you belong to.
drop policy if exists "team session realtime read" on realtime.messages;
create policy "team session realtime read" on realtime.messages
  for select to authenticated
  using (
    extension in ('broadcast','presence')
    and public.is_team_member(public.team_topic_session(realtime.topic()), auth.uid())
  );

-- Send broadcast + track presence on a session topic you belong to.
drop policy if exists "team session realtime write" on realtime.messages;
create policy "team session realtime write" on realtime.messages
  for insert to authenticated
  with check (
    extension in ('broadcast','presence')
    and public.is_team_member(public.team_topic_session(realtime.topic()), auth.uid())
  );

-- Verification: with a member's JWT, subscribe to a private channel
--   session:<their session id>  → SUBSCRIBED; a non-member → CHANNEL_ERROR.
