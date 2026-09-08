-- 0046 — Fix "Some progress hasn't saved" for users whose active org changed.
--
-- Bug: user_progress is a per-user singleton (PRIMARY KEY user_id). Its self
-- policy "user_progress org self" (migration 0011) is:
--     USING       (user_id = auth.uid() AND org_id = current_org())
--     WITH CHECK  (user_id = auth.uid() AND org_id = current_org())
-- The org_id column on the row is stamped from the caller's JWT org at write
-- time. When a user's active org later changes (they belong to more than one
-- org, or an org context switch moves profiles.org_id, which the access-token
-- hook uses to pick the JWT org_id), current_org() no longer equals the org_id
-- already stored on their row. The client's upsert (INSERT ... ON CONFLICT
-- (user_id) DO UPDATE) then hits the UPDATE path, whose USING clause is
-- evaluated against the EXISTING row — org_id (old) != current_org() (new) —
-- so the row is not updatable and every idempotent user_progress write
-- (lastSession / clearedCompanies / streakFreezes) is denied. The SyncStatus
-- banner surfaces this as "Some progress hasn't saved" (auto-retry variant),
-- while dashboard_sessions / scenario_history keep working because those are
-- INSERTs of new rows stamped with the current org.
--
-- Fix: the self policy only needs user_id = auth.uid() to isolate a user's own
-- singleton row — user_id fully scopes it and a user can never match another
-- user's row. Drop the org_id equality from USING so an active-org change no
-- longer strands the existing row. WITH CHECK keeps org_id = current_org(), so
-- writes still stamp the caller's current org (no ability to plant a row under
-- an org that is not yours). Cross-user visibility for instructors/admins is a
-- SEPARATE policy ("user_progress org staff read") and is unchanged, so no
-- tenant isolation is weakened by this change.

alter policy "user_progress org self" on public.user_progress
  using (user_id = auth.uid())
  with check ((user_id = auth.uid()) and (org_id = current_org()));
