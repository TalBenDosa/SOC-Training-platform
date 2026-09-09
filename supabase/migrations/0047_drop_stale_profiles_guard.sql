-- 0047 — remove a stale, UNUSED copy of the profiles privileged-column guard.
--
-- A security review found two functions with confusingly similar names:
--   * guard_profile_privileged_columns()      — the LIVE one the trigger
--     `profiles_guard_privileged_columns` on public.profiles actually executes.
--     It preserves id, role, org_id, is_platform_admin and xp_offset on any
--     client (auth.uid() IS NOT NULL) UPDATE, so self-service privilege
--     escalation is blocked (verified statically + empirically).
--   * profiles_guard_privileged_columns()     — an OLDER, orphaned copy that
--     only preserves id + role (NOT is_platform_admin). Nothing references it —
--     no trigger executes it — so it is dead code, but its presence is a trap: a
--     future reader could mistake it for the active guard and conclude
--     is_platform_admin is unprotected. Drop it.
--
-- Safe: it is not wired to any trigger (the trigger uses the other function).
-- Uses IF EXISTS so re-running is a no-op.

drop function if exists public.profiles_guard_privileged_columns();
