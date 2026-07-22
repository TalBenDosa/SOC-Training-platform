-- HACK THE SOC :: 0007 — lock down the audit trail
-- ---------------------------------------------------------------------------
-- FINDING (AppSec scan, 22.07.2026). 0001_init.sql created public.audit_log with
-- `create table` but never enabled row-level security on it. In Supabase the
-- anon/authenticated roles are granted on public tables by default, and without
-- RLS those grants are fully effective — so the audit log was reachable through
-- the public anon key: a client could READ every entry, and FORGE or DELETE
-- entries. An audit trail that its subjects can edit is worthless as evidence.
--
-- Separately, nothing wrote to the table at all (no תיעוד of access/privileged
-- actions — a core control under תקנות הגנת הפרטיות (אבטחת מידע) התשע"ז-2017).
-- The application side is addressed by src/lib/audit/logAudit.ts, which appends
-- through the SERVICE-ROLE key. This migration makes that the ONLY way in.
--
-- FIX. Enable RLS and add NO policy for anon/authenticated. With RLS on and no
-- permissive policy, those roles can neither select, insert, update, nor delete.
-- The service_role key BYPASSES RLS, so server-side logging keeps working while
-- every client path is closed. The result is an append-only-by-trusted-server,
-- tamper-proof-from-clients log.

alter table public.audit_log enable row level security;

-- Defensive: also revoke the default table grants so the table isn't even
-- exposed through PostgREST to the public roles. (RLS already blocks the rows;
-- this removes the surface entirely.)
revoke all on table public.audit_log from anon, authenticated;

-- No CREATE POLICY statements — deny-by-default is the intent. Only service_role
-- (which bypasses RLS) may read/write, which is exactly logAudit()'s client.

comment on table public.audit_log is
  'Append-only audit trail. Written ONLY via the service-role key (see src/lib/audit/logAudit.ts). RLS on + no client policy + grants revoked = clients cannot read, forge, or delete entries.';

-- ── Verification (run after applying) ───────────────────────────────────────
-- As anon or a signed-in user, all four must be denied / return zero rows:
--   select * from public.audit_log;                       -- 0 rows / permission denied
--   insert into public.audit_log(action) values ('x');    -- denied
--   update public.audit_log set action='x';               -- denied
--   delete from public.audit_log;                          -- denied
-- A service-role connection (server) must still be able to insert and select.
