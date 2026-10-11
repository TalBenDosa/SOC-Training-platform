-- ─────────────────────────────────────────────────────────────────────────────
-- 0020 — Contract record on organizations (manual v1)
-- ─────────────────────────────────────────────────────────────────────────────
-- Today there is NO source of truth for what a college is actually paying for.
-- `seat_limit` and `expires_at` are access-control fields a super-admin sets by
-- hand; the commercial terms behind them (plan, price, PO number, who signed,
-- when) live only in Tal's memory and whatever email thread closed the deal.
-- That's survivable for the first pilot and untenable past a handful of orgs:
-- a renewal conversation has nothing to reference, and nobody else could pick
-- up the account.
--
-- This is deliberately a RECORD, not a billing engine — no Stripe, no payment
-- capture, no automatic dunning. It gives the super-admin console somewhere to
-- write down the deal so the platform can answer "what did they buy, for how
-- much, until when, under which PO". A real payments integration can come
-- later and read/replace this without a schema fight.
--
-- Modelled as jsonb for the same reason `branding` is: the shape of a deal
-- changes (pilots, multi-year, per-seat vs site licence) and each change would
-- otherwise be a migration. Nothing queries inside it; it's read whole by the
-- super-admin console only.
--
-- Access: `organizations` already has RLS from 0011 — a member may read only
-- their OWN org row ("organizations read own", id = current_org()). That policy
-- is unchanged here, which means a college CAN read its own contract blob.
-- That's intentional and correct (it's their own commercial terms), but it is
-- why nothing secret — no internal margin notes, no other tenant's pricing —
-- may be stored here. Writes remain super-admin-only via the service-role
-- client in /api/superadmin/orgs/[id] (no client write policy exists).
-- ─────────────────────────────────────────────────────────────────────────────

alter table public.organizations
  add column if not exists contract jsonb not null default '{}'::jsonb;

comment on column public.organizations.contract is
  'Commercial record for this org (manual, super-admin authored): plan, seats_purchased, price, currency, po_number, signed_at, notes. Not a billing engine — no payment state. Readable by the org itself under the existing "organizations read own" RLS policy, so store nothing internal-only here.';

-- Verification:
--   select id, name, seat_limit, expires_at, contract from public.organizations;
