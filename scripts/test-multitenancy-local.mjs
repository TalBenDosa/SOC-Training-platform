// End-to-end multi-tenancy isolation test — runs the REAL migrations (0001–0015)
// against an in-memory Postgres (PGlite, PG18) with thin Supabase-auth shims,
// then plays out the full scenario:
//
//   1. Super-admin opens College A and College B.
//   2. Students self-enroll into each via the real invitation trigger.
//   3. Each student's progress is recorded.
//   4. We impersonate a student of each college (using the claims the REAL
//      access-token hook produces) and prove — at the DATABASE, via RLS — that
//      neither college can read or write the other's data.
//   5. Seat cap, license expiry, and offboarding-purge are checked too.
//
// This needs no Docker/Supabase — it exercises the actual SQL that ships.
// Run: node scripts/test-multitenancy-local.mjs
import { PGlite } from "@electric-sql/pglite";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";
import { randomUUID } from "node:crypto";

const MIG = join(dirname(fileURLToPath(import.meta.url)), "..", "supabase", "migrations");
const INTERNAL = "d0d0d0d0-0000-4000-8000-000000000000";
let pass = 0, fail = 0;
function check(name, cond, extra = "") {
  console.log(`  ${cond ? "✅ PASS" : "❌ FAIL"}  ${name}${extra ? `  — ${extra}` : ""}`);
  cond ? pass++ : fail++;
}
function section(t) { console.log(`\n\x1b[1m${t}\x1b[0m`); }

const SHIM = `
create schema if not exists auth;
create table if not exists auth.users (
  id uuid primary key default gen_random_uuid(), email text,
  raw_user_meta_data jsonb default '{}'::jsonb, raw_app_meta_data jsonb default '{}'::jsonb,
  created_at timestamptz default now());
create or replace function auth.uid() returns uuid language sql stable as $fn$
  select nullif(current_setting('request.jwt.claims', true)::jsonb ->> 'sub','')::uuid $fn$;
create or replace function auth.jwt() returns jsonb language sql stable as $fn$
  select coalesce(nullif(current_setting('request.jwt.claims', true),'')::jsonb, '{}'::jsonb) $fn$;
do $do$ begin
  if not exists (select from pg_roles where rolname='anon') then create role anon; end if;
  if not exists (select from pg_roles where rolname='authenticated') then create role authenticated; end if;
  if not exists (select from pg_roles where rolname='supabase_auth_admin') then create role supabase_auth_admin; end if;
  if not exists (select from pg_roles where rolname='service_role') then create role service_role; end if;
end $do$;
grant usage on schema public, auth to anon, authenticated, service_role, supabase_auth_admin;
alter default privileges in schema public grant select, insert, update, delete on tables to authenticated, anon;
alter default privileges in schema public grant execute on functions to anon, authenticated;
create or replace function public.uuid_generate_v4() returns uuid language sql as $fn$ select gen_random_uuid() $fn$;
`;

const db = new PGlite();
await db.exec(SHIM);
for (const f of readdirSync(MIG).filter(f => f.endsWith(".sql")).sort()) {
  await db.exec(readFileSync(join(MIG, f), "utf8").replace(/create extension[^;]*;/gi, ""));
}
const q = (sql, params = []) => db.query(sql, params);

// ── helper: impersonate a signed-in student using the REAL hook's claims ─────
async function claimsFor(uid) {
  const r = await q(
    `select public.custom_access_token_hook(jsonb_build_object('user_id',$1::text,'claims',jsonb_build_object('sub',$1::text))) as e`,
    [uid],
  );
  return r.rows[0].e.claims;
}
async function asStudent(uid, fn) {
  const claims = await claimsFor(uid);
  await q(`select set_config('request.jwt.claims', $1, false)`, [JSON.stringify(claims)]);
  await db.exec(`set role authenticated`);
  try { return await fn(claims); } finally { await db.exec(`reset role`); }
}

// ── super-admin (service role = superuser here) creates an org ───────────────
async function createOrg(name, slug, seats) {
  const id = randomUUID();
  await q(`insert into public.organizations (id,name,slug,seat_limit,status,starts_at) values ($1,$2,$3,$4,'active',now())`,
    [id, name, slug, seats]);
  return id;
}
// a student self-enrolls via an invitation link (fires handle_new_user)
async function enroll(orgId, handle, fullName) {
  const token = randomUUID();
  await q(`insert into public.invitations (org_id,role,token,expires_at) values ($1,'student',$2, now()+interval '14 days')`, [orgId, token]);
  const uid = randomUUID();
  await q(`insert into auth.users (id,email,raw_user_meta_data) values ($1,$2,$3)`,
    [uid, `${handle}@example.com`, JSON.stringify({ invitation_token: token, handle, full_name: fullName })]);
  return uid;
}
async function completeRoom(orgId, uid, roomId) {
  await q(`insert into public.room_progress (user_id,org_id,room_id,completed_task_ids,xp_earned,completed_at)
           values ($1,$2,$3,'[]'::jsonb,100, now())`, [uid, orgId, roomId]);
}

// ═══════════════════════════════════════════════════════════════════════════
section("1) Super-admin opens two colleges");
const sapir = await createOrg("Sapir College", "sapir", 50);
const technion = await createOrg("Technion Cyber", "technion", 50);
const orgs = await q(`select count(*)::int c from public.organizations where id in ($1,$2)`, [sapir, technion]);
check("both colleges created", orgs.rows[0].c === 2);

section("2) Students self-enroll into each college (real invitation trigger)");
const a1 = await enroll(sapir, "sapir_dana", "Dana Levi");
const a2 = await enroll(sapir, "sapir_omri", "Omri Cohen");
const b1 = await enroll(technion, "tech_noa", "Noa Bar");
const b2 = await enroll(technion, "tech_yuval", "Yuval Adar");
const memA = await q(`select count(*)::int c from public.org_members where org_id=$1 and status='active'`, [sapir]);
const memB = await q(`select count(*)::int c from public.org_members where org_id=$1 and status='active'`, [technion]);
check("Sapir has 2 members", memA.rows[0].c === 2);
check("Technion has 2 members", memB.rows[0].c === 2);
const pa = await q(`select org_id from public.profiles where id=$1`, [a1]);
check("student A1 profile bound to Sapir", pa.rows[0].org_id === sapir);
const pb = await q(`select org_id from public.profiles where id=$1`, [b1]);
check("student B1 profile bound to Technion", pb.rows[0].org_id === technion);

section("3) Each student records progress");
await completeRoom(sapir, a1, "intro"); await completeRoom(sapir, a2, "intro");
await completeRoom(technion, b1, "intro"); await completeRoom(technion, b2, "intro");
const totalRooms = await q(`select count(*)::int c from public.room_progress`);
check("4 progress rows exist (service-role view)", totalRooms.rows[0].c === 4);

section("4) ISOLATION — impersonate a Sapir student (DB-enforced RLS)");
await asStudent(a1, async (claims) => {
  check("hook stamped org_id = Sapir", claims.org_id === sapir);
  check("hook stamped org_name = 'Sapir College'", claims.org_name === "Sapir College");
  check("hook stamped org_active = true", claims.org_active === true);
  const rooms = await q(`select org_id from public.room_progress`);
  check("sees only Sapir room_progress", rooms.rows.length > 0 && rooms.rows.every(r => r.org_id === sapir),
    `${rooms.rows.length} rows, all Sapir`);
  const seeB = await q(`select count(*)::int c from public.room_progress where user_id=$1`, [b1]);
  check("cannot read a Technion student's row (cross-tenant SELECT = 0)", seeB.rows[0].c === 0);
  const seeOrgs = await q(`select id from public.organizations`);
  check("sees only its own organization row", seeOrgs.rows.length === 1 && seeOrgs.rows[0].id === sapir);
  const seeMembers = await q(`select distinct org_id from public.org_members`);
  check("sees only Sapir memberships", seeMembers.rows.length === 1 && seeMembers.rows[0].org_id === sapir);
  let blocked = false;
  try { await q(`insert into public.room_progress (user_id,org_id,room_id,completed_task_ids,xp_earned) values ($1,$2,'evil','[]'::jsonb,999)`, [a1, technion]); }
  catch { blocked = true; }
  check("cannot WRITE into Technion (WITH CHECK rejects cross-tenant insert)", blocked);
});

section("5) ISOLATION — impersonate a Technion student (symmetric)");
await asStudent(b1, async (claims) => {
  check("hook stamped org_id = Technion", claims.org_id === technion);
  const rooms = await q(`select org_id from public.room_progress`);
  check("sees only Technion room_progress", rooms.rows.length > 0 && rooms.rows.every(r => r.org_id === technion));
  const seeA = await q(`select count(*)::int c from public.room_progress where user_id=$1`, [a1]);
  check("cannot read a Sapir student's row", seeA.rows[0].c === 0);
  const seeProfilesA = await q(`select count(*)::int c from public.profiles where id=$1`, [a1]);
  check("cannot read a Sapir student's profile", seeProfilesA.rows[0].c === 0);
});

section("6) DB SEPARATION — data is physically partitioned by org_id");
const split = await q(`select org_id, count(*)::int c from public.room_progress group by org_id order by 1`);
const byOrg = Object.fromEntries(split.rows.map(r => [r.org_id, r.c]));
check("Sapir has exactly its 2 rows, Technion its 2 rows (disjoint)", byOrg[sapir] === 2 && byOrg[technion] === 2);

section("7) Seat cap enforced");
const tiny = await createOrg("Tiny College", "tiny", 1);
await enroll(tiny, "tiny_one", "One Student"); // fills the single seat
let capBlocked = false;
try {
  const u = randomUUID();
  await q(`insert into auth.users (id,email) values ($1,'x@x.com')`, [u]);
  await q(`select public.attach_member_if_seat_available($1,$2,'student')`, [tiny, u]);
} catch (e) { capBlocked = /seat_limit_reached/.test(e.message); }
check("attaching beyond the seat limit is rejected", capBlocked);

section("8) License expiry → hook reports org_active=false");
const expired = await createOrg("Expired College", "expired", 10);
await q(`update public.organizations set expires_at = now() - interval '1 day' where id=$1`, [expired]);
const ux = await enroll(expired, "exp_stu", "Exp Student");
const expClaims = await claimsFor(ux);
check("expired college's students carry org_active=false (→ /license lock)", expClaims.org_active === false);

section("9) Offboarding — purge_org removes a college cleanly, others untouched");
// Super-admin acts via the service role — no user session, so auth.uid() is
// null and the profile org_id-freeze guard (correctly) does not apply. (With a
// student's claims still set, the guard would freeze org_id — a security feature.)
await q(`select set_config('request.jwt.claims','{}',false)`);
await q(`select public.purge_org($1)`, [technion]);
const techGone = await q(`select count(*)::int c from public.organizations where id=$1`, [technion]);
const techRooms = await q(`select count(*)::int c from public.room_progress where org_id=$1`, [technion]);
const techAccounts = await q(`select org_id from public.profiles where id=$1`, [b1]);
const sapirIntact = await q(`select count(*)::int c from public.room_progress where org_id=$1`, [sapir]);
check("Technion org deleted", techGone.rows[0].c === 0);
check("Technion learner data purged", techRooms.rows[0].c === 0);
check("Technion accounts re-homed to internal (login survives)", techAccounts.rows[0].org_id === INTERNAL);
check("Sapir data fully intact after Technion purge", sapirIntact.rows[0].c === 2);

console.log(`\n${"═".repeat(60)}`);
console.log(fail === 0 ? `\x1b[32m✅ ALL ${pass} CHECKS PASSED — full tenant isolation verified\x1b[0m`
  : `\x1b[31m❌ ${fail} FAILURE(S), ${pass} passed\x1b[0m`);
process.exit(fail === 0 ? 0 : 1);
