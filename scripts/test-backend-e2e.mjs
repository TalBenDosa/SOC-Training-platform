// Backend E2E test — exercises the WHOLE database backend (schema, RLS,
// functions, triggers, guards, enrollment, XP recompute, licensing, purge)
// against the real migrations in an in-memory Postgres (PGlite), with thin
// Supabase-auth shims. Complements scripts/test-multitenancy-local.mjs (which
// focuses on the two-college isolation scenario).
//
// Run: node scripts/test-backend-e2e.mjs   (no Docker/Supabase needed)
import { PGlite } from "@electric-sql/pglite";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";
import { randomUUID } from "node:crypto";

const MIG = join(dirname(fileURLToPath(import.meta.url)), "..", "supabase", "migrations");
const INTERNAL = "d0d0d0d0-0000-4000-8000-000000000000";
let pass = 0, fail = 0; const failures = [];
function check(name, cond, extra = "") {
  if (cond) { pass++; } else { fail++; failures.push(name + (extra ? ` — ${extra}` : "")); }
  console.log(`  ${cond ? "✅" : "❌"} ${name}${extra ? `  (${extra})` : ""}`);
}
function group(t) { console.log(`\n\x1b[1m${t}\x1b[0m`); }

const SHIM = `
create schema if not exists auth;
create table if not exists auth.users (id uuid primary key default gen_random_uuid(), email text, raw_user_meta_data jsonb default '{}', raw_app_meta_data jsonb default '{}', created_at timestamptz default now());
create or replace function auth.uid() returns uuid language sql stable as $f$ select nullif(current_setting('request.jwt.claims',true)::jsonb->>'sub','')::uuid $f$;
create or replace function auth.jwt() returns jsonb language sql stable as $f$ select coalesce(nullif(current_setting('request.jwt.claims',true),'')::jsonb,'{}') $f$;
do $d$ begin if not exists(select from pg_roles where rolname='anon') then create role anon; end if; if not exists(select from pg_roles where rolname='authenticated') then create role authenticated; end if; if not exists(select from pg_roles where rolname='supabase_auth_admin') then create role supabase_auth_admin; end if; if not exists(select from pg_roles where rolname='service_role') then create role service_role; end if; end $d$;
grant usage on schema public, auth to anon, authenticated, service_role, supabase_auth_admin;
alter default privileges in schema public grant select, insert, update, delete on tables to authenticated, anon;
alter default privileges in schema public grant execute on functions to anon, authenticated;
create or replace function public.uuid_generate_v4() returns uuid language sql as $f$ select gen_random_uuid() $f$;`;

const db = new PGlite();
await db.exec(SHIM);
for (const f of readdirSync(MIG).filter(f => f.endsWith(".sql")).sort()) {
  await db.exec(readFileSync(join(MIG, f), "utf8").replace(/create extension[^;]*;/gi, ""));
}
const q = (sql, p = []) => db.query(sql, p);
const one = async (sql, p = []) => (await q(sql, p)).rows[0];

// helpers
async function makeOrg(name, seats, opts = {}) {
  const id = randomUUID();
  await q(`insert into public.organizations (id,name,slug,seat_limit,status,starts_at,expires_at,allowed_domains) values ($1,$2,$3,$4,$5,now(),$6,$7)`,
    [id, name, name.toLowerCase().replace(/[^a-z0-9]+/g, "-") + "-" + id.slice(0, 4), seats, opts.status ?? "active", opts.expires ?? null, opts.domains ?? []]);
  return id;
}
const ISO = ms => new Date(Date.now() + ms).toISOString();
async function invite(org, role = "student", opts = {}) {
  const token = randomUUID();
  const expires = opts.expires ?? ISO(14 * 864e5);
  // 0029: student invitations must NAME their recipient (email) — the
  // anonymous class-link shape is rejected by the trigger. Staff invites may
  // stay generic. Pass opts.email for any student invite that will be redeemed.
  await q(`insert into public.invitations (org_id,role,email,token,expires_at,accepted_at) values ($1,$2,$3,$4,$5,$6)`,
    [org, role, opts.email ?? null, token, expires, opts.accepted ?? null]);
  return token;
}
async function signup(email, meta = {}) {
  const uid = randomUUID();
  await q(`insert into auth.users (id,email,raw_user_meta_data) values ($1,$2,$3)`, [uid, email, JSON.stringify(meta)]);
  return uid;
}
async function claims(uid) {
  const r = await one(`select public.custom_access_token_hook(jsonb_build_object('user_id',$1::text,'claims',jsonb_build_object('sub',$1::text))) e`, [uid]);
  return r.e.claims;
}
async function asUser(uid, fn) {
  const c = await claims(uid);
  await q(`select set_config('request.jwt.claims',$1,false)`, [JSON.stringify(c)]);
  await db.exec(`set role authenticated`);
  try { return await fn(c); } finally { await db.exec(`reset role`); await q(`select set_config('request.jwt.claims','{}',false)`); }
}

// ═══════════════════════════════════════════════════════════════════════════
group("A) Schema & RLS enablement");
const tenantTables = ["profiles", "user_progress", "room_progress", "dashboard_sessions", "scenario_history", "ai_usage", "organizations", "org_members", "invitations", "audit_log"];
for (const t of tenantTables) {
  const r = await one(`select relrowsecurity rls from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname=$1`, [t]);
  check(`RLS enabled on ${t}`, r?.rls === true);
}
for (const t of ["profiles", "user_progress", "room_progress", "dashboard_sessions", "scenario_history", "organizations", "org_members"]) {
  const r = await one(`select count(*)::int n from pg_policies where schemaname='public' and tablename=$1`, [t]);
  check(`${t} has RLS policies`, (r?.n ?? 0) >= 1, `${r?.n} policies`);
}
const orgIdCols = await q(`select table_name from information_schema.columns where table_schema='public' and column_name='org_id' and table_name = any($1)`, [tenantTables]);
check("org_id present on all core per-tenant tables", orgIdCols.rows.length >= 7, `${orgIdCols.rows.length} tables`);

// ═══════════════════════════════════════════════════════════════════════════
group("B) Functions");
check("handle_available rejects reserved 'admin'", (await one(`select public.handle_available('admin') v`)).v === false);
check("handle_available rejects too-short 'ab'", (await one(`select public.handle_available('ab') v`)).v === false);
check("handle_available accepts a fresh handle", (await one(`select public.handle_available('brand_new_handle') v`)).v === true);

// 0028 closed open signup: every harness user now needs a real entry door.
// One shared harness org + one multi-use affiliation code covers all the
// throwaway accounts below — which also exercises, for free, that a code is
// usable by MANY students inside its 24h window (it is a class code, not a
// one-shot invite).
const harnessOrg = await makeOrg("Harness Co", 50);
await q(`insert into public.org_codes (org_id, code) values ($1, 'HARNESS9')`, [harnessOrg]);
const HARNESS = { org_code: "HARNESS9" };

const capOrg = await makeOrg("Cap Co", 1);
const capU1 = await signup("cap1@x.io", HARNESS);
await q(`select public.attach_member_if_seat_available($1,$2,'student')`, [capOrg, capU1]);
check("attach: first member fills the single seat", (await one(`select count(*)::int n from public.org_members where org_id=$1 and status='active'`, [capOrg])).n === 1);
const capU2 = await signup("cap2@x.io", HARNESS);
let capErr = null; try { await q(`select public.attach_member_if_seat_available($1,$2,'student')`, [capOrg, capU2]); } catch (e) { capErr = e.message; }
check("attach: beyond seat limit raises seat_limit_reached", /seat_limit_reached/.test(capErr ?? ""));
check("attach: re-adding an existing member returns 'updated' (no seat)", (await one(`select public.attach_member_if_seat_available($1,$2,'instructor') v`, [capOrg, capU1])).v === "updated");

const emailU = await signup("findme@college.ac.il", HARNESS);
check("find_user_id_by_email resolves a real email", (await one(`select public.find_user_id_by_email('findme@college.ac.il') v`)).v === emailU);
check("find_user_id_by_email returns null for unknown", (await one(`select public.find_user_id_by_email('nobody@nowhere.io') v`)).v === null);

const invOrg = await makeOrg("Inv Co", 50);
const tokValid = await invite(invOrg, "student");
check("resolve_invitation: valid token → valid=true + org name", (await one(`select valid from public.resolve_invitation($1)`, [tokValid])).valid === true);
await q(`update public.invitations set expires_at = now() - interval '1 day' where token=$1`, [tokValid]);
check("resolve_invitation: expired token → valid=false", (await one(`select valid from public.resolve_invitation($1)`, [tokValid])).valid === false);

const expOrg = await makeOrg("Exp Co", 10, { expires: ISO(-864e5) });
const expiredCount = (await one(`select public.expire_due_orgs() v`)).v;
check("expire_due_orgs flips a past-due org to 'expired'", (await one(`select status from public.organizations where id=$1`, [expOrg])).status === "expired", `returned ${expiredCount}`);

// ═══════════════════════════════════════════════════════════════════════════
group("C) Triggers");
// enrollment via invite token
const enrOrg = await makeOrg("Enroll Co", 50);
const enrTok = await invite(enrOrg, "student", { email: "student1@x.io" });
const enrU = await signup("student1@x.io", { invitation_token: enrTok, handle: "student1" });
check("handle_new_user: invite token assigns the right org", (await one(`select org_id from public.profiles where id=$1`, [enrU])).org_id === enrOrg);
check("handle_new_user: invite marked accepted", (await one(`select accepted_at is not null a from public.invitations where token=$1`, [enrTok])).a === true);
// 0028 REVERSED two old behaviors, and these checks pin the reversal so a
// revert of the migration fails loudly here:
//   - a matching email domain used to auto-enroll → now it does NOT bypass the
//     code requirement (the allowlist path was removed);
//   - "no signal → internal org" used to be the default → now open signup
//     RAISES signup_requires_code.
const domOrg = await makeOrg("Domain Co", 50, { domains: ["sapir.ac.il"] });
let domErr = null; try { await signup("dana@sapir.ac.il", { handle: "dana_d" }); } catch (e) { domErr = e.message; }
check("handle_new_user: matching domain NO LONGER bypasses the code requirement", /signup_requires_code/.test(domErr ?? ""), domErr ?? "signup succeeded");
void domOrg; // the org exists precisely to prove its domain no longer admits anyone
let defErr = null; try { await signup("random@gmail.com", { handle: "randomguy" }); } catch (e) { defErr = e.message; }
check("handle_new_user: open signup (no code, no invite) is refused", /signup_requires_code/.test(defErr ?? ""), defErr ?? "signup succeeded");
// invite to a full org → signup fails
const fullOrg = await makeOrg("Full Co", 1);
await q(`select public.attach_member_if_seat_available($1,$2,'student')`, [fullOrg, await signup("seat@x.io", HARNESS)]);
const fullTok = await invite(fullOrg, "student", { email: "late@x.io" });
let fullErr = null; try { await signup("late@x.io", { invitation_token: fullTok }); } catch (e) { fullErr = e.message; }
check("handle_new_user: invite to a FULL org fails the signup", /seat_limit_reached/.test(fullErr ?? ""));

// XP recompute trigger
const xpU = await signup("xp@x.io", { ...HARNESS, handle: "xpuser" });
await q(`insert into public.room_progress (user_id,org_id,room_id,completed_task_ids,xp_earned,completed_at) values ($1,$2,'r1','[]',150, now())`, [xpU, INTERNAL]);
check("recompute_user_xp: room XP reflected in profiles.xp", (await one(`select xp from public.profiles where id=$1`, [xpU])).xp === 150);
await q(`insert into public.scenario_history (user_id,org_id,slug,title,score,xp_earned,time_taken,completed_at) values ($1,$2,'s1','S',90,50,120, now())`, [xpU, INTERNAL]);
check("recompute_user_xp: scenario XP adds up (150+50=200)", (await one(`select xp from public.profiles where id=$1`, [xpU])).xp === 200);

// guard trigger: user cannot escalate own privileged columns
await asUser(xpU, async () => {
  await q(`update public.profiles set role='admin', is_platform_admin=true, org_id=$1 where id=$2`, [enrOrg, xpU]);
});
const guarded = await one(`select role, is_platform_admin, org_id from public.profiles where id=$1`, [xpU]);
check("guard: user cannot self-set role='admin'", guarded.role !== "admin");
check("guard: user cannot self-set is_platform_admin", guarded.is_platform_admin === false);
// xpU joined via the harness code (0028 closed the internal-org default), so
// "didn't move" now means "still in harnessOrg" — the guard's actual promise
// is that the self-update to enrOrg did not stick.
check("guard: user cannot move own org_id", guarded.org_id === harnessOrg && guarded.org_id !== enrOrg);

// touch_updated_at
const before = (await one(`select updated_at from public.user_progress where user_id=$1`, [xpU]))?.updated_at;
await q(`update public.user_progress set cleared_companies='["x"]' where user_id=$1`, [xpU]);
const after = (await one(`select updated_at from public.user_progress where user_id=$1`, [xpU]))?.updated_at;
check("touch_updated_at bumps updated_at on write", before && after && new Date(after) >= new Date(before));

// ═══════════════════════════════════════════════════════════════════════════
group("D) RLS isolation (2 orgs)");
const A = await makeOrg("College A", 50), B = await makeOrg("College B", 50);
const aTok = await invite(A, "student", { email: "a1@x.io" }), bTok = await invite(B, "student", { email: "b1@x.io" });
const a1 = await signup("a1@x.io", { invitation_token: aTok, handle: "a1" });
const b1 = await signup("b1@x.io", { invitation_token: bTok, handle: "b1" });
await q(`insert into public.room_progress (user_id,org_id,room_id,completed_task_ids,xp_earned) values ($1,$2,'r','[]',10)`, [a1, A]);
await q(`insert into public.room_progress (user_id,org_id,room_id,completed_task_ids,xp_earned) values ($1,$2,'r','[]',10)`, [b1, B]);
await asUser(a1, async () => {
  check("A sees only its own room_progress", (await q(`select org_id from public.room_progress`)).rows.every(r => r.org_id === A));
  check("A cannot read B's row", (await one(`select count(*)::int n from public.room_progress where user_id=$1`, [b1])).n === 0);
  check("A sees only its own organization", (await q(`select id from public.organizations`)).rows.every(r => r.id === A));
  check("A sees only its own org_members", (await q(`select distinct org_id from public.org_members`)).rows.every(r => r.org_id === A));
  let w = false; try { await q(`insert into public.room_progress (user_id,org_id,room_id,completed_task_ids,xp_earned) values ($1,$2,'evil','[]',1)`, [a1, B]); } catch { w = true; }
  check("A cannot WRITE into B (WITH CHECK)", w);
  check("A cannot read invitations (deny-all client)", (await q(`select * from public.invitations`).catch(() => ({ rows: [] }))).rows.length === 0);
  check("A cannot read audit_log (deny-all client)", (await q(`select * from public.audit_log`).catch(() => ({ rows: [] }))).rows.length === 0);
});

// ═══════════════════════════════════════════════════════════════════════════
group("E) purge_org completeness");
const P = await makeOrg("Purge Co", 50);
const pTok = await invite(P, "student", { email: "pu@x.io" });
const pu = await signup("pu@x.io", { invitation_token: pTok, handle: "pu" });
await q(`insert into public.room_progress (user_id,org_id,room_id,completed_task_ids,xp_earned) values ($1,$2,'r','[]',10)`, [pu, P]);
await q(`insert into public.dashboard_sessions (user_id,org_id,played_at,xp_earned,detect_rate,avg_catch_ms,attacks_caught_count,attacks_presented_count) values ($1,$2,now(),5,50,1000,1,2)`, [pu, P]);
await q(`select public.purge_org($1)`, [P]);
check("purge_org: org deleted", (await one(`select count(*)::int n from public.organizations where id=$1`, [P])).n === 0);
check("purge_org: room_progress cleared", (await one(`select count(*)::int n from public.room_progress where org_id=$1`, [P])).n === 0);
check("purge_org: dashboard_sessions cleared", (await one(`select count(*)::int n from public.dashboard_sessions where org_id=$1`, [P])).n === 0);
check("purge_org: invitations cleared", (await one(`select count(*)::int n from public.invitations where org_id=$1`, [P])).n === 0);
check("purge_org: account re-homed to internal (login survives)", (await one(`select org_id from public.profiles where id=$1`, [pu])).org_id === INTERNAL);
let purgeInternal = null; try { await q(`select public.purge_org($1)`, [INTERNAL]); } catch (e) { purgeInternal = e.message; }
check("purge_org refuses to delete the internal org", /cannot_purge_internal/.test(purgeInternal ?? ""));

// ═══════════════════════════════════════════════════════════════════════════
group("F) Licensing (hook claims)");
const susOrg = await makeOrg("Suspended Co", 50, { status: "suspended" });
const susTok = await invite(susOrg, "student", { email: "sus@x.io" });
const susU = await signup("sus@x.io", { invitation_token: susTok, handle: "susu" });
check("suspended org → hook org_active=false", (await claims(susU)).org_active === false);
const okOrg = await makeOrg("Active Co", 50);
const okTok = await invite(okOrg, "student", { email: "ok@x.io" });
const okU = await signup("ok@x.io", { invitation_token: okTok, handle: "okok" });
const okC = await claims(okU);
check("active org → org_active=true + org_name + org_role", okC.org_active === true && okC.org_name === "Active Co" && okC.org_role === "student");

// ═══════════════════════════════════════════════════════════════════════════
group("G) Security-audit fixes (0016)");
// C1 — leaderboard view must not exist (anon/cross-tenant leak).
check("C1: leaderboard view removed", (await one(`select to_regclass('public.leaderboard') v`)).v === null);
// H1 — 0001 content tables: either dropped (0015) or RLS-enabled with grants revoked.
for (const t of ["learning_paths", "modules", "lessons", "scenarios", "badges"]) {
  const r = await one(`select relrowsecurity rls from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relname=$1`, [t]);
  check(`H1: ${t} locked down (dropped or RLS on)`, r === undefined || r.rls === true, r === undefined ? "dropped" : `rls=${r.rls}`);
}
// M3 — a student sees only their OWN org_members row, not the whole roster.
const rOrg = await makeOrg("Roster Co", 50);
const rTok1 = await invite(rOrg, "student", { email: "rs1@x.io" }), rTok2 = await invite(rOrg, "student", { email: "rs2@x.io" });
const rStudent = await signup("rs1@x.io", { invitation_token: rTok1, handle: "rs1" });
await signup("rs2@x.io", { invitation_token: rTok2, handle: "rs2" }); // classmate
await asUser(rStudent, async () => {
  const rows = (await q(`select user_id from public.org_members`)).rows;
  check("M3: student sees only own membership row", rows.length === 1 && rows[0].user_id === rStudent, `${rows.length} rows`);
});
// M2 — reactivating a removed member into a now-full org is refused.
const m2Org = await makeOrg("Reactivate Co", 1);
const m2u1 = await signup("m2a@x.io", HARNESS), m2u2 = await signup("m2b@x.io", HARNESS);
await q(`select public.attach_member_if_seat_available($1,$2,'student')`, [m2Org, m2u1]); // fills the 1 seat
await q(`update public.org_members set status='removed' where org_id=$1 and user_id=$2`, [m2Org, m2u1]); // frees it
await q(`select public.attach_member_if_seat_available($1,$2,'student')`, [m2Org, m2u2]); // re-fills the seat
let m2Err = null; try { await q(`select public.attach_member_if_seat_available($1,$2,'student')`, [m2Org, m2u1]); } catch (e) { m2Err = e.message; }
check("M2: reactivation into a full org raises seat_limit_reached", /seat_limit_reached/.test(m2Err ?? ""));
// H2 — purge_org succeeds even when the org has audit_log rows.
const h2Org = await makeOrg("Audit Purge Co", 50);
await q(`insert into public.audit_log (org_id, action) values ($1,'org.create')`, [h2Org]);
let h2Err = null; try { await q(`select public.purge_org($1)`, [h2Org]); } catch (e) { h2Err = e.message; }
check("H2: purge_org clears an org that has audit_log rows", h2Err === null && (await one(`select count(*)::int n from public.organizations where id=$1`, [h2Org])).n === 0, h2Err ?? "");
check("H2: audit_log row survives purge (org_id nulled)", (await one(`select count(*)::int n from public.audit_log where action='org.create' and org_id is null`)).n >= 1);

// ═══════════════════════════════════════════════════════════════════════════
group("H) Right-to-deletion queue (0027)");
// The properties asserted here are the ones the API relies on but cannot prove
// about itself: that a request is visible ONLY to its subject and their own
// college, and that erasing the person really does erase the request. If the
// cascade were missing, an approved deletion would leave an orphan row naming
// someone who no longer exists — personal data surviving its own deletion.
const dOrgA = await makeOrg("Deletion College A", 50);
const dOrgB = await makeOrg("Deletion College B", 50);
const dStudent = await signup("del-s1@x.io", { invitation_token: await invite(dOrgA, "student", { email: "del-s1@x.io" }), handle: "dels1" });
const dMate    = await signup("del-s2@x.io", { invitation_token: await invite(dOrgA, "student", { email: "del-s2@x.io" }), handle: "dels2" });
const dOtherA  = await signup("del-o1@x.io", { invitation_token: await invite(dOrgB, "student", { email: "del-o1@x.io" }), handle: "delo1" });
await q(`update public.org_members set role='org_admin' where org_id=$1 and user_id=$2`, [dOrgB, dOtherA]);

await q(
  `insert into public.account_deletion_requests (user_id, org_id, reason) values ($1,$2,'leaving the course')`,
  [dStudent, dOrgA],
);

// One open request per person — a double click must not create a second row.
let dupErr = null;
try {
  await q(`insert into public.account_deletion_requests (user_id, org_id) values ($1,$2)`, [dStudent, dOrgA]);
} catch (e) { dupErr = e.message; }
check("0027: a second open request for the same user is refused", dupErr !== null);

await asUser(dStudent, async () => {
  const rows = (await q(`select id from public.account_deletion_requests`)).rows;
  check("0027: subject sees their own request", rows.length === 1, `${rows.length} rows`);
});

await asUser(dMate, async () => {
  const rows = (await q(`select id from public.account_deletion_requests`)).rows;
  check("0027: a classmate sees nothing", rows.length === 0, `${rows.length} rows`);
});

// The cross-tenant case: an org_admin of a DIFFERENT college must not see it.
await asUser(dOtherA, async () => {
  const rows = (await q(`select id from public.account_deletion_requests`)).rows;
  check("0027: another college's admin sees nothing", rows.length === 0, `${rows.length} rows`);
});

// No client role may decide a request — approving one erases an account, so it
// must stay a service-role operation behind the API guard.
// Note the failure MODE: this raises `permission denied`, it does not quietly
// update zero rows. The table's UPDATE grant is revoked outright, so the
// statement is rejected before RLS is ever consulted — a strictly stronger
// guarantee than a policy that filters the row set, and worth pinning as such.
await asUser(dStudent, async () => {
  let updErr = null;
  try {
    await q(`update public.account_deletion_requests set status='completed' where user_id=$1`, [dStudent]);
  } catch (e) { updErr = e.message; }
  check("0027: subject cannot self-approve (grant revoked, not just filtered)", /permission denied/i.test(updErr ?? ""), updErr ?? "no error raised");
});

// The cascade: deleting the profile must take the request with it.
await q(`delete from public.profiles where id=$1`, [dStudent]);
check(
  "0027: request cascades away when the account is deleted",
  (await one(`select count(*)::int n from public.account_deletion_requests where user_id=$1`, [dStudent])).n === 0,
);

// ═══════════════════════════════════════════════════════════════════════════
group("I) Org affiliation codes (0028)");
// The student entry model: email + class code, 24h code window, 100-day
// affiliation, same-org-only renewal. Each check pins a rule the API relies on
// but cannot prove about itself.
const iOrgA = await makeOrg("Code College A", 50);
const iOrgB = await makeOrg("Code College B", 50);
await q(`insert into public.org_codes (org_id, code) values ($1, 'AAACODE7')`, [iOrgA]);
await q(`insert into public.org_codes (org_id, code) values ($1, 'BBBCODE7')`, [iOrgB]);

// Sloppy input (lowercase, padded) must still land in the right org — the code
// is typed off a projector, and case-sensitivity would generate support load.
const iStu = await signup("code-stu@x.io", { org_code: "  aaacode7 ", handle: "codestu" });
check("0028: sloppy-cased code joins the right org", (await one(`select org_id from public.profiles where id=$1`, [iStu])).org_id === iOrgA);
const iAff = (await one(`select affiliation_expires_at from public.org_members where user_id=$1 and org_id=$2`, [iStu, iOrgA])).affiliation_expires_at;
const iDays = (new Date(iAff).getTime() - Date.now()) / 86_400_000;
check("0028: code-joined student carries a ~100-day affiliation clock", iDays > 99 && iDays < 101, `${iDays.toFixed(1)} days`);

// Expired code → refused with the named error.
await q(`update public.org_codes set expires_at = now() - interval '1 minute' where code = 'BBBCODE7'`);
let iExpErr = null; try { await signup("code-late@x.io", { org_code: "BBBCODE7" }); } catch (e) { iExpErr = e.message; }
check("0028: an expired code refuses signup (org_code_invalid)", /org_code_invalid/.test(iExpErr ?? ""), iExpErr ?? "signup succeeded");

// Renewal: same org resets the clock; another org's code must NOT move a
// student between tenants through the renewal door.
await q(`update public.org_members set affiliation_expires_at = now() - interval '1 day' where user_id=$1`, [iStu]);
await q(`select public.renew_affiliation($1, 'AAACODE7')`, [iStu]);
const iRenewed = (await one(`select affiliation_expires_at from public.org_members where user_id=$1 and org_id=$2`, [iStu, iOrgA])).affiliation_expires_at;
check("0028: renewal with the org's own code resets the 100-day clock", new Date(iRenewed).getTime() > Date.now() + 99 * 86_400_000);
await q(`update public.org_codes set expires_at = now() + interval '1 hour' where code = 'BBBCODE7'`);
let iWrongErr = null; try { await q(`select public.renew_affiliation($1, 'BBBCODE7')`, [iStu]); } catch (e) { iWrongErr = e.message; }
check("0028: renewal with ANOTHER org's code is refused (org_code_wrong_org)", /org_code_wrong_org/.test(iWrongErr ?? ""), iWrongErr ?? "renewal succeeded");

// RLS: an org admin reads their own org's codes; a student reads none; an
// admin of another org reads none of A's.
const iAdmTokA = await invite(iOrgA, "org_admin");
const iAdmA = await signup("code-adm-a@x.io", { invitation_token: iAdmTokA, handle: "codeadma" });
await asUser(iAdmA, async () => {
  const rows = (await q(`select code from public.org_codes`)).rows;
  check("0028 RLS: org admin sees own org's codes only", rows.length === 1 && rows[0].code === "AAACODE7", `${rows.length} rows`);
});
await asUser(iStu, async () => {
  const rows = (await q(`select code from public.org_codes`)).rows;
  check("0028 RLS: a student sees no codes", rows.length === 0, `${rows.length} rows`);
});

// 0029: the anonymous class-link shape is dead — a generic student invite is
// refused even with a valid unexpired token, while NAMED student invites keep
// working (proven by every student signup above). A revert of 0029 fails here.
const genTok = await invite(iOrgA, "student"); // email deliberately null
let genErr = null; try { await signup("generic-victim@x.io", { invitation_token: genTok }); } catch (e) { genErr = e.message; }
check("0029: generic (email-less) student invite is refused", /student_invite_requires_code/.test(genErr ?? ""), genErr ?? "signup succeeded");

console.log(`\n${"═".repeat(64)}`);
if (fail === 0) console.log(`\x1b[32m✅ BACKEND E2E: ALL ${pass} CHECKS PASSED\x1b[0m`);
else { console.log(`\x1b[31m❌ BACKEND E2E: ${fail} FAILURE(S), ${pass} passed\x1b[0m`); failures.forEach(f => console.log("   - " + f)); }
process.exit(fail === 0 ? 0 : 1);
