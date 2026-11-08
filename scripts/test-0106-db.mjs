// 0106: Team Training is run by the organization admin only. An org instructor is no longer
// team staff (no org-wide session reads, no answer key), cannot hold or use the instructor seat,
// and keeps a player's rights when seated as one. Runs every migration in PGlite.
//
// Run: node scripts/test-0106-db.mjs
import { randomUUID } from "node:crypto";
import { freshDb } from "./lib/pgliteHarness.mjs";

let pass = 0, fail = 0;
const check = (name, cond, extra = "") => { if (cond) pass++; else fail++; console.log(`  ${cond ? "PASS" : "FAIL"} ${name}${extra ? `  (${extra})` : ""}`); };
const group = t => console.log(`\n${t}`);

const { db, q, one } = await freshDb();
const org = randomUUID(), org2 = randomUUID();
await q(`insert into public.organizations (id,name,slug,seat_limit,status,starts_at) values ($1,'College','college-0106',100,'active',now()), ($2,'Other','other-0106',100,'active',now())`, [org, org2]);
await q(`insert into public.org_codes (org_id, code, expires_at) values ($1,'CODE0106', now() + interval '1 day'), ($2,'OTHR0106', now() + interval '1 day')`, [org, org2]);
const signup = async (email, code = "CODE0106") => { const id = randomUUID(); await q(`insert into auth.users (id,email,raw_user_meta_data) values ($1,$2,$3)`, [id, email, JSON.stringify({ org_code: code })]); return id; };
const setRole = (o, u, r) => q(`update public.org_members set role = $3 where org_id = $1 and user_id = $2`, [o, u, r]);
const [adm, ins, t1, t2, owner, adm2] = [await signup("adm@x.test"), await signup("ins@x.test"), await signup("t1@x.test"), await signup("t2@x.test"), await signup("owner@x.test"), await signup("adm2@x.test", "OTHR0106")];
await setRole(org, adm, "org_admin");
await setRole(org, ins, "instructor");
await setRole(org2, adm2, "org_admin");
await q(`update public.profiles set is_platform_admin = true where id = $1`, [owner]);

async function newSession(seats) {
  const id = randomUUID();
  await q(`insert into public.team_sessions (id, org_id, created_by, company_id, status, schema_version, started_at) values ($1,$2,$3,'nexacorp','running',2, now() - interval '10 minutes')`, [id, org, adm]);
  for (const [u, r] of seats) await q(`insert into public.team_session_members (session_id, user_id, role, status, last_seen_at) values ($1,$2,$3,'active', now())`, [id, u, r]);
  await q(`insert into public.session_events (session_id, seq, type, payload, occurred_at) values ($1, 1, 'session.started', '{}', now() - interval '10 minutes')`, [id]);
  await q(`insert into public.session_injects (session_id, due_offset_ms, channel, body, expected_action, status) values ($1, 0, 'feed', '{"id":"e1"}', '{"verdict":"tp"}', 'fired')`, [id]);
  return id;
}
async function as(uid, claims, fn) {
  await db.exec("begin");
  try {
    await db.exec(`set local role authenticated; select set_config('request.jwt.claims', '${JSON.stringify({ sub: uid, role: "authenticated", org_id: org, ...claims })}', true);`);
    const r = await fn(); await db.exec("commit"); return { r, err: null };
  } catch (e) { await db.exec("rollback"); return { r: null, err: String(e.message) }; }
}
let n = 0;
const act = (ses, uid, claims, type, payload) => as(uid, claims, () => db.query(`select (public.apply_session_action(p_session => $1, p_type => $2, p_payload => $3::jsonb, p_idempotency_key => $4)).seq as seq`, [ses, type, JSON.stringify(payload), `k${++n}`]));
const seatErr = async (ses, u, role) => { try { await q(`insert into public.team_session_members (session_id, user_id, role, status) values ($1,$2,$3,'active')`, [ses, u, role]); return null; } catch (e) { return String(e.message); } };

group("1. who is team staff in the database");
{
  const s = await newSession([[adm, "instructor"], [t1, "t1"]]);
  const staffAs = async (uid, orgRole) => (await as(uid, { org_role: orgRole }, () => db.query(`select public.is_session_staff($1) v`, [s]))).r?.rows[0]?.v;
  check("an org admin is session staff", await staffAs(adm, "org_admin") === true);
  check("an org instructor is not session staff", await staffAs(ins, "instructor") === false);
  check("a token still saying org_admin after a demotion is not staff", await (async () => { await setRole(org, adm, "instructor"); const v = await staffAs(adm, "org_admin"); await setRole(org, adm, "org_admin"); return v; })() === false);
  const listAs = async (uid, orgRole) => (await as(uid, { org_role: orgRole }, () => db.query(`select count(*)::int c from public.team_sessions where id = $1`, [s]))).r?.rows[0]?.c;
  check("an org admin reads the org's session through RLS", await listAs(adm, "org_admin") === 1);
  check("an unseated org instructor no longer reads it", await listAs(ins, "instructor") === 0);
  const injAs = async (uid, orgRole) => (await as(uid, { org_role: orgRole }, () => db.query(`select count(*)::int c from public.session_injects where session_id = $1`, [s]))).r?.rows[0]?.c;
  check("an org admin reads the answer key (session_injects)", await injAs(adm, "org_admin") === 1);
  check("an org instructor cannot read the answer key", await injAs(ins, "instructor") === 0);
}

group("2. holding the instructor seat");
{
  const s = await newSession([[t1, "t1"]]);
  check("an org admin takes the instructor seat", await seatErr(s, adm, "instructor") === null);
  const e = await seatErr(s, ins, "instructor");
  check("an org instructor is refused the instructor seat", e !== null && /team_admin_only/.test(e), e ?? "");
  check("an org instructor may take a player seat (t2)", await seatErr(s, t2, "t2") === null && await seatErr(await newSession([]), ins, "t2") === null);
  let up = null; try { await q(`update public.team_session_members set role = 'instructor' where session_id = $1 and user_id = $2`, [s, t1]); } catch (x) { up = String(x.message); }
  check("a player cannot be moved into the instructor seat", up !== null && /team_admin_only/.test(up), up ?? "");
  check("the platform owner takes the seat", await seatErr(await newSession([]), owner, "instructor") === null);
  const e2 = await seatErr(await newSession([]), adm2, "instructor");
  check("an org admin of ANOTHER organization is refused", e2 !== null && /team_admin_only/.test(e2), e2 ?? "");
}

group("3. using the instructor seat");
{
  const s = await newSession([[adm, "instructor"], [t1, "t1"], [ins, "t2"]]);
  const ok = await act(s, adm, { org_role: "org_admin" }, "staff.inject", { kind: "announcement", text: "Heads up" });
  check("the org admin in the seat sends an inject", ok.err === null, ok.err ?? "");
  // A legacy seat: an org instructor who holds the instructor seat from before 0106.
  const legacy = await newSession([[t1, "t1"]]);
  await q(`alter table public.team_session_members disable trigger team_session_members_staff_seat`);
  await q(`insert into public.team_session_members (session_id, user_id, role, status, last_seen_at) values ($1,$2,'instructor','active', now())`, [legacy, ins]);
  await q(`alter table public.team_session_members enable trigger team_session_members_staff_seat`);
  const bad = await act(legacy, ins, { org_role: "instructor" }, "staff.inject", { kind: "announcement", text: "x" });
  check("an org instructor in a legacy instructor seat cannot inject", bad.err !== null && /team_admin_only/.test(bad.err), bad.err ?? "");
  check("nothing was written", Number((await one(`select count(*) c from public.session_events where session_id = $1 and type = 'staff.inject'`, [legacy])).c) === 0);
  let hb = null; try { await q(`update public.team_session_members set last_seen_at = now() where session_id = $1 and user_id = $2`, [legacy, ins]); } catch (x) { hb = String(x.message); }
  check("the legacy row still takes a heartbeat (existing rows are not broken)", hb === null, hb ?? "");
}

group("4. isolation approval override");
{
  const s = await newSession([[adm, "instructor"], [t2, "t2"]]);
  check("the org admin in the seat may approve", (await one(`select public.team_isolation_can_approve($1,$2,$3) v`, [s, adm, t2])).v === true);
  const legacy = await newSession([[t2, "t2"]]);
  await q(`alter table public.team_session_members disable trigger team_session_members_staff_seat`);
  await q(`insert into public.team_session_members (session_id, user_id, role, status, last_seen_at) values ($1,$2,'instructor','active', now())`, [legacy, ins]);
  await q(`alter table public.team_session_members enable trigger team_session_members_staff_seat`);
  check("an org instructor in a legacy instructor seat may not approve", (await one(`select public.team_isolation_can_approve($1,$2,$3) v`, [legacy, ins, t2])).v === false);
}

group("5. an org instructor seated as a player keeps a player's rights");
{
  const s = await newSession([[adm, "instructor"], [ins, "t1"]]);
  const read = await as(ins, { org_role: "instructor" }, () => db.query(`select count(*)::int c from public.team_sessions where id = $1`, [s]));
  check("reads their own session", read.r?.rows[0]?.c === 1, read.err ?? "");
  const inj = await as(ins, { org_role: "instructor" }, () => db.query(`select count(*)::int c from public.session_injects where session_id = $1`, [s]));
  check("still no answer key", inj.r?.rows[0]?.c === 0, inj.err ?? "");
  const disp = await act(s, ins, { org_role: "instructor" }, "staff.inject", { kind: "announcement", text: "x" });
  check("cannot send a staff inject from a t1 seat", disp.err !== null && /action_not_allowed/.test(disp.err), disp.err ?? "");
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
