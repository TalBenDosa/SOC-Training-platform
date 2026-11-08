// Team Training 0107: an isolation is approved by the senior on shift. The SOC Manager (or
// Lead) when one is on shift, else the Tier-3, else the exercise admin; a senior Tier-3's own request
// is approved at once; the exercise admin may always answer, whoever is on shift.
// Runs every migration in PGlite (no Docker / Supabase needed).
//
// Run: node scripts/test-0107-db.mjs
import { randomUUID } from "node:crypto";
import { freshDb } from "./lib/pgliteHarness.mjs";

let pass = 0, fail = 0; const failures = [];
function check(name, cond, extra = "") {
  if (cond) pass++; else { fail++; failures.push(name + (extra ? ` (${extra})` : "")); }
  console.log(`  ${cond ? "PASS" : "FAIL"} ${name}${extra ? `  (${extra})` : ""}`);
}
const group = t => console.log(`\n${t}`);

const { db, q, one } = await freshDb();
const org = randomUUID();
await q(`insert into public.organizations (id,name,slug,seat_limit,status,starts_at) values ($1,'College','college-0107',100,'active',now())`, [org]);
await q(`insert into public.org_codes (org_id, code, expires_at) values ($1,'CODE0107', now() + interval '1 day')`, [org]);
const signup = async email => { const id = randomUUID(); await q(`insert into auth.users (id,email,raw_user_meta_data) values ($1,$2,$3)`, [id, email, JSON.stringify({ org_code: "CODE0107" })]); return id; };
const [t2, t3, t3b, mgr, lead, ins] = [await signup("t2@x.test"), await signup("t3@x.test"), await signup("t3b@x.test"), await signup("mgr@x.test"), await signup("lead@x.test"), await signup("ins@x.test")];
await q(`update public.org_members set role = 'org_admin' where org_id = $1 and user_id = $2`, [org, ins]);

async function newSession(seats) {
  const id = randomUUID();
  await q(`insert into public.team_sessions (id, org_id, created_by, company_id, status, schema_version, started_at) values ($1,$2,$3,'nexacorp','running',2, now() - interval '10 minutes')`, [id, org, ins]);
  for (const [u, r, stale] of seats) await q(`insert into public.team_session_members (session_id, user_id, role, status, last_seen_at) values ($1,$2,$3,'active', now() - ($4 || ' seconds')::interval)`, [id, u, r, stale ? "600" : "0"]);
  await q(`insert into public.session_events (session_id, seq, type, payload, occurred_at) values ($1, 1, 'session.started', '{}', now() - interval '10 minutes')`, [id]);
  return id;
}
async function asUserCommit(uid, fn) {
  await db.exec("begin");
  try {
    await db.exec(`set local role authenticated; select set_config('request.jwt.claims', '${JSON.stringify({ sub: uid, role: "authenticated", org_id: org })}', true);`);
    const r = await fn(); await db.exec("commit"); return r;
  } catch (e) { await db.exec("rollback"); throw e; }
}
let n = 0;
async function act(ses, uid, type, payload) {
  try {
    const r = await asUserCommit(uid, () => db.query(`select (public.apply_session_action(p_session => $1, p_type => $2, p_payload => $3::jsonb, p_idempotency_key => $4)).seq as seq`, [ses, type, JSON.stringify(payload), `k${++n}`]));
    return { seq: Number(r.rows[0]?.seq), err: null };
  } catch (e) { return { seq: null, err: String(e.message) }; }
}
const evs = async (ses, type) => (await q(`select seq, type, actor_id, role, payload from public.session_events where session_id=$1 and type=$2 order by seq`, [ses, type])).rows;
const tier = async (ses, actor = null) => (await one(`select public.team_isolation_senior_tier($1,$2) t`, [ses, actor])).t;
let hostN = 0;
const ask = (ses, uid) => act(ses, uid, "isolation.requested", { host: `WS-0107-${++hostN}`, reason: "beacon to a known C2" });

group("1. a SOC Manager on shift: only the Manager answers");
{
  const s = await newSession([[t2, "t2"], [t3, "t3"], [mgr, "mgr"], [ins, "instructor"]]);
  check("the senior tier is the Manager", (await tier(s)) === "mgr");
  const r = await ask(s, t2);
  check("Tier-2 asks", r.err === null, r.err ?? "");
  const byT3 = await act(s, t3, "isolation.approved", { request_seq: r.seq });
  check("Tier-3 cannot approve while the Manager is on shift", /not_approver/.test(byT3.err ?? ""), byT3.err ?? "accepted");
  const byMgr = await act(s, mgr, "isolation.approved", { request_seq: r.seq });
  check("the Manager approves", byMgr.err === null, byMgr.err ?? "");
  const iso = (await evs(s, "edr.host_isolated")).at(-1);
  check("isolated, approved_by = the Manager", iso?.payload.approved_by === mgr && iso?.payload.approver_role === "mgr", JSON.stringify(iso?.payload));

  const r2 = await ask(s, t3);
  const auto = (await evs(s, "isolation.approved")).find(e => e.payload.request_seq === r2.seq);
  check("a Tier-3 request waits for the Manager (not auto-approved)", r2.err === null && !auto, r2.err ?? "auto-approved");
  const self = await act(s, t3, "isolation.approved", { request_seq: r2.seq });
  check("the Tier-3 cannot approve their own request under a Manager", /not_approver/.test(self.err ?? ""), self.err ?? "accepted");
  const den = await act(s, mgr, "isolation.denied", { request_seq: r2.seq, reason: "capture memory first" });
  check("the Manager denies", den.err === null, den.err ?? "");
  const r3 = await ask(s, t2);
  const byIns = await act(s, ins, "isolation.approved", { request_seq: r3.seq });
  check("the exercise admin may always answer, even with the Manager on shift", byIns.err === null, byIns.err ?? "");
}

group("2. a Lead counts as the Manager rung");
{
  const s = await newSession([[t2, "t2"], [t3, "t3"], [lead, "lead"]]);
  check("the senior tier is the Lead", (await tier(s)) === "mgr");
  const r = await ask(s, t3);
  check("a Tier-3 request waits for the Lead", (await evs(s, "isolation.approved")).length === 0);
  check("the Lead approves", (await act(s, lead, "isolation.approved", { request_seq: r.seq })).err === null);
}

group("3. no Manager on shift: the Tier-3 is the shift senior");
{
  const s = await newSession([[t2, "t2"], [t3, "t3"], [t3b, "t3"], [mgr, "mgr", true], [ins, "instructor"]]);
  check("a Manager seated but offline does not count", (await tier(s)) === "t3");
  const r = await ask(s, t2);
  const byT3 = await act(s, t3, "isolation.approved", { request_seq: r.seq });
  check("the Tier-3 approves a Tier-2 request", byT3.err === null, byT3.err ?? "");

  const r2 = await ask(s, t3b);
  const auto = (await evs(s, "isolation.approved")).find(e => e.payload.request_seq === r2.seq);
  check("the senior Tier-3's own request is approved at once", r2.err === null && auto?.actor_id === t3b && auto?.role === "t3" && auto?.payload.auto === "shift_senior", r2.err ?? JSON.stringify(auto));
  const iso = (await evs(s, "edr.host_isolated")).find(e => e.payload.request_seq === r2.seq);
  check("and the host is isolated (actor and approver = that Tier-3)", iso?.actor_id === t3b && iso?.payload.approved_by === t3b, JSON.stringify(iso?.payload));
  const again = await act(s, t3, "isolation.approved", { request_seq: r2.seq });
  check("the auto-approved request is closed", /no_open_request/.test(again.err ?? ""), again.err ?? "accepted");
  const t2self = await act(s, t2, "isolation.approved", { request_seq: r.seq });
  check("a Tier-2 can never approve", /action_not_allowed|not_approver|no_open_request/.test(t2self.err ?? ""), t2self.err ?? "accepted");

  const rI = await ask(s, t2);
  const insDen = await act(s, ins, "isolation.denied", { request_seq: rI.seq, reason: "wait for the memory capture" });
  check("the exercise admin may always answer, with a Tier-3 on shift too", insDen.err === null, insDen.err ?? "");

  // The Manager comes back online: the Manager is the senior again, the Tier-3 waits.
  await q(`update public.team_session_members set last_seen_at = now() where session_id=$1 and user_id=$2`, [s, mgr]);
  const r3 = await ask(s, t3);
  check("Manager back: a Tier-3 request waits again", !(await evs(s, "isolation.approved")).some(e => e.payload.request_seq === r3.seq));
}

group("4. nobody senior on shift: the exercise admin is the fallback");
{
  const s = await newSession([[t2, "t2"], [t3, "t3", true], [ins, "instructor"]]);
  check("an offline Tier-3 does not count", (await tier(s)) === "staff");
  const r = await ask(s, t2);
  const byIns = await act(s, ins, "isolation.approved", { request_seq: r.seq });
  check("the exercise admin approves", byIns.err === null, byIns.err ?? "");
  // The Tier-3 comes back and acts: acting counts as active, so they are the senior.
  const r2 = await ask(s, t2);
  const byT3 = await act(s, t3, "isolation.approved", { request_seq: r2.seq });
  check("the Tier-3 who acts counts as on shift and approves", byT3.err === null, byT3.err ?? "");
}

group("5. grants");
{
  for (const fn of ["team_isolation_senior_tier(uuid,uuid)", "team_isolation_can_approve(uuid,uuid,uuid)", "team_isolation_auto_approve()"]) {
    const can = (await one(`select has_function_privilege('authenticated', 'public.${fn}', 'execute') as can`)).can;
    check(`clients cannot call ${fn.split("(")[0]}`, can === false);
  }
}

console.log(`\n${pass} passed, ${fail} failed`);
if (fail) { console.log(failures.map(f => `  - ${f}`).join("\n")); process.exit(1); }
