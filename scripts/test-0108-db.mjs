// Team Training 0108: a containment request (disable an account, ...) is answered by the senior
// on shift (SOC Manager / Lead, else Tier-3) or the exercise admin, always; a senior Tier-3's own
// request is approved at once; the exercise admin may isolate a host themselves.
// Runs every migration in PGlite (no Docker / Supabase needed).
//
// Run: node scripts/test-0108-db.mjs
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
await q(`insert into public.organizations (id,name,slug,seat_limit,status,starts_at) values ($1,'College','college-0108',100,'active',now())`, [org]);
await q(`insert into public.org_codes (org_id, code, expires_at) values ($1,'CODE0108', now() + interval '1 day')`, [org]);
const signup = async email => { const id = randomUUID(); await q(`insert into auth.users (id,email,raw_user_meta_data) values ($1,$2,$3)`, [id, email, JSON.stringify({ org_code: "CODE0108" })]); return id; };
const [t1, t2, t3, mgr, ins] = [await signup("t1@x.test"), await signup("t2@x.test"), await signup("t3@x.test"), await signup("mgr@x.test"), await signup("ins@x.test")];
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

let evN = 0;
// A log in the feed, escalated by Tier-1: the case a containment request belongs to.
async function escalatedCase(ses) {
  const eid = `log-${++evN}`;
  await q(`insert into public.session_events (session_id, seq, type, payload) values ($1, public.team_next_seq($1), 'feed.event', $2)`, [ses, JSON.stringify({ id: eid, hostname: "WS-FIN-0108" })]);
  const esc = await act(ses, t1, "escalation.requested", { event_id: eid, verdict: "true_positive", summary: "impossible travel then MFA fatigue on j.doe" });
  if (esc.err) throw new Error("escalation failed: " + esc.err);
  return eid;
}
const askContain = (ses, uid, eid, target = "j.doe@nexacorp.example") => act(ses, uid, "containment.requested", { event_id: eid, target, containment_type: "disable_account", reason: "credential theft", blast_radius: "none" });
const answers = async (ses, reqSeq) => (await evs(ses, "containment.approved")).concat(await evs(ses, "containment.denied")).filter(e => Number(e.payload.request_seq) === reqSeq);

group("1. a SOC Manager on shift answers a containment request; Tier-3 cannot; the exercise admin may");
{
  const s = await newSession([[t1, "t1"], [t2, "t2"], [t3, "t3"], [mgr, "mgr"], [ins, "instructor"]]);
  const eid = await escalatedCase(s);
  const r = await askContain(s, t2, eid);
  check("Tier-2 asks to disable the account", r.err === null, r.err ?? "");
  const byT3 = await act(s, t3, "containment.approved", { event_id: eid, request_seq: r.seq });
  check("Tier-3 cannot answer while the Manager is on shift", /not_approver/.test(byT3.err ?? ""), byT3.err ?? "accepted");
  const byMgr = await act(s, mgr, "containment.approved", { event_id: eid, request_seq: r.seq });
  check("the Manager approves", byMgr.err === null, byMgr.err ?? "");
  const ex = await act(s, t2, "containment.executed", { event_id: eid, request_seq: r.seq, target: "j.doe@nexacorp.example", containment_type: "disable_account" });
  check("Tier-2 executes the approved containment", ex.err === null, ex.err ?? "");

  const eid2 = await escalatedCase(s);
  const r2 = await askContain(s, t3, eid2, "svc-backup");
  check("a Tier-3 request under a Manager is not auto-approved", r2.err === null && (await answers(s, r2.seq)).length === 0, r2.err ?? "auto");
  const byIns = await act(s, ins, "containment.denied", { event_id: eid2, request_seq: r2.seq, reason: "service account, disable after the backup window" });
  check("the exercise admin may always answer (deny)", byIns.err === null, byIns.err ?? "");
}

group("2. no Manager on shift: the Tier-3 is the shift senior");
{
  const s = await newSession([[t1, "t1"], [t2, "t2"], [t3, "t3"], [mgr, "mgr", true], [ins, "instructor"]]);
  const eid = await escalatedCase(s);
  const r = await askContain(s, t2, eid);
  const byT3 = await act(s, t3, "containment.approved", { event_id: eid, request_seq: r.seq });
  check("the Tier-3 approves a Tier-2 request", byT3.err === null, byT3.err ?? "");
  const eid2 = await escalatedCase(s);
  const r2 = await askContain(s, t3, eid2, "a.levi@nexacorp.example");
  const auto = (await answers(s, r2.seq))[0];
  check("the senior Tier-3's own request is approved at once", r2.err === null && auto?.type === "containment.approved" && auto?.actor_id === t3 && auto?.payload.auto === "shift_senior", r2.err ?? JSON.stringify(auto));
  const ex = await act(s, t3, "containment.executed", { event_id: eid2, request_seq: r2.seq, target: "a.levi@nexacorp.example", containment_type: "disable_account" });
  check("and the Tier-3 executes it", ex.err === null, ex.err ?? "");
  const eid3 = await escalatedCase(s);
  const r3 = await askContain(s, t2, eid3, "m.cohen@nexacorp.example");
  const byT2 = await act(s, t2, "containment.approved", { event_id: eid3, request_seq: r3.seq });
  check("a Tier-2 never answers", /action_not_allowed|not_approver/.test(byT2.err ?? ""), byT2.err ?? "accepted");
}

group("3. nobody senior on shift: the exercise admin answers (no more stranded requests)");
{
  const s = await newSession([[t1, "t1"], [t2, "t2"], [ins, "instructor"]]);
  const eid = await escalatedCase(s);
  const r = await askContain(s, t2, eid);
  const byIns = await act(s, ins, "containment.approved", { event_id: eid, request_seq: r.seq });
  check("the exercise admin approves", byIns.err === null, byIns.err ?? "");
}

group("4. the exercise admin isolates a host themselves");
{
  const s = await newSession([[t1, "t1"], [t2, "t2"], [t3, "t3"], [mgr, "mgr"], [ins, "instructor"]]);
  const r = await act(s, ins, "isolation.requested", { host: "WS-HR-0108", reason: "ransomware note on the share" });
  check("the exercise admin sends the request", r.err === null, r.err ?? "");
  const iso = (await evs(s, "edr.host_isolated")).find(e => e.payload.request_seq === r.seq);
  check("it is approved at once and the host is isolated", iso?.payload.approved_by === ins && iso?.payload.approver_role === "instructor", JSON.stringify(iso?.payload));
  const t1iso = await act(s, t1, "isolation.requested", { host: "WS-HR-0109", reason: "x" });
  check("Tier-1 still cannot request an isolation", /action_not_allowed/.test(t1iso.err ?? ""), t1iso.err ?? "accepted");
}

group("5. grants");
{
  for (const fn of ["team_containment_request_of(uuid,jsonb)", "team_containment_validate_answer()", "team_containment_auto_approve()"]) {
    const can = (await one(`select has_function_privilege('authenticated', 'public.${fn}', 'execute') as can`)).can;
    check(`clients cannot call ${fn.split("(")[0]}`, can === false);
  }
}

console.log(`\n${pass} passed, ${fail} failed`);
if (fail) { console.log(failures.map(f => `  - ${f}`).join("\n")); process.exit(1); }
