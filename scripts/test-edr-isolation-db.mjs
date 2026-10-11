// Team exercise — EDR host isolation recorded in the session log (migration 0082).
// Runs every migration in PGlite (no Docker / Supabase needed).
//
// Run: node scripts/test-edr-isolation-db.mjs
import { randomUUID } from "node:crypto";
import { freshDb, asUser } from "./lib/pgliteHarness.mjs";

let pass = 0, fail = 0; const failures = [];
function check(name, cond, extra = "") {
  if (cond) pass++; else { fail++; failures.push(name + (extra ? ` — ${extra}` : "")); }
  console.log(`  ${cond ? "✅" : "❌"} ${name}${extra ? `  (${extra})` : ""}`);
}
const group = t => console.log(`\n\x1b[1m${t}\x1b[0m`);

const { db, q, one } = await freshDb();
const org = randomUUID();
await q(`insert into public.organizations (id,name,slug,seat_limit,status,starts_at) values ($1,'College','college-edr',100,'active',now())`, [org]);
await q(`insert into public.org_codes (org_id, code, expires_at) values ($1,'CODEEDR1', now() + interval '1 day')`, [org]);
const signup = async email => { const id = randomUUID(); await q(`insert into auth.users (id,email,raw_user_meta_data) values ($1,$2,$3)`, [id, email, JSON.stringify({ org_code: "CODEEDR1" })]); return id; };
const t1 = await signup("t1@edr.test"), t2 = await signup("t2@edr.test"), t3 = await signup("t3@edr.test");

const ses = randomUUID();
await q(`insert into public.team_sessions (id, org_id, created_by, company_id, status, schema_version, started_at) values ($1,$2,$3,'nexacorp','running',2,now())`, [ses, org, t2]);
for (const [u, r] of [[t1, "t1"], [t2, "t2"], [t3, "t3"]]) {
  await q(`insert into public.team_session_members (session_id, user_id, role, status) values ($1,$2,$3,'active')`, [ses, u, r]);
}

// asUser() always rolls back; an action here must COMMIT so the next one sees it.
async function asUserCommit(uid, fn, claims = {}) {
  await db.exec("begin");
  try {
    await db.exec(`set local role authenticated; select set_config('request.jwt.claims', '${JSON.stringify({ sub: uid, role: "authenticated", ...claims })}', true);`);
    const r = await fn();
    await db.exec("commit");
    return r;
  } catch (e) { await db.exec("rollback"); throw e; }
}
let n = 0;
async function act(uid, type, payload) {
  try {
    await asUserCommit(uid, () => db.query(`select public.apply_session_action(p_session => $1, p_type => $2, p_payload => $3::jsonb, p_idempotency_key => $4)`, [ses, type, JSON.stringify(payload), `k${++n}`]), { org_id: org });
    return null;
  } catch (e) { return String(e.message); }
}

group("who may isolate");
check("Tier-2 isolates a host", (await act(t2, "edr.host_isolated", { host: "WS-FIN-2847", case: "encoded PowerShell" })) === null);
const t1Err = await act(t1, "edr.host_isolated", { host: "WS-HR-1142" });
check("Tier-1 may not isolate (EDR is Tier-2/3 work)", /action_not_allowed/.test(t1Err ?? ""), t1Err ?? "accepted");
check("Tier-3 isolates another host", (await act(t3, "edr.host_isolated", { host: "SRV-DB-01" })) === null);

group("one clean timeline per host");
const dup = await act(t3, "edr.host_isolated", { host: "ws-fin-2847" });
check("isolating an already-isolated host is refused (case-insensitive)", /invalid_payload: .*already isolated/.test(dup ?? ""), dup ?? "accepted");
const relNot = await act(t2, "edr.host_released", { host: "WS-HR-1142" });
check("releasing a host that isn't isolated is refused", /invalid_payload: .*not isolated/.test(relNot ?? ""), relNot ?? "accepted");
check("releasing an isolated host works", (await act(t2, "edr.host_released", { host: "WS-FIN-2847" })) === null);
check("…and it can be isolated again", (await act(t2, "edr.host_isolated", { host: "WS-FIN-2847" })) === null);

group("payload validation");
for (const [label, host] of [["empty host", ""], ["missing host", undefined], ["host with spaces / injection", "x; drop table"], ["over-long host", "A".repeat(300)]]) {
  const err = await act(t2, "edr.host_isolated", host === undefined ? {} : { host });
  check(`refused: ${label}`, /invalid_payload: a valid host name is required/.test(err ?? ""), err ?? "accepted");
}

group("recorded for the team and the report");
const rows = (await q(`select type, actor_id, payload->>'host' host from public.session_events where session_id=$1 and type like 'edr.%' order by seq`, [ses])).rows;
check("4 accepted isolation events are in the log, in order",
  JSON.stringify(rows.map(r => [r.type, r.host])) === JSON.stringify([["edr.host_isolated", "WS-FIN-2847"], ["edr.host_isolated", "SRV-DB-01"], ["edr.host_released", "WS-FIN-2847"], ["edr.host_isolated", "WS-FIN-2847"]]),
  JSON.stringify(rows));
check("each row carries its actor", rows[1]?.actor_id === t3);
const visible = await asUser(db, t1, () => db.query(`select count(*)::int n from public.session_events where session_id=$1 and type like 'edr.%'`, [ses]), { org_id: org });
check("teammates can read the isolations (session member read policy)", visible.rows[0].n === 4);

group("not while the shift isn't running");
await q(`update public.team_sessions set status='paused' where id=$1`, [ses]);
const paused = await act(t2, "edr.host_released", { host: "SRV-DB-01" });
check("a paused shift refuses isolation changes", /action_not_allowed/.test(paused ?? ""), paused ?? "accepted");

group("privileges unchanged");
const g = (await one(`select has_function_privilege('authenticated', 'public.team_validate_action(uuid,uuid,text,jsonb)', 'execute') as can`)).can;
check("clients still cannot call team_validate_action directly", g === false);

console.log(`\n${pass} passed, ${fail} failed`);
if (fail) { console.log(failures.map(f => `  - ${f}`).join("\n")); process.exit(1); }
