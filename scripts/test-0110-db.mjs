// 0110 student_report_snapshots: server-only figures of each progress report. No client
// access at all (a learner never reads a manager's report), and the rows go with the org.
// Runs every migration in PGlite (no Docker / Supabase needed).
//
// Run: node scripts/test-0110-db.mjs
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
await q(`insert into public.organizations (id,name,slug,seat_limit,status,starts_at) values ($1,'College','college-0110',100,'active',now())`, [org]);
await q(`insert into public.org_codes (org_id, code, expires_at) values ($1,'CODE0110', now() + interval '1 day')`, [org]);
const signup = async email => { const id = randomUUID(); await q(`insert into auth.users (id,email,raw_user_meta_data) values ($1,$2,$3)`, [id, email, JSON.stringify({ org_code: "CODE0110" })]); return id; };
const [learner, admin] = [await signup("l@x.test"), await signup("a@x.test")];

async function as(role, uid, fn) {
  await db.exec("begin");
  try {
    await db.exec(`set local role ${role}; select set_config('request.jwt.claims', '${JSON.stringify({ sub: uid, role })}', true);`);
    const r = await fn(); await db.exec("commit"); return { r, err: null };
  } catch (e) { await db.exec("rollback"); return { r: null, err: String(e.message) }; }
}

group("1. the server keeps report figures");
let r = await as("service_role", admin, () => db.query(`insert into public.student_report_snapshots (org_id, user_id, created_by, metrics) values ($1,$2,$3,'{"v":1,"xp":100}') returning id`, [org, learner, admin]));
check("service role inserts", !r.err, r.err ?? "");
r = await as("service_role", admin, () => db.query(`insert into public.student_report_snapshots (org_id, user_id, metrics) values ($1,$2,'[1,2]')`, [org, learner]));
check("metrics must be an object", !!r.err);

group("2. no client access");
r = await as("authenticated", learner, () => db.query(`select count(*)::int n from public.student_report_snapshots`));
check("the learner cannot read reports about them", !!r.err || r.r.rows[0].n === 0, r.err ?? "");
r = await as("authenticated", admin, () => db.query(`insert into public.student_report_snapshots (org_id, user_id, metrics) values ($1,$2,'{}')`, [org, learner]));
check("a signed-in user cannot write", !!r.err);
r = await as("anon", learner, () => db.query(`select count(*)::int n from public.student_report_snapshots`));
check("anon reads nothing", !!r.err || r.r.rows[0].n === 0);

group("3. the rows go with the organization (purge_org deletes the org row)");
let purgeErr = null;
try { await q(`select public.purge_org($1)`, [org]); } catch (e) { purgeErr = String(e.message); }
check("purge_org runs", !purgeErr, purgeErr ?? "");
check("no rows left", (await one(`select count(*)::int n from public.student_report_snapshots where org_id = $1`, [org])).n === 0);

console.log(`\n${pass} passed, ${fail} failed`);
if (fail) { console.log(failures.join("\n")); process.exit(1); }
