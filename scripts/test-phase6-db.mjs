// QA PHASE 6 (security) — DB-level checks for migration 0083.
// Runs every migration in PGlite (no Docker / Supabase needed).
//
// Run: node scripts/test-phase6-db.mjs
import { randomUUID } from "node:crypto";
import { freshDb, asUser } from "./lib/pgliteHarness.mjs";

let pass = 0, fail = 0; const failures = [];
function check(name, cond, extra = "") {
  if (cond) pass++; else { fail++; failures.push(name + (extra ? ` — ${extra}` : "")); }
  console.log(`  ${cond ? "✅" : "❌"} ${name}${extra ? `  (${extra})` : ""}`);
}
const group = t => console.log(`\n\x1b[1m${t}\x1b[0m`);
async function denied(db, uid, sql, claims) {
  try { await asUser(db, uid, () => db.query(sql), claims); return false; }
  catch (e) { return /permission denied|violates row-level security/i.test(String(e.message)); }
}

const { db, q, one } = await freshDb();
const org = randomUUID();
await q(`insert into public.organizations (id,name,slug,seat_limit,status,starts_at) values ($1,'College','college-p6',100,'active',now())`, [org]);
await q(`insert into public.org_codes (org_id, code, expires_at) values ($1,'CODEP6AA', now() + interval '1 day')`, [org]);
const signup = async email => { const id = randomUUID(); await q(`insert into auth.users (id,email,raw_user_meta_data) values ($1,$2,$3)`, [id, email, JSON.stringify({ org_code: "CODEP6AA" })]); return id; };
const stu = await signup("stu@p6.test");
const other = await signup("other@p6.test");

group("SEC-05 revoke_user_sessions");
for (const u of [stu, stu, other]) {
  const s = (await one(`insert into auth.sessions (user_id) values ($1) returning id`, [u])).id;
  await q(`insert into auth.refresh_tokens (session_id, user_id, token) values ($1,$2,'t')`, [s, u]);
}
const n = (await one(`select public.revoke_user_sessions($1) n`, [stu])).n;
check("removes every session of the user (2)", n === 2, String(n));
check("…and their refresh tokens (cascade)", (await one(`select count(*)::int c from auth.refresh_tokens where user_id=$1`, [stu])).c === 0);
check("other users' sessions untouched", (await one(`select count(*)::int c from auth.sessions where user_id=$1`, [other])).c === 1);
check("students cannot call revoke_user_sessions", await denied(db, stu, `select public.revoke_user_sessions('${other}')`, { org_id: org }));

console.log(`\n${fail ? "\x1b[31mFAIL" : "\x1b[32mPASS"}\x1b[0m — ${pass} passed, ${fail} failed`);
if (fail) { console.log(failures.map(f => `  - ${f}`).join("\n")); process.exit(1); }
