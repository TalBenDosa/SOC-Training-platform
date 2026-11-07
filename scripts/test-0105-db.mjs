// 0105: a player can read their own team session row but not its config (attack plan, variety memory).
// Runs every migration in PGlite. Run: node scripts/test-0105-db.mjs
import { randomUUID } from "node:crypto";
import { freshDb } from "./lib/pgliteHarness.mjs";

let pass = 0, fail = 0;
const check = (name, cond, extra = "") => { cond ? pass++ : fail++; console.log(`  ${cond ? "PASS" : "FAIL"} ${name}${extra ? `  (${extra})` : ""}`); };
const { db, q } = await freshDb();
const org = randomUUID();
await q(`insert into public.organizations (id,name,slug,seat_limit,status,starts_at) values ($1,'College','college-0105',100,'active',now())`, [org]);
await q(`insert into public.org_codes (org_id, code, expires_at) values ($1,'CODE0105', now() + interval '1 day')`, [org]);
const uid = randomUUID();
await q(`insert into auth.users (id,email,raw_user_meta_data) values ($1,'p@x.test',$2)`, [uid, JSON.stringify({ org_code: "CODE0105" })]);
const sid = randomUUID();
await q(`insert into public.team_sessions (id, org_id, created_by, company_id, status, schema_version, started_at, config) values ($1,$2,$3,'nexacorp','running',2, now(), '{"attacks":["x"],"variety":{"makers":["fp_psexec"]}}')`, [sid, org, uid]);
await q(`insert into public.team_session_members (session_id, user_id, role, status, last_seen_at) values ($1,$2,'t1','active', now())`, [sid, uid]);
const asPlayer = async sql => {
  await db.exec("begin");
  try {
    await db.exec(`set local role authenticated; select set_config('request.jwt.claims', '${JSON.stringify({ sub: uid, role: "authenticated", org_id: org })}', true);`);
    const r = await db.query(sql, [sid]); await db.exec("rollback"); return { rows: r.rows, err: null };
  } catch (e) { await db.exec("rollback"); return { rows: null, err: String(e.message) }; }
};
const own = await asPlayer(`select id, status from public.team_sessions where id = $1`);
check("a player reads their session's id and status", own.rows?.length === 1 && own.rows[0].status === "running", own.err ?? "");
const cfg = await asPlayer(`select config from public.team_sessions where id = $1`);
check("a player cannot read config", cfg.err !== null && /permission denied/i.test(cfg.err), cfg.err ?? JSON.stringify(cfg.rows));
const star = await asPlayer(`select * from public.team_sessions where id = $1`);
check("select * is refused too (no config through a wildcard)", star.err !== null, star.err ?? "");
const seed = await asPlayer(`select seed from public.team_sessions where id = $1`);
check("a player cannot read the seed", seed.err !== null, seed.err ?? "");
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
