// Scenario review 2026-10-01 — DB checks for migration 0084 (team feed recycling).
// Runs every migration in PGlite. Run: node scripts/test-team-review-db.mjs
import { randomUUID } from "node:crypto";
import { freshDb } from "./lib/pgliteHarness.mjs";

let pass = 0, fail = 0; const failures = [];
function check(name, cond, extra = "") {
  if (cond) pass++; else { fail++; failures.push(name + (extra ? ` — ${extra}` : "")); }
  console.log(`  ${cond ? "✅" : "❌"} ${name}${extra ? `  (${extra})` : ""}`);
}
const group = t => console.log(`\n\x1b[1m${t}\x1b[0m`);

const { q, one } = await freshDb();
const org = randomUUID();
await q(`insert into public.organizations (id,name,slug,seat_limit,status,starts_at) values ($1,'College','college-tr',100,'active',now())`, [org]);
await q(`insert into public.org_codes (org_id, code, expires_at) values ($1,'CODETRV1', now() + interval '1 day')`, [org]);
const owner = randomUUID();
await q(`insert into auth.users (id,email,raw_user_meta_data) values ($1,'o@tr.test',$2)`, [owner, JSON.stringify({ org_code: "CODETRV1" })]);

const sid = randomUUID();
await q(`insert into public.team_sessions (id, org_id, created_by, company_id, status, started_at, feed_gap_ms, feed_jitter_ms)
         values ($1,$2,$3,'nexacorp','running', now() - interval '40 minutes', 20000, 0)`, [sid, org, owner]);
const fired = async (body, answer) => q(`insert into public.session_injects (session_id, due_offset_ms, trigger, channel, body, expected_action, status)
  values ($1, 0, '{"kind":"at_time"}', 'feed', $2, $3, 'fired')`, [sid, JSON.stringify(body), JSON.stringify(answer)]);
const NOISE = ["TradeFlow opened", "svc-backup TGT renewed", "Teams launched", "git via bash", "DNS api.github.com"];
for (const [i, d] of NOISE.entries()) await fired({ id: `n${i}`, description: d }, { expected_verdict: "benign", origin: "noise" });
await fired({ id: "fp1", description: "r.williams copied 9.3 GB to USB" }, { expected_verdict: "fp", origin: "noise", fp_explanation: "approved RITM0048213" });
await fired({ id: "atk", description: "Lagos VPN login" }, { expected_verdict: "tp", origin: "pool_attack" });

group("0084 recycling: no decoys, repeats spread evenly");
for (let round = 0; round < 5; round++) {
  await one(`select public.replenish_feed() as n`);
  await q(`update public.session_injects set status = 'fired' where session_id = $1 and status = 'pending'`, [sid]);   // the promoter ran
}
const copies = (await q(`select body->>'description' d, count(*)::int n from public.session_injects where session_id=$1 group by 1`, [sid])).rows;
const by = Object.fromEntries(copies.map(r => [r.d, r.n]));
check("the FP decoy is never recycled", by["r.williams copied 9.3 GB to USB"] === 1, JSON.stringify(by));
check("an attack log is never recycled", by["Lagos VPN login"] === 1);
const counts = NOISE.map(d => by[d] ?? 0);
check("every noise log was recycled", counts.every(n => n > 1), JSON.stringify(counts));
check("repeats spread evenly (max − min ≤ 1)", Math.max(...counts) - Math.min(...counts) <= 1, JSON.stringify(counts));
check("recycled copies get fresh opaque ids", (await one(`select count(distinct body->>'id')::int n from public.session_injects where session_id=$1`, [sid])).n
  === (await one(`select count(*)::int n from public.session_injects where session_id=$1`, [sid])).n);

console.log(`\n${fail ? "\x1b[31mFAIL" : "\x1b[32mPASS"}\x1b[0m — ${pass} passed, ${fail} failed`);
if (fail) { console.log(failures.map(f => `  - ${f}`).join("\n")); process.exit(1); }
