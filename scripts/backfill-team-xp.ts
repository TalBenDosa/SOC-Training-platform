// Award team-training XP (0087) for ended sessions that have none yet — the
// sessions played before team XP existed. Uses the same server code as the app.
//
//   npx tsx scripts/backfill-team-xp.ts --dry-run   # print the awards, write nothing
//   npx tsx scripts/backfill-team-xp.ts --yes       # award them
//
// It prints the Supabase project it is about to touch first, and writes nothing
// without an explicit --yes (QA L14) — ENV_FILE can point it at any project.
//
// Env (from .env.local): NEXT_PUBLIC_SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY.
import { readFileSync } from "node:fs";
import { createClient } from "@supabase/supabase-js";
import { buildServerReport } from "../src/lib/team/report/serverReport";
import { awardTeamXp, sessionsMissingXp } from "../src/lib/team/awardTeamXp";
import { teamXpFor } from "../src/lib/team/teamXp";

const envFile = process.env.ENV_FILE ?? ".env.local";
const env = Object.fromEntries(readFileSync(envFile, "utf8").split(/\r?\n/)
  .map(l => /^([A-Z_]+)\s*=\s*(.*)$/.exec(l)).filter(Boolean).map(m => [m![1], m![2].trim().replace(/^["']|["']$/g, "")]));
const url = env.NEXT_PUBLIC_SUPABASE_URL, key = env.SUPABASE_SERVICE_ROLE_KEY;
if (!url || !key) { console.error(`missing Supabase URL / service key in ${envFile}`); process.exit(1); }
const dry = process.argv.includes("--dry-run");
const yes = process.argv.includes("--yes");
/** The project ref of a Supabase URL (https://<ref>.supabase.co), else the host. */
function projectRef(u: string): string {
  try { const h = new URL(u).hostname; return h.endsWith(".supabase.co") ? h.split(".")[0] : h; } catch { return u; }
}
console.log(`Target Supabase project: ${projectRef(url)}  (${url}, from ${envFile})`);
if (!dry && !yes) {
  console.error("Refusing to write without confirmation: re-run with --yes to award, or --dry-run to preview.");
  process.exit(1);
}
const admin = createClient(url, key, { auth: { persistSession: false, autoRefreshToken: false } });

async function main() {
  const ids = await sessionsMissingXp(admin, 200);
  console.log(`${ids.length} ended session(s) without team XP${dry ? " (dry run)" : ""}`);
  let failed = 0;
  for (const id of ids) {
    try {
      if (dry) {
        const r = await buildServerReport(admin, id);
        console.log(id, r.perUser.map(u => `${u.name} [${u.role}] → ${teamXpFor(u)} XP`).join(" · "));
      } else {
        const xp = await awardTeamXp(admin, id);
        console.log(id, JSON.stringify(xp));
      }
    } catch (e) { failed++; console.error(id, "FAILED:", e instanceof Error ? e.message : e); }
  }
  if (failed) process.exit(2);
}
main().catch(e => { console.error(e); process.exit(1); });
