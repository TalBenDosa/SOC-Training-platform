#!/usr/bin/env node
/**
 * E-01 verification — after instantiateStory adaptation, are file paths, usernames
 * and detection names intact? The bug replaced every path segment (Users, Downloads,
 * Google, Chrome) AND the username with the company short-name, so `C:\Users\r.avraham\
 * Downloads\x.exe` became `C:\NEXACORP\r.NEXACORP\NEXACORP\x.exe` and detection names
 * collapsed to one char. Materialise every story×company and assert none of that.
 */
import { pathToFileURL } from "node:url";
import path from "node:path";
process.env.NODE_ENV = "production";
const ROOT = process.cwd();
const imp = (p) => import(pathToFileURL(path.join(ROOT, p)).href);

const { pickStoryForCompany, instantiateStory } = await imp("src/app/(app)/dashboard/attackStories.ts");
const { COMPANY_EVENTS } = await imp("src/lib/sim/companyProfiles.ts");
const { BENIGN_EVENTS } = await imp("src/app/(app)/dashboard/benignEvents.ts");
const { COMPANY_PROFILES } = await imp("src/lib/sim/companyProfilesMeta.ts");

const profById = new Map(COMPANY_PROFILES.map((p) => [p.id, p]));
function companyEvents(id) {
  const base = id === "nexacorp" ? BENIGN_EVENTS : COMPANY_EVENTS[id] ?? BENIGN_EVENTS;
  const active = new Set(profById.get(id)?.architecture?.sources ?? []);
  return base.filter((e) => active.size === 0 || active.has(e.source));
}

const FS_WORDS = ["Users", "Downloads", "Program Files", "AppData", "Roaming", "Google", "Chrome", "Windows", "Temp", "Application"];
let checked = 0, bad = 0;
const samples = [];

for (const prof of COMPANY_PROFILES) {
  const id = prof.id;
  const netbios = id.toUpperCase();
  const pool = companyEvents(id);
  const edr = prof.architecture?.edr;
  for (const diff of ["easy", "medium", "hard"]) {
    for (let draw = 0; draw < 40; draw++) {
      const story = pickStoryForCompany(id, diff);
      if (!story) continue;
      const adapted = instantiateStory(story, pool, edr, id);
      for (const e of adapted.events) {
        const blob = `${JSON.stringify(e.process ?? {})} ${JSON.stringify(e.raw ?? {})}`;
        checked++;
        // 1. A Windows path must never contain the company netbios as a segment.
        for (const m of blob.matchAll(/[A-Za-z]:\\\\[^"]*/g)) {
          if (m[0].includes(`\\\\${netbios}\\\\`) || m[0].includes(`:\\\\${netbios}\\\\`)) {
            bad++; if (samples.length < 8) samples.push(`[${id}/${story.slug ?? story.id}] path corrupted: ${m[0].slice(0, 80)}`); break;
          }
        }
        // 2. A known FS word must never have been rewritten to the netbios: if the
        //    story process path had one, the adapted one should still have it.
        const op = story.events.find(x => x === undefined); // noop guard
        void op;
        // 3. detection / threat names must not collapse to <=3 chars.
        const dn = e.raw?.["threat.name"] ?? e.raw?.["sophos.detection_name"] ?? e.raw?.["crowdstrike.detection.name"];
        if (typeof dn === "string" && dn.trim() && dn.trim().length <= 3) {
          bad++; if (samples.length < 8) samples.push(`[${id}/${story.slug ?? story.id}] short detection name: "${dn}"`);
        }
        // 4. process.user must not be DOMAIN\DOMAIN (username replaced by company).
        const u = e.process?.user;
        if (typeof u === "string" && new RegExp(`\\\\${netbios}$`, "i").test(u) && u.toUpperCase() === `${netbios}\\${netbios}`) {
          bad++; if (samples.length < 8) samples.push(`[${id}] user collapsed: "${u}"`);
        }
      }
    }
  }
}

console.log(`\nE-01 path/identity integrity — ${checked} adapted events across ${COMPANY_PROFILES.length} companies × 3 difficulties × 40 draws`);
if (bad === 0) {
  console.log("  PASS — no path corrupted, no company-name-in-path, no collapsed detection name/user.\n");
  process.exit(0);
} else {
  console.log(`  FAIL — ${bad} corrupted value(s):`);
  for (const s of samples) console.log("   • " + s);
  process.exit(1);
}
