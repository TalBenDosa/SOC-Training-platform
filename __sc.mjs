import { pathToFileURL } from "node:url"; import path from "node:path"; import fs from "node:fs";
const m = await import(pathToFileURL(path.join(process.cwd(),"src/lib/sim/scenarios.ts")).href);
const out=[];
for (const s of m.SCENARIOS) {
  const b = m.buildScenarioBySlug(s.slug);
  if(!b){ console.log(`!! ${s.slug}: buildScenarioBySlug returned nothing`); continue; }
  out.push({ slug:s.slug, difficulty:b.difficulty??s.difficulty, events:(b.events??[]).length,
    questions:(b.questions??[]).length, narrative:(b.narrative??"").length,
    briefing:(b.briefing??"").length, objectives:(b.learning_objectives??[]).length,
    verdict:b.verdict??b.expected_verdict??"?", bundle:b });
}
fs.writeFileSync("__scen.json", JSON.stringify(out.map(({bundle,...r})=>r),null,2));
console.log("slug".padEnd(32),"diff".padEnd(12),"evt","qs","narr","brief","obj");
for(const r of out) console.log(r.slug.padEnd(32), String(r.difficulty).padEnd(12), String(r.events).padStart(3), String(r.questions).padStart(3), String(r.narrative).padStart(5), String(r.briefing).padStart(5), String(r.objectives).padStart(4));
const tot=out.reduce((a,r)=>a+r.events,0);
console.log(`\ntotal events across all scenarios: ${tot}`);
console.log(`missing briefing: ${out.filter(r=>!r.briefing).length}`);
console.log(`missing narrative: ${out.filter(r=>!r.narrative).length}`);
