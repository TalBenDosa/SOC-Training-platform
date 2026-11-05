// Builds the "what to do next" line for every room film: for each film, the
// station the learner opens next and the first concrete thing they do there.
// Reads the experience files, the campaign docs' film tables and the slug
// prefixes in the film wiring list; writes JSON for the film studio.
// Usage: npx tsx scripts/film-next-guide.ts <wire_films.py> <out.json>
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import type { BriefingLab, RoomExperience } from "../src/lib/rooms/experience/types";

const [wirePath, outPath] = process.argv.slice(2);
const root = path.resolve(__dirname, "..");
const expDir = path.join(root, "src/lib/rooms/experience");

const list = (xs: string[]) => (xs.length <= 1 ? xs.join("") : `${xs.slice(0, -1).join(", ")} or ${xs[xs.length - 1]}`);

function action(lab: BriefingLab): string {
  switch (lab.kind) {
    case "terminal": return `Open the console and find out: ${lab.objectives[0]?.task ?? lab.title}`;
    case "pcap": return `Filter the capture and find out: ${lab.objectives[0]?.task ?? lab.title}`;
    case "worksheet": return `Read the table and work out: ${lab.questions[0]?.q ?? lab.title}`;
    case "sort": return `Sort every card into ${list(lab.buckets.map(b => b.label.replace(/\s*\(.*\)$/, "")))}.`;
    case "reactor": return `Route every card into the right reactor: ${list(lab.reactors.map(r => r.label))}.`;
    case "trace": return `Follow the trail, starting with: ${lab.steps[0]?.ask ?? lab.title}`;
    case "queue": return `Work the alert queue and decide for each one: ${list(lab.actions.map(a => a.label))}.`;
    case "hotspot": return `Find every red flag in ${lab.artifact}.`;
    case "inspect": return `Open every entry in ${lab.artifact} and judge it.`;
    case "anatomy": return "Decode the record field by field: what each field tells an analyst.";
    case "xray": return "Scan every everyday object with the lens and see the computer inside.";
    case "simulate": return "Run each scenario and read why each check passes or fails.";
    case "encap": return "Build the packet layer by layer.";
    case "lineup": return `Read the evidence and pick the culprit in each of ${lab.rounds.length} rounds.`;
    case "locks": return `Open all ${lab.locks.length} doors by answering each one's question.`;
    case "tricks": return `Flip all ${lab.cards.length} cards and stamp each with ${list(lab.attacks.map(a => a.name))}.`;
    case "sequence": return "Put the moments in the order they really happened.";
    case "chat": return `Open the chat with ${lab.bot} and reach every goal, starting with: ${lab.goals[0].task}`;
    case "match": return "Pair every item on the left with its partner on the right.";
    case "evidence": return `Name what each of the ${lab.items.length} screens shows.`;
    case "portal": return `Open the console and work the job: ${lab.steps[0].ask}`;
    case "intercept": return `Guard ${lab.protect}: block or pass every item before it lands.`;
    case "duel": return `Beat ${lab.attacker} in a card duel: answer each move with the card that stops it.`;
    case "deduce": return "Read the clues, rule out the suspects and name the culprit.";
    case "tune": return `Set the dials and deploy a rule that catches at least ${lab.goal.catch} attacks with at most ${lab.goal.maxFalse} false alarms.`;
    case "pathway": return `Walk the route hop by hop: ${lab.goal}.`;
    case "defuse": return `Defuse ${lab.device} before the ${lab.seconds}-second clock runs out.`;
    case "outbreak": return `Isolate hosts turn by turn and stop the spread before it reaches ${lab.crown}.`;
    case "codebreak": return `Crack ${lab.rounds.length} codes from their clues before your tries run out.`;
    case "rush": return `Make ${lab.target} right calls before the clock stops.`;
    case "spotdiff": return "Compare the two copies and tap every line that was tampered with.";
    default: return `Play ${lab.title}.`;
  }
}

// Experiences, keyed by room id.
const exps = new Map<string, RoomExperience>();
for (const f of readdirSync(expDir)) {
  if (!f.endsWith(".ts") || f === "index.ts" || f === "types.ts" || f.endsWith(".test.ts")) continue;
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const mod = require(path.join(expDir, f)) as Record<string, unknown>;
  for (const v of Object.values(mod)) {
    const e = v as RoomExperience;
    if (e && typeof e === "object" && "roomId" in e && "stations" in e) exps.set(e.roomId, e);
  }
}

// Film wiring list: ("room-id", "var", "prefix", "doc.md")
const wire = [...readFileSync(wirePath, "utf8").matchAll(/\("([a-z0-9-]+)",\s*"\w+",\s*"([a-z0-9-]+)",\s*"([^"]+\.md)"\)/g)].map(m => ({ room: m[1], prefix: m[2], doc: m[3] }));
const order = wire.map(w => w.room);

type Guide = { room: string; film: string; nextStation: string; vo: string; card: string; action: string };
const out: Record<string, Guide> = {};
for (const [i, w] of wire.entries()) {
  const e = exps.get(w.room);
  if (!e) continue;
  const doc = readFileSync(path.join(root, "docs/campaign", w.doc), "utf8");
  const rows = [...doc.matchAll(/^\|\s*(?:\*\*)?(Intro|Chapter (\d+)|Finale)[^|]*\|\s*([^|]+?)\s*\|/gm)];
  for (const r of rows) {
    const which = r[1] === "Intro" ? "intro" : r[1] === "Finale" ? "finale" : `ch${r[2]}`;
    const film = `${w.prefix}-${which}`;
    let nextIdx: number;
    if (which === "intro") nextIdx = 0;
    else if (which === "finale") nextIdx = e.stations.length;
    else {
      const label = r[3].replace(/^אחרי\s*/, "").trim();
      const at = e.stations.findIndex(s => s.label === label);
      if (at < 0) { console.warn(`${film}: no station '${label}'`); continue; }
      nextIdx = at + 1;
    }
    if (nextIdx >= e.stations.length) {
      const nextRoom = order[i + 1] ? exps.get(order[i + 1]) : undefined;
      const name = nextRoom ? `${nextRoom.codename}` : "the next room";
      const first = nextRoom?.stations[0];
      out[film] = { room: w.room, film, nextStation: first?.label ?? "", card: `NEXT ROOM · ${name.toUpperCase()}`, action: first ? `Start with ${first.label}.` : "Open the next room.", vo: `Next room: ${name}. Start with ${first?.label ?? "its first station"}.` };
      continue;
    }
    const st = e.stations[nextIdx];
    const labs = st.taskIds.flatMap(t => e.briefings?.[t] ?? []);
    const act = labs[0] ? action(labs[0]) : "Read the evidence and answer its questions.";
    out[film] = { room: w.room, film, nextStation: st.label, card: `NEXT MISSION · ${st.label.toUpperCase()}`, action: act, vo: `Next mission: ${st.label}. ${act}` };
  }
}
writeFileSync(outPath, JSON.stringify(out, null, 2));
console.log(`wrote ${Object.keys(out).length} film guides`);
