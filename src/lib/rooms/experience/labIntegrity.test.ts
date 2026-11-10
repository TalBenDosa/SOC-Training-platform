// A game lab that cannot be won, or whose answer is broken, blocks a room. And Tal's rule:
// no two rooms play alike, and the console stays only where the command line IS the topic.
import { describe, it, expect } from "vitest";
import { ROOMS } from "@/data/rooms";
import { buildNetwork, tuneResult } from "@/components/operation/briefing/ArcadeLabs";
import { getRoomExperience, type BriefingLab } from "./index";
import { runHunt, type HuntStep } from "./hunt";

const ARCADE = ["intercept", "duel", "deduce", "tune", "pathway", "defuse", "outbreak", "codebreak", "rush", "spotdiff", "chat", "portal", "hunt"] as const;
/** Rooms where typing commands is the skill being taught: one console lab at most. */
const CONSOLE_ROOMS = new Set(["linux-fundamentals", "linux-log-analysis", "windows-fundamentals", "powershell-for-soc-analyst"]);

const rooms = ROOMS
  .map(room => ({ room, exp: getRoomExperience(room.id, room.tasks.map(t => t.id)) }))
  .filter(r => r.exp)
  .map(({ room, exp }) => ({ id: room.id, labs: Object.values(exp!.briefings ?? {}).flat() as BriefingLab[] }));

function problems(l: BriefingLab): string[] {
  const out: string[] = [];
  const need = (ok: unknown, msg: string) => { if (!ok) out.push(msg); };
  switch (l.kind) {
    case "intercept":
      need(l.items.length >= 8, "fewer than 8 items");
      need(l.items.filter(i => i.bad).length >= 3 && l.items.filter(i => !i.bad).length >= 3, "needs 3+ of each side");
      break;
    case "duel":
      need(l.moves.length >= 3, "fewer than 3 moves");
      need(l.cards.length >= l.moves.length + 1, "needs spare cards to be a choice");
      for (const m of l.moves) need(l.cards.some(c => c.id === m.counter), `${m.id}: counter ${m.counter} is not a card`);
      need(new Set(l.moves.map(m => m.counter)).size === l.moves.length, "a played card is gone, so each move needs its own counter");
      break;
    case "deduce":
      need(l.suspects.some(s => s.id === l.culprit), "culprit is not a suspect");
      need(l.suspects.length >= 4, "fewer than 4 suspects");
      need(l.clues.length >= 2, "fewer than 2 clues");
      for (const s of l.suspects) need(s.cells.length === l.columns.length, `${s.id}: cells do not match columns`);
      break;
    case "tune": {
      need(l.events.filter(e => e.bad).length >= 3, "needs 3+ attacks");
      for (const e of l.events) for (const d of l.dials) need(typeof e.values[d.id] === "number", `${e.id}: no value for ${d.id}`);
      need(!tuneResult(l, Object.fromEntries(l.dials.map(d => [d.id, d.start]))).pass, "the starting dials already meet the goal");
      // Walk every dial setting: the goal must be reachable.
      let solvable = false;
      const walk = (i: number, v: Record<string, number>) => {
        if (solvable) return;
        if (i === l.dials.length) { if (tuneResult(l, v).pass) solvable = true; return; }
        const d = l.dials[i];
        for (let x = d.min; x <= d.max; x += d.step) walk(i + 1, { ...v, [d.id]: x });
      };
      walk(0, {});
      need(solvable, "no dial setting meets the goal");
      break;
    }
    case "pathway": {
      const ids = new Set(l.nodes.map(n => n.id));
      const near = (a: string, b: string) => l.edges.some(([x, y]) => (x === a && y === b) || (x === b && y === a));
      for (const n of l.route) need(ids.has(n), `route node ${n} missing`);
      for (const [a, b] of l.edges) need(ids.has(a) && ids.has(b), `edge ${a}-${b} has a missing node`);
      for (let i = 1; i < l.route.length; i++) need(near(l.route[i - 1], l.route[i]), `no edge ${l.route[i - 1]}-${l.route[i]}`);
      for (const n of l.nodes) need(n.x >= 8 && n.x <= 92 && n.y >= 8 && n.y <= 92, `${n.id} sits off the map`);
      need(l.route.slice(0, -1).some((n, i) => l.edges.some(([x, y]) => (x === n || y === n) && ![x, y].every(v => l.route.slice(0, i + 2).includes(v)))), "no wrong hop to tempt anyone");
      for (const t of Object.keys(l.traps)) need(ids.has(t), `trap ${t} is not a node`);
      break;
    }
    case "defuse":
      need(l.rounds.length >= 3, "fewer than 3 modules");
      need(l.seconds >= l.rounds.length * 12, "too little time to read");
      for (const r of l.rounds) { need(r.wires.some(w => w.id === r.cut), `${r.id}: cut is not a wire`); need(r.wires.length >= 3, `${r.id}: fewer than 3 wires`); }
      break;
    case "portal": {
      // Every step must be reachable by the click that completes it.
      const pages = Object.values(l.pages), records = Object.values(l.records);
      const rows = pages.flatMap(p => p.table?.rows ?? []).concat(records.flatMap(r => r.logs?.rows ?? []));
      const ok = (t: string) => {
        const [kind, ...rest] = t.split(":");
        const id = rest.join(":");
        if (kind === "menu") return !!l.pages[id] && (l.menu.some(g => g.items.some(i => i.id === id)) || pages.some(p => p.tabs?.some(t => t.id === id) || p.sub?.some(t => t.id === id)));
        if (kind === "row") return rows.some(r => r.id === id);
        if (kind === "tree") return records.some(r => r.tree?.some(n => n.id === id));
        if (kind === "node") return records.some(r => r.graph?.nodes.some(n => n.id === id));
        if (kind === "tab") return records.some(r => !!r.graph) && ["story", "alerts", "assets", "evidence", "summary"].includes(id);
        if (kind === "set") {
          const [field, value] = [rest[0], rest.slice(1).join(":")];
          if (field === "classification") return records.some(r => r.closing?.includes(value));
          return records.some(r => r.strip?.some(s => s.field === field && s.options?.includes(value)));
        }
        if (kind === "action") {
          if (id === "full" || id === "logs" || id === "bookmark") return true;
          if (id === "play") return records.some(r => !!r.graph);
          if (id.startsWith("approve:") || id.startsWith("reject:")) return records.some(r => r.remediation?.some(x => x.id === id.split(":")[1]));
          if (id.startsWith("entity:")) return records.some(r => r.entities?.some(e => `entity:${e.id}` === id));
          if (id.startsWith("field:")) return records.some(r => [...r.facts, ...(r.tree?.flatMap(n => n.facts ?? []) ?? [])].some(([k]) => `field:${k}` === id));
          return records.some(r => r.actions?.some(a => a.id === id));
        }
        return false;
      };
      for (const s of l.steps) need(ok(s.target), `${s.id}: target ${s.target} cannot be clicked`);
      for (const t of Object.keys(l.traps)) need(ok(t) || t.startsWith("action:") || t.startsWith("row:") || t.startsWith("set:") || t.startsWith("tree:") || t.startsWith("node:"), `trap ${t}`);
      need(l.steps.length >= 6, "fewer than 6 steps");
      need(!!l.pages[l.home], "home page missing");
      for (const r of rows) if (r.record) need(!!l.records[r.record], `row ${r.id}: no record ${r.record}`);
      break;
    }
    case "hunt": {
      need(l.rungs.length >= 3, "fewer than 3 rungs");
      const path: HuntStep[] = [], opts = { emptyColumns: l.language === "SPL" };
      for (const r of l.rungs) {
        const right = r.choices.filter(c => c.right);
        need(right.length === 1, `${r.id}: needs exactly one right line`);
        need(r.choices.length >= 3, `${r.id}: fewer than 3 choices`);
        const before = runHunt(l.tables, l.start, path, opts);
        for (const c of r.choices) {
          const res = runHunt(l.tables, l.start, [...path, c.apply], opts);
          if (c.right) need(!res.error && res.rows.length > 0, `${r.id}: the right line returns nothing`);
          else need(!!res.error || JSON.stringify(res) !== JSON.stringify(runHunt(l.tables, l.start, [...path, right[0]!.apply], opts)), `${r.id}/${c.id}: a wrong line returns the same result as the right one`);
        }
        need(!before.error, `${r.id}: query already broken`);
        path.push(right[0]!.apply);
      }
      need(runHunt(l.tables, l.start, path, opts).rows.length === l.expect, "finished query does not return the expected rows");
      break;
    }
    case "outbreak":
      need(l.cols * l.rows >= 20, "grid too small");
      need(l.crown.length <= 9, "crown label does not fit its node");
      need(l.via.length > 0, "no spread path named");
      break;
    case "codebreak":
      need(l.rounds.length >= 2, "fewer than 2 codes");
      for (const r of l.rounds) need(/^[A-Za-z0-9]{3,10}$/.test(r.answer), `${r.id}: answer must be 3-10 letters or digits`);
      break;
    case "rush":
      need(l.cards.length >= 10, "fewer than 10 cards");
      need(l.target <= l.cards.length, "target above the card count");
      need(l.target >= Math.ceil(l.cards.length * 0.6), "target too easy");
      need(l.cards.some(c => c.answer) && l.cards.some(c => !c.answer), "needs both answers");
      break;
    case "spotdiff": {
      need(l.good.length === l.suspect.length, "the two copies differ in length");
      const marked = new Set([...l.diffs.map(d => d.line), ...(l.decoys ?? []).map(d => d.line)]);
      l.suspect.forEach((line, i) => {
        if (marked.has(i)) need(line !== l.good[i], `line ${i} is marked but identical`);
        else need(line === l.good[i], `line ${i} differs but is not marked`);
      });
      need(l.diffs.length >= 2, "fewer than 2 changes to find");
      break;
    }
  }
  return out;
}

describe("game labs", () => {
  it("the outbreak network is always winnable: crown far from the start, every host linked", () => {
    for (let run = 0; run < 150; run++) {
      const net = buildNetwork(6, 5, n => Math.floor(Math.random() * n));
      expect(net.crown).not.toBe(net.start);
      expect(net.links.length).toBeGreaterThanOrEqual(29);
      expect(net.target).toBeGreaterThanOrEqual(12);
    }
  });

  it("every game lab can be won and its answers exist", () => {
    const bad: string[] = [];
    for (const r of rooms) for (const l of r.labs) for (const p of problems(l)) bad.push(`${r.id} / ${l.title}: ${p}`);
    expect(bad).toEqual([]);
  });

  it("an evidence screen never names its own answer in its title bar", () => {
    const bad: string[] = [];
    for (const r of rooms) for (const l of r.labs) {
      if (l.kind !== "evidence") continue;
      for (const it of l.items) {
        const s = it.screen as unknown as Record<string, unknown>;
        const bar = [it.caption, s.product, s.tool, s.service, s.playbook].filter(Boolean).join(" ").toLowerCase();
        const word = (l.choices.find(c => c.id === it.answer)?.label ?? "").split(/[ (:]/)[0].toLowerCase();
        if (word.length > 2 && bar.includes(word)) bad.push(`${r.id} / ${l.title} / ${it.id}: "${word}"`);
      }
    }
    expect(bad).toEqual([]);
  });

  it("a tune row or a portal record id never states its own verdict (R9)", () => {
    const VERDICT = /\b(stolen|attacker|thief|thieves|compromised|rogue|fake|replayed|leaked|red team|past case|malicious|intruder)\b/i;
    // Exempt: rows that are closed cases with their known outcome, or lines of a report being edited.
    const LABELLED = /closed case|^line (from|for)/i;
    const bad: string[] = [];
    for (const r of rooms) for (const l of r.labs) {
      if (l.kind === "tune" && !LABELLED.test(l.eventColumn)) {
        for (const e of l.events) if (VERDICT.test(e.label)) bad.push(`${r.id} / ${l.title} / ${e.id}: "${e.label}"`);
        if (VERDICT.test(l.eventColumn)) bad.push(`${r.id} / ${l.title}: column "${l.eventColumn}"`);
      }
      if (l.kind === "portal") {
        const ids = [...Object.keys(l.records), ...Object.values(l.pages).flatMap(p => p.table?.rows.map(row => row.id) ?? [])];
        for (const id of ids) if (VERDICT.test(id.replace(/-/g, " "))) bad.push(`${r.id} / ${l.title}: id "${id}"`);
      }
    }
    expect(bad).toEqual([]);
  });

  it("the console stays in the rooms that teach the command line", () => {
    const over: string[] = [];
    for (const r of rooms) {
      const n = r.labs.filter(l => l.kind === "terminal").length;
      if (n > (CONSOLE_ROOMS.has(r.id) ? 1 : 0)) over.push(`${r.id}: ${n} console labs`);
    }
    expect(over).toEqual([]);
  });

  it("every room has at least two games, and no two rooms share the same mix", () => {
    const seen = new Map<string, string>();
    const bad: string[] = [];
    // Practical-mission rooms (SPEC-practical-missions.md, decision 2) replaced their arcade labs with graded missions.
    const missionRooms = new Set(ROOMS.filter(r => r.tasks.some(t => t.type === "mission")).map(r => r.id));
    for (const r of rooms) {
      if (missionRooms.has(r.id)) continue;
      const mix = [...new Set(r.labs.map(l => l.kind as string).filter(k => (ARCADE as readonly string[]).includes(k)))].sort().join("+");
      if (mix.split("+").filter(Boolean).length < 2) bad.push(`${r.id}: mix "${mix}"`);
      else if (seen.has(mix)) bad.push(`${r.id} and ${seen.get(mix)} both use ${mix}`);
      seen.set(mix, r.id);
    }
    expect(bad).toEqual([]);
  });
});
