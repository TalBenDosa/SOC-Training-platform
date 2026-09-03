import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { buildClipboardClipperScenario } from "./clipboardClipper";
import { buildInvestigationsFromScenario } from "@/lib/edr/fromLiveStory";

// Packs that have been fully converted to the vendor emitters. Each MUST stay 100%
// emitter-authored — no hand-typed `raw: { … }` block may creep back in, because that
// is exactly the drift the emitter layer exists to prevent (a hand-typed field can be
// wrong; an emitter-rendered one is registry-correct by construction).
const FULLY_EMITTER_AUTHORED = ["clipboardClipper.ts"];

describe("emitter-authored scenario packs", () => {
  it.each(FULLY_EMITTER_AUTHORED)("%s contains no hand-authored raw blocks", (file) => {
    const src = fs.readFileSync(path.resolve("src/lib/sim/scenario-packs", file), "utf-8");
    // Any `raw: {` literal in the source is a hand-typed vendor block — forbidden here.
    const handRaw = (src.match(/\braw:\s*\{/g) ?? []).length;
    expect(handRaw, `${file} has ${handRaw} hand-authored raw block(s); use the emitters`).toBe(0);
  });

  it("clipboardClipper still builds a coherent, correct incident from emitters only", () => {
    const s = buildClipboardClipperScenario();
    expect(s.events.length).toBe(8);
    // the whole chain lands on one company host, correctly correlated
    const inv = buildInvestigationsFromScenario({ title: s.title, events: s.events })[0];
    expect(inv.host.name).toBe("LAP-5528");
    expect(inv.processes.some(p => p.name === "cmd.exe" && p.ppid === 6214)).toBe(true);
    expect(inv.processes.some(p => p.name === "clipsvc_helper.exe" && p.ppid === 6214)).toBe(true);
    expect(inv.detections.map(d => d.technique).sort()).toEqual(["T1059.003", "T1115", "T1204.002"]);
    const payload = inv.processes.find(p => p.pid === inv.answer.pid);
    expect(payload?.name).toBe("clipsvc_helper.exe");
    // one hash → one file across the whole pack
    const byHash = new Map<string, Set<string>>();
    for (const e of s.events) {
      const h = e.process?.hash?.sha256 ?? e.file?.sha256;
      const nm = e.process?.name ?? e.file?.name;
      if (h && nm) { const set = byHash.get(h) ?? new Set(); set.add(nm); byHash.set(h, set); }
    }
    expect([...byHash.values()].every(n => n.size === 1)).toBe(true);
  });
});
