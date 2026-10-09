/**
 * ATT&CK v19 guard. The content gates (validate-content / validate-scenarios)
 * cover lessons, quizzes, rooms and scenario debriefs, but not the live-feed
 * corpora (attackStories, ai-stories, companyProfiles, native log modules).
 * This scans every structured ATT&CK field in src/ instead, so a revoked v18
 * ID or the retired "Defense Evasion" tactic label cannot slip back in.
 */
import { describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
// Plain .mjs helper shared with the content gates (validate-content / validate-scenarios).
import { isRevokedId, REVOKED as REVOKED_MAP } from "../../../scripts/attack-deprecated.mjs";
import { TACTICS, TECHNIQUES, tacticById, techniqueById } from "./attack";

const SRC = path.join(process.cwd(), "src");
const REVOKED: Record<string, string> = REVOKED_MAP;

function* walk(dir: string): Generator<string> {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) yield* walk(full);
    else if (/\.(ts|tsx|json)$/.test(e.name) && !e.name.endsWith(".test.ts")) yield full;
  }
}
const FILES = [...walk(SRC)].map(f => ({ f: path.relative(process.cwd(), f), text: fs.readFileSync(f, "utf8") }));

// mitre_technique: "T…", "mitre_technique": "T…", mitreTechnique, mitre: "T…" / mitre: ["T…", …],
// threat.technique(.subtechnique).id, crowdstrike.TechniqueId
const ID_FIELD = /(?:\bmitre_technique|"mitre_technique"|\bmitreTechnique|"mitreTechnique"|\bmitre|"threat\.technique(?:\.subtechnique)?\.id"|"crowdstrike\.TechniqueId")\s*:\s*(\[[^\]]*\]|"[^"]*")/g;
const TACTIC_FIELD = /(?:\b(?:tactic|mitre_tactic|phase)|"mitre_tactic"|"crowdstrike\.Tactic"|"threat\.tactic\.name")\s*:\s*"(Defense Evasion[^"]*)"/g;

describe("ATT&CK v19 consistency", () => {
  it("no structured field carries a revoked or retired technique ID", () => {
    const bad: string[] = [];
    for (const { f, text } of FILES) {
      for (const m of text.matchAll(ID_FIELD)) {
        for (const id of m[1].match(/T1\d{3}(?:\.\d{3})?/g) ?? []) {
          if (isRevokedId(id)) bad.push(`${f}: ${id}${REVOKED[id] ? ` -> ${REVOKED[id]}` : ""}`);
        }
      }
    }
    expect(bad).toEqual([]);
  });

  it("no tactic field still uses the pre-v19 name Defense Evasion", () => {
    const bad: string[] = [];
    for (const { f, text } of FILES) {
      for (const m of text.matchAll(TACTIC_FIELD)) bad.push(`${f}: ${m[0]}`);
    }
    expect(bad).toEqual([]);
  });

  it("every technique ID cited in a structured field has a library entry", () => {
    // The MITRE drawer (EventFeed MitreSlideout) reads this library; a missing ID shows only a link.
    const missing = new Set<string>();
    for (const { f, text } of FILES) {
      if (f.includes(path.join("lib", "mitre"))) continue;
      for (const m of text.matchAll(ID_FIELD)) {
        for (const id of m[1].match(/T1\d{3}(?:\.\d{3})?/g) ?? []) {
          if (!isRevokedId(id) && !techniqueById(id)) missing.add(id);
        }
      }
    }
    expect([...missing].sort()).toEqual([]);
  });

  it("library entries are unique and sub-technique names carry the parent name", () => {
    const ids = TECHNIQUES.map(t => t.id);
    expect(ids.length).toBe(new Set(ids).size);
    for (const t of TECHNIQUES) {
      const parent = t.id.includes(".") ? techniqueById(t.id.split(".")[0]) : undefined;
      if (parent) expect(t.name.startsWith(`${parent.name}: `), `${t.id} ${t.name}`).toBe(true);
      if (t.tactics) expect(t.tactics, t.id).toContain(t.tactic);
    }
  });

  it("catalog uses the v19 tactics", () => {
    expect(tacticById("TA0005")?.name).toBe("Stealth");
    expect(tacticById("TA0112")?.name).toBe("Defense Impairment");
    expect(TACTICS.some(t => t.name === "Defense Evasion")).toBe(false);
    for (const t of TECHNIQUES) {
      expect(isRevokedId(t.id), t.id).toBe(false);
      expect(tacticById(t.tactic), `${t.id} tactic ${t.tactic}`).toBeDefined();
    }
  });
});
