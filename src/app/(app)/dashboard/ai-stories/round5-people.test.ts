// AI round, people families: every row renders in its product's native format on the companies the story runs on,
// the Team Training variants stay inside a Sentinel workspace's own records, and the two variants of a family share
// no people, addresses or plot (Tal, 2026-11-12: "other data, other stories").
import { describe, expect, it, vi } from "vitest";
vi.mock("server-only", () => ({}));
import { nativeView, applyStack } from "@/lib/logs/native";
import { validateNative } from "@/lib/logs/native/validate";
import { NATIVE_SOURCES } from "@/lib/logs/native/index";
import { stackFor } from "@/lib/logs/native/index";
import { NOT_SENTINEL, stackForConsole } from "@/lib/team/investigationConsole";
import { ATTACK_STORIES } from "@/app/(app)/dashboard/attackStories";
import { AI_R5_PEOPLE_STORIES } from "./round5-people";
import { collectDocIps } from "@/lib/sim/variation";

const XDR = stackForConsole({}, "sentinel");
const ids = AI_R5_PEOPLE_STORIES.map(s => s.id);

describe("AI round, people families", () => {
  it("two families, one solo and one team variant each, in the catalog", () => {
    expect(ids).toHaveLength(4);
    for (const fam of ["ai-crescendo-jailbreak", "ai-fake-it-worker"]) {
      const v = AI_R5_PEOPLE_STORIES.filter(s => s.family === fam);
      expect(v.map(s => s.mode).sort(), fam).toEqual(["solo", "team"]);
    }
    for (const s of AI_R5_PEOPLE_STORIES) {
      const cat = ATTACK_STORIES.find(x => x.id === s.id);
      expect(cat, s.id).toBeDefined();
      expect(cat!.family).toBe(s.family);
      expect(!!cat!.teamOnly, s.id).toBe(s.mode === "team");
    }
  });

  for (const s of AI_R5_PEOPLE_STORIES) {
    it(`${s.id}: every row renders natively without a violation on its companies`, () => {
      const bad: string[] = [];
      for (const c of s.companies) {
        const stack = stackFor(c);
        for (const e of s.events) {
          const v = nativeView(applyStack(e, c, stack), c, stack);
          if (!v) continue;
          const mod = NATIVE_SOURCES[v.log.sourceId];
          if (!mod) continue;
          const errs = validateNative(v.log, mod.schema);
          if (errs.length) bad.push(`${c} ${e.id} ${v.log.sourceId}: ${JSON.stringify(errs.slice(0, 2))}`);
        }
      }
      expect(bad).toEqual([]);
    });
  }

  for (const s of AI_R5_PEOPLE_STORIES.filter(x => x.mode === "team")) {
    it(`${s.id}: an XDR session shows no other vendor's record`, () => {
      const foreign: string[] = [];
      for (const c of s.companies) for (const e of s.events) {
        const id = nativeView(applyStack(e, c, XDR), c, XDR)?.log.sourceId;
        if (id && NOT_SENTINEL.has(id)) foreign.push(`${e.id} as ${id}`);
      }
      expect(foreign).toEqual([]);
    });
  }

  it("the solo and team variants of a family share no person and no address", () => {
    for (const fam of ["ai-crescendo-jailbreak", "ai-fake-it-worker"]) {
      const [a, b] = AI_R5_PEOPLE_STORIES.filter(s => s.family === fam);
      const people = (evs: typeof a.events) => new Set(evs.map(e => e.user_email?.split("@")[0]).filter(Boolean));
      const ips = (evs: typeof a.events) => { const out = new Set<string>(); for (const e of evs) collectDocIps(e, out); return out; };
      const pa = people(a.events), ia = ips(a.events);
      expect([...people(b.events)].filter(p => pa.has(p)), fam).toEqual([]);
      expect([...ips(b.events)].filter(ip => ia.has(ip)), fam).toEqual([]);
    }
  });

  it("each story carries a benign look-alike and a factual description on every row", () => {
    for (const s of AI_R5_PEOPLE_STORIES) {
      expect(s.events.some(e => e.expected_verdict === "fp"), s.id).toBe(true);
      for (const e of s.events) {
        expect(e.description && e.description.length > 20, `${s.id} ${e.id}`).toBe(true);
        expect(JSON.stringify(e), `${s.id} ${e.id} em dash`).not.toContain(String.fromCharCode(0x2014));
      }
    }
  });
});
