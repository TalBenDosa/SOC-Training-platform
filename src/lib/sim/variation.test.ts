import { describe, it, expect } from "vitest";
import { ATTACK_STORIES, instantiateStory } from "@/app/(app)/dashboard/attackStories";
import { companyFeedPool, feedCompanyProfile } from "@/app/(app)/dashboard/feedPool";
import { BENIGN_EVENTS } from "@/app/(app)/dashboard/benignEvents";
import { COMPANY_EVENTS } from "@/lib/sim/companyProfiles";
import { COMPANY_ASSETS } from "@/lib/sim/companyProfilesMeta";
import { docOwnerOfIp } from "@/lib/sim/docAddresses";
import { varyAttackerInfra, collectDocIps } from "./variation";
import type { TelemetryEvent } from "./types";

/*
 * The variation layer (Tal 2026-11-12): the same storyline never shows the same attacker infrastructure twice,
 * and the swap keeps the plot whole.
 */
const CO = "rocketstack";
const POOL = companyFeedPool({ BENIGN_EVENTS, COMPANY_EVENTS }, CO);
const EDR = feedCompanyProfile(CO).architecture?.edr;
const attackRow = (e: TelemetryEvent) => !e.is_baseline && e.expected_verdict !== "fp" && !e.fp_explanation;
const attackIps = (events: TelemetryEvent[]) => { const s = new Set<string>(); for (const e of events) if (attackRow(e)) collectDocIps(e, s); return s; };
const render = (id: string, seed: string, used?: Set<string>) => instantiateStory(ATTACK_STORIES.find(s => s.id === id)!, POOL, EDR, CO, () => 0.5, { seed, usedIps: used });

// Stories with attacker addresses that this company can be dealt (their attack rows name documentation addresses).
const SAMPLE = ATTACK_STORIES.filter(s => (s.companies ?? []).includes(CO) && attackIps(s.events).size > 0).slice(0, 12).map(s => s.id);

describe("variation layer: attacker infrastructure", () => {
  it("has a sample to check", () => expect(SAMPLE.length).toBeGreaterThanOrEqual(5));

  it("two sessions show different attacker addresses; one session replays the same", () => {
    let changed = 0, total = 0;
    for (const id of SAMPLE) {
      const a = attackIps(render(id, "session-a").events), b = attackIps(render(id, "session-b").events), a2 = attackIps(render(id, "session-a").events);
      expect([...a2].sort(), id).toEqual([...a].sort());
      total += a.size;
      changed += [...a].filter(ip => !b.has(ip)).length;
    }
    expect(changed / total).toBeGreaterThan(0.6);
  });

  it("no original attacker address survives anywhere in a render it was swapped in, and the text follows", () => {
    for (const id of SAMPLE) {
      const story = ATTACK_STORIES.find(s => s.id === id)!;
      const base = instantiateStory(story, POOL, EDR, CO, () => 0.5);   // fixed draw: the reference render
      const { story: out, variation } = varyAttackerInfra(base, POOL, CO, (() => { let x = 0.17; return () => (x = (x * 9301 + 0.49297) % 1); })());
      const blob = JSON.stringify(out);
      for (const [from, to] of Object.entries(variation.ips)) {
        expect(blob, `${id}: ${from} left behind`).not.toMatch(new RegExp(`(?<![\\d.])${from.replace(/\./g, "\\.")}(?![\\d])`));
        const before = base.events.filter(e => (e.description ?? "").includes(from)).length;
        const after = out.events.filter(e => (e.description ?? "").includes(to)).length;
        expect(after, `${id}: descriptions naming ${from}`).toBe(before);
      }
    }
  });

  it("never swaps the company's offices, its ordinary noise or a known operator", () => {
    const offices = new Set(Object.values(COMPANY_ASSETS).map(a => a.office?.ip).filter((x): x is string => !!x));
    const noise = new Set<string>(); for (const e of POOL) collectDocIps(e, noise);
    for (const id of SAMPLE) {
      const base = instantiateStory(ATTACK_STORIES.find(s => s.id === id)!, POOL, EDR, CO, () => 0.5);
      const { variation } = varyAttackerInfra(base, POOL, CO, Math.random);
      for (const from of Object.keys(variation.ips)) {
        expect(offices.has(from), `${id} office ${from}`).toBe(false);
        expect(noise.has(from), `${id} noise ${from}`).toBe(false);
        expect(docOwnerOfIp(from), `${id} operator ${from}`).toBeUndefined();
      }
    }
  });

  it("the storylines of one session never share an attacker address", () => {
    const used = new Set<string>();
    const seen = new Map<string, string>();
    for (const id of SAMPLE) for (const ip of attackIps(render(id, "one-session", used).events)) {
      const owner = seen.get(ip);
      // An address the story authored and kept (an operator, a placed address) may recur; a drawn one never does.
      if (owner && used.has(ip)) throw new Error(`${ip} drawn for both ${owner} and ${id}`);
      seen.set(ip, id);
    }
  });
});
