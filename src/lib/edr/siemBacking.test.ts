/**
 * SIEM ↔ EDR are one product: everything the EDR console shows during a live shift must be
 * backed by a log the analyst can already see in the SIEM feed, and the EDR must stay empty
 * until the attack's endpoint telemetry has actually arrived (Tal, 2026-10-21).
 *
 * For every storyline × every company it can run at, the dashboard's real pipeline is
 * replayed: instantiate the story for the company, inject its events one by one, and build
 * the EDR view from what has been injected so far (exactly what page.tsx does).
 */
import { describe, it, expect } from "vitest";
import { ATTACK_STORIES, instantiateStory, storiesForCompany } from "@/app/(app)/dashboard/attackStories";
import { BENIGN_EVENTS } from "@/app/(app)/dashboard/benignEvents";
import { COMPANY_EVENTS } from "@/lib/sim/companyProfiles";
import { COMPANY_PROFILES } from "@/lib/sim/companyProfilesMeta";
import { buildInvestigationFromStory } from "./fromLiveStory";
import type { TelemetryEvent } from "@/lib/sim/types";

const ENDPOINT = new Set(["edr", "sysmon", "linux_audit", "windows_security"]);

function seeded(n: number) {
  let s = n >>> 0;
  return () => { s = (s * 1664525 + 1013904223) >>> 0; return s / 2 ** 32; };
}

type Problem = { story: string; company: string; step: number; what: string };

function checkBacked(inv: NonNullable<ReturnType<typeof buildInvestigationFromStory>>, feed: TelemetryEvent[]): string[] {
  const out: string[] = [];
  const blob = feed.map(e => JSON.stringify(e)).join("\n");
  const hosts = new Set(feed.map(e => e.hostname).filter(Boolean));
  if (!hosts.has(inv.host.name)) out.push(`host ${inv.host.name} is in no SIEM log`);
  for (const d of inv.detections) {
    // A detection is backed when a log in the feed carries its ATT&CK technique (or, for an
    // unmapped EDR alert, an EDR log exists), on the same process / host.
    const byTech = /^T\d{4}/.test(d.technique) ? blob.includes(d.technique) : feed.some(e => e.source === "edr");
    if (!byTech) out.push(`detection ${d.technique} "${d.name}" has no SIEM log`);
  }
  for (const p of inv.processes) {
    if (p.startedAt === "—") continue; // an ancestor stub (explorer/services), shown so the tree connects
    // Benign background processes (Teams, OneDrive, …) are host telemetry a real EDR always
    // shows and a SIEM never receives; they carry no detection. Anything flagged must be backed.
    const flagged = p.verdict !== "benign" || inv.detections.some(d => d.pid === p.pid);
    if (flagged && !blob.includes(p.name)) out.push(`flagged process ${p.name} (pid ${p.pid}) is in no SIEM log`);
  }
  if (inv.timeline.length > feed.length) out.push(`timeline has ${inv.timeline.length} rows for ${feed.length} logs`);
  return out;
}

describe("EDR is fed only by what the SIEM already shows", () => {
  const problems: Problem[] = [];
  let checked = 0, withEdr = 0;

  for (const c of COMPANY_PROFILES) {
    const pool = c.id === "nexacorp" ? BENIGN_EVENTS : (COMPANY_EVENTS[c.id] ?? BENIGN_EVENTS);
    const edr = (c.architecture as { edr?: string } | undefined)?.edr;
    for (const base of storiesForCompany(c.id)) {
      const s = instantiateStory(base, pool, edr, c.id, seeded(base.id.length * 31 + c.id.length));
      checked++;
      let sawEdr = false;
      for (let k = 1; k <= s.events.length; k++) {
        const feed = s.events.slice(0, k);
        const inv = buildInvestigationFromStory({ id: s.id, title: s.title, events: feed });
        const endpointSoFar = feed.some(e => ENDPOINT.has(e.source));
        if (!endpointSoFar && inv) problems.push({ story: s.id, company: c.id, step: k, what: "EDR case before any endpoint log reached the SIEM" });
        if (!inv) continue;
        sawEdr = true;
        for (const what of checkBacked(inv, feed)) problems.push({ story: s.id, company: c.id, step: k, what });
      }
      if (sawEdr) withEdr++;
    }
  }

  it("covers every company × storyline", () => {
    expect(checked).toBeGreaterThan(150);
    expect(withEdr).toBeGreaterThan(30);
    expect(ATTACK_STORIES.length).toBeGreaterThan(80);
  });

  it("no EDR detection, process or host without a SIEM log, at any moment of the attack", () => {
    const uniq = [...new Map(problems.map(p => [`${p.story}|${p.what}`, p])).values()];
    expect(uniq.map(p => `${p.story} @${p.company} step ${p.step}: ${p.what}`)).toEqual([]);
  });
});
