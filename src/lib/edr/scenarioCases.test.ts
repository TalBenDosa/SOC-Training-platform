// EDR cases built from scenarios must tell the scenario's story (audit 2026-10-22):
// false positives have no payload, a Mac is a Mac, one host per process tree, and the
// host's address is its own, never the attacker's.
import { describe, it, expect } from "vitest";
import { SCENARIOS } from "@/lib/sim/scenarios";
import { buildInvestigationsFromScenario } from "./fromLiveStory";
import { benignIncidentIds, withDefaultIncidents } from "@/lib/scenarios/incidentGroups";
import { buildAlertIndex } from "@/lib/scenarios/eventClass";
import type { TelemetryEvent } from "@/lib/sim/types";

type Built = { slug: string; attack_kind?: string; build: () => { title: string; attack_kind?: string; events: TelemetryEvent[] } };
const all = (SCENARIOS as unknown as Built[]).map(sc => {
  const b = sc.build();
  const events = withDefaultIncidents(b.events, sc.slug);
  const idx = buildAlertIndex(b.events);
  const benign = new Set(benignIncidentIds(b.events, sc.slug, b.attack_kind ?? sc.attack_kind, e => !!e.id && idx.has(e.id)));
  // the student's copy: what the page ships (no verdict fields)
  const shipped = events.map(e => ({ ...e, description: undefined, mitre_technique: undefined, mitre_tactic: undefined, expected_verdict: undefined }));
  return { slug: sc.slug, title: b.title, events, cases: buildInvestigationsFromScenario({ title: b.title, events: shipped }, { benignIncidents: benign }) };
});

describe("scenario EDR cases", () => {
  it("false-positive scenarios have no payload: Resolve as benign is the right call", () => {
    for (const slug of ["backup-agent-false-positive", "software-install-false-positive"]) {
      const s = all.find(x => x.slug === slug)!;
      expect(s.cases.length, slug).toBeGreaterThan(0);
      for (const c of s.cases) expect(c.answer.pid, `${slug}/${c.id}`).toBe(-1);
    }
  });

  it("a Mac is labelled macOS and never gets a made-up bash root", () => {
    for (const s of all) for (const c of s.cases) {
      const macPaths = c.processes.some(p => /^\/(Applications|Users|Library|System|private|Volumes)\//.test(p.path) || /\.app\//.test(p.path));
      if (!macPaths) continue;
      expect(c.host.os, `${s.slug}/${c.id}`).toMatch(/^macOS/);
      const inventedBash = c.processes.filter(p => p.name === "bash" && p.startedAt === "—"
        && !s.events.some(e => e.process?.name === "bash" || e.process?.parent_name === "bash"));
      expect(inventedBash.map(p => p.pid), `${s.slug}/${c.id}`).toEqual([]);
    }
  });

  it("a case split per host holds only that host's processes", () => {
    for (const s of all) for (const c of s.cases) {
      const [, host] = c.id.split("@");
      if (!host) continue;
      for (const p of c.processes) {
        if (p.startedAt === "—") continue; // an ancestor stub
        const owners = new Set(s.events.filter(e => e.process?.pid === p.pid).map(e => e.hostname).filter(Boolean));
        if (owners.size) expect([...owners], `${s.slug}/${c.id} pid ${p.pid}`).toContain(host);
      }
    }
  });

  it("the host's address comes from its own process telemetry, not a logon's remote end", () => {
    for (const s of all) for (const c of s.cases) {
      const own = s.events.filter(e => e.hostname === c.host.name && /^process/.test(e.event_type ?? "") && e.src_ip).map(e => e.src_ip as string);
      if (!own.length) continue;
      expect(own, `${s.slug}/${c.id}: host ip ${c.host.ip}`).toContain(c.host.ip);
    }
  });
});
