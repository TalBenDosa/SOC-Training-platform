import { describe, it, expect, vi } from "vitest";

// buildTimeline is server-only in the app; the guard module throws outside a
// react-server bundle, so stub it for the unit test.
vi.mock("server-only", () => ({}));

import {
  buildTeamTimeline, TEAM_ANSWER_FIELDS, TEAM_TIME_BASE_MS,
  classifyStoryEvent, classifyPoolEvent, scrubClockPhrases, resolveTeamStory,
} from "./buildTimeline";
import { BENIGN_EVENTS } from "@/app/(app)/dashboard/benignEvents";
import { storiesForCompany, instantiateStory } from "@/app/(app)/dashboard/attackStories";
import type { TelemetryEvent } from "@/lib/sim/types";

const COMBOS: [string, "easy" | "medium" | "hard"][] = [
  ["nexacorp", "easy"], ["nexacorp", "medium"], ["quantumbank", "hard"], ["rocketstack", "medium"], ["medcore", "hard"],
];
const TIER = { easy: "foundation", medium: "core", hard: "advanced" } as const;

describe("buildTeamTimeline — answer key off the wire (audit S4)", () => {
  // Story CHOICE deliberately avoids recently used stories (pickStoryForCompany's
  // anti-repeat memory), so two builds may differ — the timeline is generated once
  // at start and stored, which is what makes every member replay the same incident.
  // The public ids, however, must be a pure function of (seed, position).
  it("opaque ids are a pure function of (seed, position)", () => {
    const feedIds = (seed: string) => buildTeamTimeline("nexacorp", "medium", seed).filter(e => e.channel === "feed").map(e => e.body.id);
    const a = feedIds("seed-1");
    const b = feedIds("seed-1");
    const n = Math.min(a.length, b.length);
    expect(n).toBeGreaterThan(0);
    // feed ids = f(seed, position): the two builds share exactly the ids of the shorter feed
    expect(new Set(a).size).toBe(a.length);
    expect(a.filter(id => b.includes(id)).length).toBe(n);
    const c = buildTeamTimeline("nexacorp", "medium", "seed-2").map(e => e.body.id);
    expect(c.filter(id => a.includes(id)).length).toBe(0);   // a different seed never reuses ids
  });

  it.each(COMBOS)("%s/%s: no public body carries an answer field", (company, diff) => {
    const tl = buildTeamTimeline(company, diff, "s");
    expect(tl.length).toBeGreaterThan(0);
    for (const e of tl) {
      for (const k of TEAM_ANSWER_FIELDS) expect(e.body).not.toHaveProperty(k);
      if (e.channel === "inject") {
        expect(e.body).not.toHaveProperty("expected_response");
        expect(e.body).not.toHaveProperty("linked_objective");
        expect(["update", "mgmt_request", "ticket", "announcement"]).toContain(e.body.kind);
      }
    }
  });

  it.each(COMBOS)("%s/%s: ids are opaque + unique, and every log has the session tier", (company, diff) => {
    const tl = buildTeamTimeline(company, diff, "s");
    const ids = tl.map(e => String(e.body.id));
    expect(new Set(ids).size).toBe(ids.length);
    for (const e of tl) {
      expect(String(e.body.id)).toMatch(/^[em][0-9a-f]{12}$/);
      if (e.channel === "feed") expect(e.body.tier).toBe(TIER[diff]);
    }
  });

  it("keeps the ground truth in the answer (server-side only)", () => {
    const tl = buildTeamTimeline("nexacorp", "medium", "s");
    const attacks = tl.filter(e => e.channel === "feed" && ["tp", "escalate"].includes(String(e.answer?.expected_verdict)));
    expect(attacks.length).toBeGreaterThan(0);
    expect(attacks.every(e => typeof e.answer?.original_id === "string")).toBe(true);
    const kinds = tl.filter(e => e.channel === "inject").map(e => e.answer?.kind);
    expect(kinds).toEqual(expect.arrayContaining(["twist", "false_lead", "mgmt_pressure", "ticket"]));
    const twist = tl.find(e => e.answer?.kind === "twist");
    expect(twist?.body.kind).toBe("update");
    expect(typeof twist?.answer?.expected_response).toBe("string");
  });

  it("easy shifts have no curveballs and a single-threaded story", () => {
    const tl = buildTeamTimeline("nexacorp", "easy", "s");
    expect(tl.some(e => e.channel === "inject")).toBe(false);
  });

  it("dates don't mark the attack: every feed log sits on one synthetic base, raw{} included", () => {
    for (const diff of ["medium", "hard"] as const) {
      const tl = buildTeamTimeline("quantumbank", diff, "s").filter(e => e.channel === "feed");
      const attack = tl.filter(e => ["tp", "escalate"].includes(String(e.answer?.expected_verdict)));
      expect(attack.length).toBeGreaterThan(0);
      for (const e of tl) {
        expect(e.body.ts).toBe(new Date(TEAM_TIME_BASE_MS + e.due_offset_ms).toISOString());
        // no raw timestamp is left on an authored template date (May/June 2026)
        expect(JSON.stringify(e.body.raw ?? {})).not.toMatch(/2026-0[56]-d{2}[T ]d{2}:/);
      }
    }
  });
});

// ── 2026-09-27 live-playtest fix round (contract 1 + content) ─────────────────
type Diff = "easy" | "medium" | "hard";
const ALL_COMBOS: [string, Diff][] = (["nexacorp", "medcore", "globallogis", "rocketstack", "quantumbank"] as const)
  .flatMap(c => (["easy", "medium", "hard"] as const).map(d => [c, d] as [string, Diff]));
const VERDICTS = ["tp", "escalate", "benign", "fp"];

describe("buildTeamTimeline — answer key (contract 1)", () => {
  it.each(ALL_COMBOS)("%s/%s: every feed answer has an explicit verdict; every incident log has an incident_id", (company, diff) => {
    for (const seed of ["s", "bec9df68"]) {
      const feed = buildTeamTimeline(company, diff, seed).filter(e => e.channel === "feed");
      expect(feed.length).toBeGreaterThan(0);
      for (const e of feed) {
        expect(VERDICTS).toContain(e.answer?.expected_verdict);
        const origin = e.answer?.origin;
        // every story event — malicious steps AND the legitimate control steps — belongs to an incident
        if (origin === "story") expect(typeof e.answer?.incident_id).toBe("string");
        // every malicious log (story step, standalone pool attack, twist beacon) belongs to an incident
        if (["tp", "escalate"].includes(String(e.answer?.expected_verdict))) expect(typeof e.answer?.incident_id).toBe("string");
        if (origin === "noise" || origin === "itsm") expect(e.answer?.incident_id).toBeUndefined();
      }
      expect(feed.some(e => e.answer?.origin === "story")).toBe(true);
    }
  });

  it("story control steps are benign, not tp (ra_01 ticket, ra_02 approved account, fbu_01 site visit)", () => {
    const stories = [...storiesForCompany("nexacorp", "medium"), ...storiesForCompany("nexacorp", "easy")];
    const ev = (id: string) => stories.flatMap(s => s.events).find(e => e.id === id) as TelemetryEvent;
    expect(classifyStoryEvent(ev("evt_ra_01_ticket"))).toBe("benign");
    expect(classifyStoryEvent(ev("evt_ra_02_baseline_create"))).toBe("benign");
    expect(classifyStoryEvent(ev("evt_fbu_01_site_visit"))).toBe("benign");
    expect(classifyStoryEvent(ev("evt_ra_05_acct_create"))).toBe("tp");
    expect(classifyStoryEvent(ev("evt_ra_06_group_add_domain"))).toBe("tp");
    expect(classifyStoryEvent(ev("evt_fbu_02_overlay_fetch"))).toBe("tp");
  });

  it("malicious events hiding in the noise pool are tp/escalate, decoys are fp", () => {
    const byId = (id: string) => BENIGN_EVENTS.find(e => e.id === id) as TelemetryEvent;
    for (const id of ["b_fwd_atk_01", "b_fwd_atk_02", "b_copy_atk_01", "b_copy_atk_02", "b_email_replyto_mismatch", "b_email_spf_fail_lookalike", "b_bf_04"]) {
      expect(["tp", "escalate"], id).toContain(classifyPoolEvent(byId(id)));
    }
    expect(classifyPoolEvent(byId("b_fwd_fp_01"))).toBe("fp");
    expect(classifyPoolEvent(byId("b_itv_02"))).toBe("fp");
    expect(classifyPoolEvent(byId("b_dns_08"))).toBe("benign");
  });

  it("no public body carries IT-verification text or any other answer field", () => {
    for (const [c, d] of ALL_COMBOS) {
      for (const e of buildTeamTimeline(c, d, "s")) {
        for (const k of TEAM_ANSWER_FIELDS) expect(e.body).not.toHaveProperty(k);
      }
    }
  });
});

describe("buildTeamTimeline — scripted injects are backed by telemetry", () => {
  it.each(["s", "bec9df68", "seed-2"])("seed %s: twist beacons + false-lead transfers exist, deterministic from the seed", (seed) => {
    const tl = buildTeamTimeline("nexacorp", "medium", seed);
    const twist = tl.find(e => e.answer?.original_id === "msel_twist")!;
    const lead = tl.find(e => e.answer?.original_id === "msel_false_lead")!;
    const beacons = tl.filter(e => e.answer?.supports_inject === "msel_twist");
    expect(beacons.length).toBeGreaterThanOrEqual(2);
    for (const b of beacons) {
      expect(b.channel).toBe("feed");
      expect(b.answer?.expected_verdict).toBe("tp");
      expect(b.due_offset_ms).toBeGreaterThan(twist.due_offset_ms);
    }
    // the beacon belongs to a running attack story's incident, on a host that story used
    const inc = beacons[0].answer?.incident_id;
    expect(new Set(beacons.map(b => b.answer?.incident_id)).size).toBe(1);
    const storyLogs = tl.filter(e => e.answer?.origin === "story" && e.answer?.incident_id === inc);
    expect(storyLogs.length).toBeGreaterThan(0);
    // (an identity-only story pair has no endpoint to beacon from — then only the incident link holds)
    const storyHasHost = tl.some(e => e.answer?.origin === "story" && e.body.hostname && ["tp", "escalate"].includes(String(e.answer?.expected_verdict)));
    if (storyHasHost) expect(storyLogs.map(e => e.body.hostname)).toContain(beacons[0].body.hostname);

    const saas = tl.filter(e => e.answer?.supports_inject === "msel_false_lead");
    expect(saas.filter(e => e.body.source === "firewall").length).toBeGreaterThanOrEqual(2);
    for (const e of saas) expect(["benign", "fp"]).toContain(e.answer?.expected_verdict);
    expect(saas.some(e => Math.abs(e.due_offset_ms - lead.due_offset_ms) < 120_000)).toBe(true);

    // placement is a pure function of the seed (story choice aside)
    const again = buildTeamTimeline("nexacorp", "medium", seed).filter(e => e.answer?.supports_inject === "msel_false_lead");
    expect(again.map(e => e.body.description)).toEqual(saas.map(e => e.body.description));
  });
});

describe("buildTeamTimeline — shift length (recycling)", () => {
  it("medium covers ~34–36 min; easy and hard stay proportional", () => {
    const spanMin = (c: string, d: Diff, seed: string) => {
      const feed = buildTeamTimeline(c, d, seed).filter(e => e.channel === "feed");
      return feed[feed.length - 1].due_offset_ms / 60000;
    };
    const med = ["a", "b", "c", "d"].map(s => spanMin("nexacorp", "medium", s));
    const avg = med.reduce((a, b) => a + b, 0) / med.length;
    expect(avg).toBeGreaterThan(33);
    expect(avg).toBeLessThan(37);
    expect(spanMin("nexacorp", "easy", "a")).toBeGreaterThan(21);
    expect(spanMin("nexacorp", "hard", "a")).toBeGreaterThan(31);
  });
});

describe("content hygiene", () => {
  it("scrubs narrated clock times and relative delays from story prose", () => {
    expect(scrubClockPhrases("At 22:47 the t.aharoni account opened a session.")).toBe("The t.aharoni account opened a session.");
    expect(scrubClockPhrases("LAP-4471 loaded an article page on logisticsweekly.com at 13:42, allowed under business.")).toBe("LAP-4471 loaded an article page on logisticsweekly.com, allowed under business.");
    expect(scrubClockPhrases("Fourteen seconds later she double-clicked the file.")).toBe("She double-clicked the file.");
    expect(scrubClockPhrases("One second later cmd.exe spawned powershell.exe.")).toBe("cmd.exe spawned powershell.exe.");
    expect(scrubClockPhrases("powershell.exe on WS-1 connected to 1.2.3.4:443")).toBe("powershell.exe on WS-1 connected to 1.2.3.4:443");
  });

  it("domain events land on the DC and a LogonId never spans two machines (rogue-admin on NexaCorp)", () => {
    const story = storiesForCompany("nexacorp", "medium").find(s => s.id === "rogue-admin")!;
    expect(story).toBeTruthy();
    const code = (e: TelemetryEvent) => String(e.raw?.["winlog.event_id"] ?? e.raw?.["event.code"] ?? "");
    for (let k = 0; k < 5; k++) {
      const evs = instantiateStory(story, BENIGN_EVENTS, "Microsoft Defender for Endpoint", "nexacorp").events;
      const domainEvents = evs.filter(e => ["4720", "4726", "4728", "4756"].includes(code(e)));
      expect(domainEvents.length).toBeGreaterThan(0);
      for (const e of domainEvents) {
        expect(e.hostname).toBe("SRV-NXC-DC01");
        expect(String(e.raw?.["winlog.computer_name"])).toMatch(/^SRV-NXC-DC01/);
      }
      const hostsById = new Map<string, Set<string>>();
      for (const e of evs) for (const [key, v] of Object.entries(e.raw ?? {})) {
        if (!/LogonId$/i.test(key) || typeof v !== "string" || /^0x3e[457]$/i.test(v)) continue;
        hostsById.set(v, (hostsById.get(v) ?? new Set<string>()).add(String(e.hostname)));
      }
      for (const [id, hosts] of hostsById) expect(hosts.size, `LogonId ${id} on ${[...hosts].join(",")}`).toBe(1);
      // no story host borrows another employee's workstation: the admin server is a server
      const logon = evs.find(e => e.id === "evt_ra_03_admin_logon")!;
      expect(logon.hostname).not.toMatch(/^(WS|LT)-/);
    }
  });

  it("the drive-by story's file path follows the victim swap", () => {
    const story = storiesForCompany("nexacorp", "easy").find(s => s.id === "fake-browser-update")!;
    for (let k = 0; k < 5; k++) {
      const evs = instantiateStory(story, BENIGN_EVENTS, "Microsoft Defender for Endpoint", "nexacorp").events;
      const w = evs.find(e => e.id === "evt_fbu_04_file_write")!;
      const user = String(w.user_email).split("@")[0];
      expect(w.file?.path).toContain(`\\Users\\${user}\\`);
      if (user !== "d.rosen") expect(JSON.stringify([w.raw, w.file, w.process])).not.toContain("d.rosen");
    }
  });
});

describe("buildTeamTimeline — staff-chosen storyline (exercise-report #18)", () => {
  const storyIncidents = (tl: ReturnType<typeof buildTeamTimeline>) =>
    [...new Set(tl.filter(e => e.channel === "feed" && e.answer?.origin === "story").map(e => String(e.answer?.incident_id)))];
  const expectedIncident = (s: { id: string; events: TelemetryEvent[] }) =>
    s.events.find(e => e.incident_id)?.incident_id ?? `story:${s.id}`;

  it("resolveTeamStory accepts only stories offered for that company + difficulty", () => {
    const easy = storiesForCompany("nexacorp", "easy");
    expect(easy.length).toBeGreaterThan(1);
    expect(resolveTeamStory("nexacorp", "easy", easy[0].id)?.id).toBe(easy[0].id);
    expect(resolveTeamStory("nexacorp", "easy", null)).toBeNull();
    expect(resolveTeamStory("nexacorp", "easy", "no-such-story")).toBeNull();
    // an advanced-only story is not accepted for an easy session
    const hardOnly = storiesForCompany("nexacorp", "hard").find(s => !easy.some(e => e.id === s.id));
    if (hardOnly) expect(resolveTeamStory("nexacorp", "easy", hardOnly.id)).toBeNull();
  });

  it("a chosen storyline is always the (easy: only) story incident, build after build", () => {
    const [a, b] = storiesForCompany("nexacorp", "easy");
    for (const seed of ["s1", "s2", "s3"]) {
      expect(storyIncidents(buildTeamTimeline("nexacorp", "easy", seed, a.id))).toEqual([expectedIncident(a)]);
      expect(storyIncidents(buildTeamTimeline("nexacorp", "easy", seed, b.id))).toEqual([expectedIncident(b)]);
    }
  });

  it("medium keeps the chosen story as one of the two incidents; unknown ids fall back to random", () => {
    const [a] = storiesForCompany("nexacorp", "medium");
    expect(storyIncidents(buildTeamTimeline("nexacorp", "medium", "s", a.id))).toContain(expectedIncident(a));
    expect(storyIncidents(buildTeamTimeline("nexacorp", "medium", "s", "bogus")).length).toBeGreaterThan(0);
  });
});
