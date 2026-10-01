/**
 * Team threat intel (scenario review 2026-10-01, fix 1): the team feed carries no
 * answer key, so "Check hash / IP" judged an attacker's IOC by the bare log — a C2
 * address or a malicious attachment came back CLEAN. The server-built truth table
 * (fired logs + their answers) restores the verdicts; decoys stay clean.
 */
import { describe, it, expect, vi } from "vitest";
vi.mock("server-only", () => ({}));
import { buildTeamTimeline } from "./buildTimeline";
import { teamLoad } from "./load";
import { buildTeamIocTruth } from "./iocTruth";
import { assessIoc, extractIocs, hashIntel } from "@/lib/edr/iocIntel";
import type { Ev } from "./types";
import type { TelemetryEvent } from "@/lib/sim/types";

/** A session as the DB holds it: public feed rows (with inject_id) + the staff-only answers. */
function session(company: string, difficulty: "easy" | "medium" | "hard", seed: string) {
  const tl = buildTeamTimeline(company, difficulty, seed, null, teamLoad(difficulty, [{ role: "t1" }, { role: "t3" }]));
  const feed = tl.map((t, i) => ({ t, i })).filter(x => x.t.channel === "feed");
  const events: Ev[] = feed.map(({ t, i }, k) => ({ seq: k + 1, type: "feed.event", actor_id: null, role: null, payload: { ...t.body, inject_id: `inj-${i}` }, occurred_at: undefined }));
  const injects = feed.map(({ t, i }) => ({ id: `inj-${i}`, channel: "feed", expected_action: t.answer ?? null }));
  return { feed, events, injects };
}

describe("buildTeamIocTruth", () => {
  it("the twist's C2 address and every attack log's external IOCs look up as bad — clean without the truth", () => {
    const { feed, events, injects } = session("nexacorp", "medium", "e90b31d5");
    const truth = buildTeamIocTruth(events, injects);
    const c2 = feed.find(x => (x.t.answer as { original_id?: string } | undefined)?.original_id?.startsWith("msel_twist_edr"))?.t.body as TelemetryEvent | undefined;
    expect(c2?.dst_ip).toBeTruthy();
    expect(assessIoc("ip", c2!.dst_ip!, { event: c2, truth }).verdict).toBe("malicious");
    expect(assessIoc("ip", c2!.dst_ip!, { event: c2 }).verdict).toBe("clean");   // the bug: no answer key on the public log

    let judged = 0;
    for (const { t } of feed) {
      const a = t.answer as { expected_verdict?: string } | undefined;
      if (a?.expected_verdict !== "tp" && a?.expected_verdict !== "escalate") continue;
      const ev = t.body as unknown as TelemetryEvent;
      for (const ioc of extractIocs(ev)) {
        const v = assessIoc(ioc.type, ioc.value, { event: ev, truth }).verdict;
        if (v === "internal") continue;
        judged++;
        expect(["malicious", "suspicious", "clean"]).toContain(v);
      }
    }
    expect(judged).toBeGreaterThan(0);
  });

  it("decoy (fp) logs' IOCs are never condemned", () => {
    for (const seed of ["a", "b", "c"]) {
      const { feed, events, injects } = session("nexacorp", "medium", seed);
      const truth = buildTeamIocTruth(events, injects);
      const attackIocs = new Set(feed.filter(x => ["tp", "escalate"].includes(String((x.t.answer as { expected_verdict?: string })?.expected_verdict)))
        .flatMap(x => extractIocs(x.t.body as unknown as TelemetryEvent).map(i => `${i.type}:${i.value}`)));
      for (const { t } of feed) {
        if ((t.answer as { expected_verdict?: string })?.expected_verdict !== "fp") continue;
        const ev = t.body as unknown as TelemetryEvent;
        for (const ioc of extractIocs(ev)) {
          if (attackIocs.has(`${ioc.type}:${ioc.value}`)) continue;   // shared with a real attack log
          expect(assessIoc(ioc.type, ioc.value, { event: ev, truth }).verdict).not.toBe("malicious");
        }
      }
    }
  });

  it("only fired logs count — an attack that hasn't reached the feed is not in the table", () => {
    const { events, injects } = session("nexacorp", "medium", "e90b31d5");
    const half = Math.floor(events.length / 3);
    const early = buildTeamIocTruth(events.slice(0, half), injects);
    const full = buildTeamIocTruth(events, injects);
    expect(Object.keys(early.entries).length).toBeLessThan(Object.keys(full.entries).length);
  });
});

describe("a story's benign step keeps its IOCs clean", () => {
  it("the legitimate login before a takeover doesn't make the home IP malicious", () => {
    const row = (seq: number, inj: string, body: Record<string, unknown>): Ev => ({ seq, type: "feed.event", actor_id: null, role: null, payload: { ...body, inject_id: inj } });
    const base = { source: "vpn", vendor: "Palo Alto Networks PAN-OS", event_type: "vpn_login", user_email: "j.chen@nexacorp.com" };
    const events = [
      row(1, "a", { ...base, id: "p1", ts: "2026-01-01T08:14:00Z", severity: "informational", src_ip: "77.125.38.201", description: "j.chen connected from Tel Aviv, registered device, MFA approved" }),
      row(2, "b", { ...base, id: "p2", ts: "2026-01-01T08:17:00Z", severity: "high", src_ip: "41.203.64.9", mitre_technique: "T1078", description: "j.chen's account connected from Lagos on an unregistered device" }),
    ];
    const injects = [
      { id: "a", channel: "feed", expected_action: { expected_verdict: "benign", incident_id: "story:impossible-travel" } },
      { id: "b", channel: "feed", expected_action: { expected_verdict: "tp", incident_id: "story:impossible-travel" } },
    ];
    const truth = buildTeamIocTruth(events, injects);
    const ev = (i: number) => events[i].payload as unknown as TelemetryEvent;
    expect(assessIoc("ip", "77.125.38.201", { event: ev(0), truth }).verdict).toBe("clean");
    expect(assessIoc("ip", "41.203.64.9", { event: ev(1), truth }).verdict).toBe("malicious");
  });
});

describe("vendor file verdicts count without any truth table", () => {
  it("a Defender-for-O365 attachment marked Malicious is malicious on lookup", () => {
    const ev = {
      id: "x", ts: "2026-01-01T08:13:47Z", source: "o365", vendor: "Microsoft Defender for Office 365", event_type: "email_received", severity: "high",
      description: "Phishing email with macro-enabled attachment delivered to inbox",
      raw: { "data.office365.AttachmentData.SHA256": "4c1d0f61b9d2e6e8a0c5f3b7a9e2d4c6b8a0f1e3d5c7b9a1e3f5d7c9b1a3e5f7", "data.office365.AttachmentData.FileVerdict": "Malicious" },
    } as unknown as TelemetryEvent;
    expect(hashIntel("4c1d0f61b9d2e6e8a0c5f3b7a9e2d4c6b8a0f1e3d5c7b9a1e3f5d7c9b1a3e5f7", { event: ev }).verdict).toBe("malicious");
  });
});
