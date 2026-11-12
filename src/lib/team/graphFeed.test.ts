// Microsoft Graph alerts in the SIEM feed of a session that runs on Sentinel. Each Microsoft detection
// renders as ms_graph and nothing else does; an EDR session and an older session do not change by a
// byte; and an alert can never tell an attack from a benign detection.
import { describe, it, expect } from "vitest";
import { buildTeamTimeline, type TimelineEntry } from "./buildTimeline";
import { teamLoad } from "./load";
import { CONSOLE_CHOICES, XDR_PRODUCTS, stackForConsole } from "./investigationConsole";
import { applyStack, fitsStack, graphAlertFor, nativeView, stackFor, storyFitsStack, withoutDetectionFeed } from "@/lib/logs/native";
import { feedSourceOf, microsoftProductOf, sanitizeStack, sourceFor, STACK_CHOICES, type Stack } from "@/lib/logs/native/stack";
import { validateNative } from "@/lib/logs/native/validate";
import { NATIVE_SOURCES } from "@/lib/logs/native";
import { ATTACK_STORIES } from "@/app/(app)/dashboard/attackStories";
import { eventMatchesSearch } from "@/app/(app)/dashboard/eventSearch";
import type { LiveEvent } from "@/app/(app)/dashboard/liveEventEnrich";
import type { NativeLog } from "@/lib/logs/native/types";
import type { TelemetryEvent } from "@/lib/sim/types";

type Rec = Record<string, unknown>;
const roster = [{ role: "t1" }, { role: "t1" }, { role: "t2" }, { role: "t3" }, { role: "mgr" }];
const COMPANIES = ["nexacorp", "medcore", "rocketstack", "globallogis", "quantumbank"];
const SENTINEL = stackForConsole({}, "sentinel");
const alertOf = (l: NativeLog) => ((l.record.data as Rec)["ms-graph"]) as Rec;
const authored = (ev: TelemetryEvent): TelemetryEvent => {
  const e = ev as TelemetryEvent & { _authored_source?: string; _authored_vendor?: string };
  return { ...ev, source: (e._authored_source ?? ev.source) as TelemetryEvent["source"], vendor: e._authored_vendor ?? ev.vendor };
};
const timeline = (company: string, diff: "easy" | "medium" | "hard", stack: Stack, seed = `graph-${company}`) =>
  buildTeamTimeline(company, diff, seed, null, teamLoad(diff, roster), stack);
const feedOf = (t: TimelineEntry[]) => t.filter(e => e.channel === "feed");

describe("the stack key", () => {
  it("stackForConsole sets it for Sentinel only", () => {
    // XDR stands for Microsoft Sentinel only (Tal 2026-11-12): the Microsoft products, the organization's own network devices.
    expect(stackForConsole({ firewall: "fortigate" }, "sentinel")).toEqual({ firewall: "fortigate", ...XDR_PRODUCTS, detection_feed: "ms_graph" });
    expect(stackForConsole({ edr: "crowdstrike" }, "edr")).toEqual({ edr: "crowdstrike" });
    // A client cannot turn it on for an EDR session.
    expect(stackForConsole({ edr: "crowdstrike", detection_feed: "ms_graph" }, "edr")).toEqual({ edr: "crowdstrike" });
  });
  it("sanitizeStack keeps the one value and nothing else, and GET reads it back", () => {
    expect(sanitizeStack({ edr: "mde", detection_feed: "ms_graph" })).toEqual({ edr: "mde", detection_feed: "ms_graph" });
    expect(sanitizeStack({ edr: "mde", detection_feed: "anything" })).toEqual({ edr: "mde" });
    expect(sanitizeStack({ edr: "mde" })).toEqual({ edr: "mde" });
  });
  it("is no choice in the product picker", () => {
    expect(STACK_CHOICES.map(c => c.category as string)).not.toContain("detection_feed");
    expect(STACK_CHOICES.flatMap(c => c.options as string[])).not.toContain("ms_graph");
    expect(CONSOLE_CHOICES.map(c => c.id)).toContain("sentinel");
  });
});

describe("an EDR session and an older session", () => {
  for (const company of COMPANIES) {
    it(`${company}: the timeline and every rendered record are the same as before`, () => {
      const chosen: Stack = { edr: "crowdstrike", firewall: "fortigate" };
      const older = timeline(company, "medium", chosen);
      const edr = timeline(company, "medium", sanitizeStack(stackForConsole(chosen, "edr")));
      expect(JSON.stringify(edr)).toBe(JSON.stringify(older));
      for (const t of feedOf(edr)) {
        const ev = t.body as unknown as TelemetryEvent;
        expect(JSON.stringify(nativeView(ev, company, stackForConsole(chosen, "edr")))).toBe(JSON.stringify(nativeView(ev, company, chosen)));
        expect(nativeView(ev, company, chosen)?.log.sourceId).not.toBe("ms_graph");
        expect(feedSourceOf(ev, company, chosen)).toBeNull();
      }
    }, 60_000);
  }
});

describe("a Sentinel session", () => {
  for (const company of COMPANIES) {
    it(`${company}: no new events, and only the detections change format`, () => {
      const without = withoutDetectionFeed(SENTINEL);
      for (const diff of ["easy", "medium", "hard"] as const) {
        const withFeed = timeline(company, diff, SENTINEL);
        // The XDR session (Sentinel data only) replays exactly from its seed; the Graph feed changes only how its
        // detections render (below), never which rows the session carries.
        expect(JSON.stringify(withFeed)).toBe(JSON.stringify(timeline(company, diff, SENTINEL)));
        let graph = 0;
        const problems: string[] = [];
        const eff = stackFor(company, SENTINEL);
        for (const t of feedOf(withFeed)) {
          const ev = t.body as unknown as TelemetryEvent;
          const own = nativeView(ev, company, without);
          const view = nativeView(ev, company, SENTINEL);
          const microsoft = !!microsoftProductOf(authored(ev), eff);
          if (microsoft) {
            graph++;
            if (view?.log.sourceId !== "ms_graph") problems.push(`${ev.id} ${ev.source}/${ev.vendor}: ${view?.log.sourceId}`);
            if (view?.product !== "Microsoft Graph Security") problems.push(`${ev.id}: product ${view?.product}`);
            if (feedSourceOf(ev, company, SENTINEL) !== "ms_graph") problems.push(`${ev.id}: row source`);
            if (view) for (const v of validateNative(view.log, NATIVE_SOURCES.ms_graph!.schema)) problems.push(`${ev.id}: ${v.problem} ${v.path}`);
          } else {
            if (JSON.stringify(view) !== JSON.stringify(own)) problems.push(`${ev.id}: ${ev.source} changed to ${view?.log.sourceId}`);
            if (feedSourceOf(ev, company, SENTINEL) !== null) problems.push(`${ev.id}: row says Graph`);
          }
        }
        console.log(`[graph-feed] ${company} ${diff}: ${feedOf(withFeed).length} logs, ${graph} Graph alerts`);
        expect(problems.slice(0, 10)).toEqual([]);
        expect(graph).toBeGreaterThan(0);
      }
    }, 120_000);
  }

  it("host, user and IOC pivots read the payload, and the alert names them too", () => {
    const ev = feedOf(timeline("nexacorp", "hard", SENTINEL)).map(t => t.body as unknown as TelemetryEvent)
      .find(e => !!microsoftProductOf(authored(e), stackFor("nexacorp", SENTINEL)) && e.hostname && e.src_ip)!;
    const hay = JSON.stringify(nativeView(ev, "nexacorp", SENTINEL)!.log.record);
    expect(hay).toContain(ev.hostname!);
    expect(hay).toContain(ev.src_ip!);
    expect(applyStack(ev, "nexacorp", SENTINEL).hostname).toBe(ev.hostname);
  });

  it("the feed's source search follows what the row says", () => {
    const row = { id: "e1", ts: "2026-01-01T08:00:00.000Z", source: "edr", event_type: "edr_alert", feed_source: "ms_graph", ruleLevel: 10, ruleId: "HTS-1", displayDescription: "x" } as unknown as LiveEvent;
    expect(eventMatchesSearch(row, "source:ms_graph")).toBe(true);
    expect(eventMatchesSearch({ ...row, feed_source: undefined }, "source:ms_graph")).toBe(false);
    expect(eventMatchesSearch({ ...row, feed_source: undefined }, "source:edr")).toBe(true);
  });

  it("stories fit a Sentinel session exactly as they fit the same products", () => {
    const without = withoutDetectionFeed(SENTINEL);
    for (const s of ATTACK_STORIES) expect(storyFitsStack(s.events, "nexacorp", SENTINEL)).toBe(storyFitsStack(s.events, "nexacorp", without));
    const e = ATTACK_STORIES[0].events[0];
    expect(fitsStack(e, "nexacorp", SENTINEL)).toBe(fitsStack(e, "nexacorp", without));
    expect(sourceFor(e, stackFor("nexacorp", without))).not.toBe("ms_graph");
  });
});

describe("graphAlertFor, for the Sentinel workspace", () => {
  it("needs no key on the stack, and returns the same alert the feed shows", () => {
    const without = withoutDetectionFeed(SENTINEL);
    let n = 0;
    for (const t of feedOf(timeline("nexacorp", "hard", SENTINEL))) {
      const ev = t.body as unknown as TelemetryEvent;
      const view = nativeView(ev, "nexacorp", SENTINEL);
      const alert = graphAlertFor(ev, "nexacorp", without);
      if (view?.log.sourceId === "ms_graph") { n++; expect(alert).toEqual(view.log); }
      else expect(alert).toBeNull();
      // The workspace's own stack keeps the Defender record.
      expect(nativeView(ev, "nexacorp", without)?.log.sourceId).not.toBe("ms_graph");
    }
    expect(n).toBeGreaterThan(0);
  });
  it("a product that is not Microsoft's has no Graph alert", () => {
    const ev = feedOf(timeline("nexacorp", "hard", { edr: "crowdstrike" })).map(t => t.body as unknown as TelemetryEvent).find(e => e.is_detection && e.source === "edr");
    if (ev) expect(graphAlertFor(ev, "nexacorp", { edr: "crowdstrike" })).toBeNull();
  });
});

describe("a Graph alert never carries the answer", () => {
  const COMMON_PATHS = (o: Rec) => Object.keys(o).sort().join(",");
  /** The keys of an object at every depth, values aside: what an analyst could read a pattern from. */
  const shape = (v: unknown): unknown => (Array.isArray(v) ? "[]" : v && typeof v === "object"
    ? Object.fromEntries(Object.entries(v as Rec).sort(([a], [b]) => a.localeCompare(b)).map(([k, x]) => [k, shape(x)])) : "x");

  for (const company of COMPANIES) {
    it(`${company}: benign and attack detections are the same shape over whole timelines`, () => {
      const top = new Set<string>();
      const perType = new Map<string, Set<string>>();
      const verdictsSeen = { attack: 0, benign: 0 };
      const problems: string[] = [];
      let alerts = 0;
      for (const diff of ["easy", "medium", "hard"] as const) for (const seed of ["a", "b"]) {
        const incidents = new Set<string>();
        for (const t of feedOf(timeline(company, diff, SENTINEL, `leak-${company}-${seed}`))) {
          const ev = t.body as unknown as TelemetryEvent;
          const log = nativeView(ev, company, SENTINEL)?.log;
          if (log?.sourceId !== "ms_graph") continue;
          const a = alertOf(log);
          top.add(COMMON_PATHS(a));
          if (a.status !== "new") problems.push(`${ev.id}: status ${a.status}`);
          if (a.classification !== "unknown") problems.push(`${ev.id}: classification ${a.classification}`);
          if (a.determination !== "unknown") problems.push(`${ev.id}: determination ${a.determination}`);
          if (a.investigationState !== "unknown") problems.push(`${ev.id}: investigationState ${a.investigationState}`);
          if (a.assignedTo !== null || a.actorDisplayName !== null || a.resolvedDateTime !== null) problems.push(`${ev.id}: assigned or attributed`);
          if ((a.systemTags as unknown[]).length || (a.comments as unknown[]).length) problems.push(`${ev.id}: tags or comments`);
          for (const e of a.evidence as Rec[]) {
            if (e.verdict !== "unknown") problems.push(`${ev.id}: verdict ${e.verdict}`);
            if (e.remediationStatus !== "none") problems.push(`${ev.id}: remediationStatus ${e.remediationStatus}`);
            for (const r of e.roles as string[]) if (r !== "source" && r !== "destination") problems.push(`${ev.id}: role ${r}`);
            const type = e["@odata.type"] as string;
            if (!perType.has(type)) perType.set(type, new Set());
            perType.get(type)!.add(JSON.stringify(shape({ ...e, parentProcessImageFile: null })));
          }
          // One incident per alert in a session: never the story's grouping.
          if (incidents.has(a.incidentId as string)) problems.push(`${ev.id}: incident ${a.incidentId} shared`);
          incidents.add(a.incidentId as string);
          alerts++;
          verdictsSeen[(t.answer as Rec | undefined)?.expected_verdict === "tp" ? "attack" : "benign"]++;
        }
      }
      expect(problems.slice(0, 10)).toEqual([]);
      expect(top.size).toBe(1);
      for (const [type, shapes] of perType) expect(shapes.size, type).toBe(1);
      console.log(`[graph-leak] ${company}: ${alerts} alerts ${JSON.stringify(verdictsSeen)}`);
    }, 180_000);
  }

  it("the answer fields of an event change nothing in its alert", () => {
    const body = feedOf(timeline("nexacorp", "hard", SENTINEL)).map(t => t.body as unknown as TelemetryEvent)
      .find(e => nativeView(e, "nexacorp", SENTINEL)?.log.sourceId === "ms_graph")!;
    const clean = JSON.stringify(nativeView(body, "nexacorp", SENTINEL)!.log);
    for (const leak of [
      { expected_verdict: "tp" }, { expected_verdict: "fp", fp_explanation: "Approved change" }, { incident_id: "inc-story-7" }, { edr_scope: "non_edr" },
      { it_context: "Nobody in IT knows this" }, { attack_name: "Ransomware" }, { feed_origin: "story" },
    ]) expect(JSON.stringify(nativeView({ ...body, ...leak } as TelemetryEvent, "nexacorp", SENTINEL)!.log)).toBe(clean);
  });
});
