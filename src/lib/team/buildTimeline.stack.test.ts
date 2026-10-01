// Vendor choice in team sessions: every feed log is labelled for, and renders natively
// in, the chosen products; nothing from another vendor leaks into text or fields; the
// answer key stays off the public body.
import { describe, it, expect } from "vitest";
import { buildTeamTimeline, TEAM_ANSWER_FIELDS } from "./buildTimeline";
import { teamLoad } from "./load";
import { nativeView, NATIVE_SOURCES } from "@/lib/logs/native";
import { categoryOf, PRODUCT_LABEL, type Stack } from "@/lib/logs/native/stack";
import { validateNative } from "@/lib/logs/native/validate";
import type { TelemetryEvent } from "@/lib/sim/types";

const OTHER_EDR = /\b(CrowdStrike|Falcon|SentinelOne|Sophos|Defender for Endpoint|Microsoft Defender(?! for Office))\b/;
const roster = [{ role: "t1" }, { role: "t1" }, { role: "t2" }, { role: "t3" }, { role: "mgr" }];

const CASES: [string, "easy" | "medium" | "hard", Stack][] = [
  ["medcore", "medium", { edr: "crowdstrike", firewall: "fortigate", vpn: "globalprotect" }],
  ["nexacorp", "hard", { edr: "sentinelone", firewall: "checkpoint", idp: "okta" }],
  ["rocketstack", "medium", { edr: "mde", firewall: "paloalto", collab: "m365", idp: "entra" }],
  ["globallogis", "easy", { edr: "crowdstrike", firewall: "cisco_ftd", email_security: "proofpoint" }],
];

describe("team timeline under a chosen stack", () => {
  for (const [company, diff, stack] of CASES) {
    it(`${company} ${diff} ${JSON.stringify(stack)}`, () => {
      const tl = buildTeamTimeline(company, diff, `seed-${company}`, null, teamLoad(diff, roster), stack);
      const feed = tl.filter(e => e.channel === "feed").map(e => e.body as unknown as TelemetryEvent);
      expect(feed.length).toBeGreaterThan(30);
      let rendered = 0;
      const problems: string[] = [];
      for (const ev of feed) {
        for (const k of TEAM_ANSWER_FIELDS) if (k in (ev as unknown as Record<string, unknown>)) problems.push(`${ev.id}: answer field ${k} public`);
        const cat = categoryOf({ ...ev, source: ((ev as { _authored_source?: string })._authored_source ?? ev.source) as TelemetryEvent["source"], vendor: (ev as { _authored_vendor?: string })._authored_vendor ?? ev.vendor });
        const chosen = cat ? stack[cat as keyof Stack] : undefined;
        if (chosen) {
          if (ev.vendor !== PRODUCT_LABEL[chosen]) problems.push(`${ev.id}: vendor ${ev.vendor} ≠ ${PRODUCT_LABEL[chosen]}`);
          if (cat === "edr" && ev.description && OTHER_EDR.test(ev.description.replace(PRODUCT_LABEL[chosen]!, ""))) problems.push(`${ev.id}: description names another EDR — ${ev.description.slice(0, 90)}`);
        }
        const v = nativeView(ev, company, stack);
        if (!v) continue;
        rendered++;
        if (chosen && v.log.sourceId !== chosen) problems.push(`${ev.id}: rendered by ${v.log.sourceId}, chose ${chosen}`);
        const viol = validateNative(v.log, NATIVE_SOURCES[v.log.sourceId]!.schema);
        if (viol.length) problems.push(`${ev.id}: ${viol.slice(0, 2).map(x => `${x.problem}:${x.path}`).join(", ")}`);
      }
      console.log(`[team-stack] ${company} ${diff}: ${feed.length} logs, ${rendered} native, ${problems.length} problems`);
      expect(problems.slice(0, 15)).toEqual([]);
    });
  }
  it("no stack → nothing is relabelled (the legacy build; story choice there is random by design)", () => {
    const b = buildTeamTimeline("nexacorp", "medium", "same", null, teamLoad("medium", roster), {});
    expect(b.filter(e => e.channel === "feed").some(e => "_authored_vendor" in (e.body as Record<string, unknown>))).toBe(false);
  });
});
