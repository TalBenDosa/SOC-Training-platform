// "Verify with IT" in the team exercise: every log that offers the call gets IT's reply from
// the server (it-verify route), and that reply must match the log's ground truth.
import { describe, expect, it } from "vitest";
import { buildTeamTimeline, teamStoryPool } from "./buildTimeline";
import { COMPANY_PROFILES } from "@/lib/sim/companyProfilesMeta";
import { itVerifyAnswer, itVerifyApplies } from "@/lib/sim/itVerify";
import type { TelemetryEvent } from "@/lib/sim/types";

/** Exactly what POST /api/team/sessions/[id]/it-verify builds from the fired log + its answer. */
function routeReply(body: Record<string, unknown>, a: Record<string, unknown>) {
  const merged = {
    ...body, description: a.authored_description ?? body.description, mitre_technique: a.mitre_technique ?? body.mitre_technique,
    fp_explanation: a.fp_explanation, is_baseline: a.is_baseline, it_verify_result: a.it_verify_result,
    it_verify_message: a.it_verify_message, it_context: a.it_context, expected_verdict: undefined,
  } as unknown as TelemetryEvent;
  return itVerifyAnswer(merged, a.expected_verdict as string);
}

// Story steps that are authorised but still part of the incident (a defender's own containment
// action, a genuine HR record): IT confirms them through it_context.
const AUTHORISED_INCIDENT_STEPS = new Set(["aicld1", "rsoc8", "rsoc9", "aiag12"]);

describe("Verify with IT (team)", () => {
  const rows: { oid: string; company: string; body: Record<string, unknown>; a: Record<string, unknown> }[] = [];
  for (const c of COMPANY_PROFILES.map(p => p.id)) for (const d of ["easy", "medium", "hard"] as const) {
    for (const s of [undefined, ...teamStoryPool(c, d, null).map(x => x.id)]) {
      for (const e of buildTeamTimeline(c, d, `itv-${c}-${d}-${s}`, s)) {
        if (e.channel !== "feed") continue;
        const body = e.body as Record<string, unknown>, a = (e.answer ?? {}) as Record<string, unknown>;
        rows.push({ oid: String(a.original_id ?? "").replace(/__\d+$/, ""), company: c, body, a });
      }
    }
  }
  const offered = rows.filter(r => r.body.it_check);

  it("offers the call on admin changes, remote-access tools and logs with an authored IT answer", () => {
    expect(offered.length).toBeGreaterThan(100);
    expect(offered.some(r => /anydesk/i.test(JSON.stringify(r.body)))).toBe(true);
  });

  it("never puts IT's answer in the public log", () => {
    for (const r of rows) for (const k of ["it_verify_result", "it_verify_message", "it_context"]) expect(r.body[k], `${r.oid}.${k}`).toBeUndefined();
  });

  it("every reply matches the log's ground truth", () => {
    const wrong: string[] = [];
    for (const r of offered) {
      const reply = routeReply(r.body, r.a);
      const v = String(r.a.expected_verdict);
      const attack = v === "tp" || v === "escalate";
      const want = attack && !AUTHORISED_INCIDENT_STEPS.has(r.oid) ? "unverified" : "confirmed";
      if (!reply || !reply.message || reply.result !== want) wrong.push(`${r.oid}@${r.company} ${v} → ${reply?.result ?? "none"}`);
    }
    expect([...new Set(wrong)]).toEqual([]);
  });

  it("an unapproved AnyDesk install: IT says the tool is not allowed", () => {
    const r = offered.find(x => x.oid === "evt_rat_02_execute");
    expect(r).toBeTruthy();
    const reply = routeReply(r!.body, r!.a)!;
    expect(reply.result).toBe("unverified");
    expect(reply.message).toMatch(/AnyDesk is not on the approved software list/);
  });

  it("the dashboard shows the call on the same logs (shared rule)", () => {
    expect(itVerifyApplies({ source: "edr", event_type: "process_create", process: { name: "AnyDesk.exe", pid: 1 }, raw: {} } as TelemetryEvent)).toBe(true);
    expect(itVerifyApplies({ source: "edr", event_type: "process_create", process: { name: "chrome.exe", pid: 1 }, raw: {} } as TelemetryEvent)).toBe(false);
    expect(itVerifyApplies({ source: "ad", event_type: "group_modify", raw: {} } as TelemetryEvent)).toBe(true);
  });
});
