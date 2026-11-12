/**
 * Exercise variety (owner, 2026-11-07: two exercises in a row both had a PsExec run; "no
 * repetition, vary it every time"). Expert review of the same two exercises: the same five
 * benign-positive makers, the same Heap decoy, fixed inject texts, a rundll32 twist every time, a
 * ticket right before every FP alert and never before an attack, two decoys on one person.
 *
 *  - the catalogue is wide (>= 20 makers, several decoy and twist kinds, several inject texts);
 *  - over 50 seeds no maker, decoy or twist takes more than a fair share;
 *  - an organization's consecutive sessions (with history) share no maker, decoy or twist;
 *  - per-run parameters differ between sessions;
 *  - every variant passes the public-payload checks (no answer field, no technique on a raw log, no
 *    empty field, no authored conclusion in the native record) and renders natively with zero
 *    schema violations (the feed's log gate);
 *  - no ticket shape gives the answer away, and no person carries two decoys.
 */
import { describe, it, expect, vi } from "vitest";
vi.mock("server-only", () => ({}));
import { buildTeamTimeline, TEAM_ANSWER_FIELDS, type TimelineEntry, type VarietyOpts } from "./buildTimeline";
import { teamLoad } from "./load";
import { loadWithPlan } from "./attackPlan";
import { FP_MAKERS } from "./fpAlerts";
import { DECOY_KINDS, TWIST_KINDS, INJECT_TEXT_KEYS } from "./msel";
import { historyFromConfigs, isDocIp, type VarietyRecord } from "./variety";
import { ATTACK_STORIES } from "@/app/(app)/dashboard/attackStories";
import { mitreVisible } from "@/lib/sim/mitreVisible";
import { nativeView, NATIVE_SOURCES } from "@/lib/logs/native";
import { validateNative } from "@/lib/logs/native/validate";
import type { Stack } from "@/lib/logs/native/stack";
import type { TelemetryEvent } from "@/lib/sim/types";

const roster = [{ role: "t1" }, { role: "t1" }, { role: "t2" }, { role: "t3" }, { role: "mgr" }];
type Diff = "easy" | "medium" | "hard";
function build(company: string, seed: string, opts: VarietyOpts = {}, stack: Stack = {}, diff: Diff = "medium", storyId: string | null = null) {
  let rec: VarietyRecord | null = null;
  const tl = buildTeamTimeline(company, diff, seed, storyId, teamLoad(diff, roster), stack, null, null, { ...opts, onVariety: r => { rec = r; } });
  return { tl, rec: rec! as VarietyRecord };
}
/** Stories that carry each twist ground: code ran on a workstation, a cloud sign-in worked, a spray never got in. */
// One story per twist ground: code ran, a sign-in worked, an account logged on, and a spray that never got in.
// Team Training stories only (the engines share none, Tal 2026-11-12): code ran, a cloud sign-in worked, a spray, a web attack from outside.
const TWIST_STORIES = ["tech-support-scam", "core-device-code-phish", "nexacorp-chain-d", "okta-password-burst", "web-inj-cmdi-pdfexport"];
const ans = (e: TimelineEntry) => (e.answer ?? {}) as Record<string, unknown>;
const origId = (e: TimelineEntry) => String(ans(e).original_id ?? "");

describe("catalogue", () => {
  it("is wide: >= 20 benign-positive makers in many kinds, several decoys, twists and inject texts", () => {
    expect(FP_MAKERS.length).toBeGreaterThanOrEqual(20);
    expect(new Set(FP_MAKERS.map(m => m.kind)).size).toBeGreaterThanOrEqual(18);
    expect(DECOY_KINDS.length).toBeGreaterThanOrEqual(5);
    expect(TWIST_KINDS.length).toBeGreaterThanOrEqual(5);
    expect(INJECT_TEXT_KEYS.filter(k => k.startsWith("ticket:")).length).toBeGreaterThanOrEqual(5);
    expect(INJECT_TEXT_KEYS.filter(k => k.startsWith("ann:")).length).toBeGreaterThanOrEqual(3);
  });
});

describe("fair share across 50 seeds", () => {
  it("no maker, decoy or twist exceeds a fair share", () => {
    const makers = new Map<string, number>(), decoys = new Map<string, number>(), twists = new Map<string, number>();
    const bump = (m: Map<string, number>, k: string | null) => { if (k) m.set(k, (m.get(k) ?? 0) + 1); };
    let picks = 0;
    for (let i = 0; i < 50; i++) {
      const { rec } = build(i % 2 ? "nexacorp" : "medcore", `fair-${i}`);
      rec.makers.forEach(k => bump(makers, k)); picks += rec.makers.length;
      bump(decoys, rec.decoy); bump(twists, rec.twist);
    }
    // Fair share: the count a uniform draw over the items that actually ran would give, with room
    // for chance and for items a company can carry only sometimes (x2.5).
    const fair = (m: Map<string, number>, total: number) => (total / Math.max(1, m.size)) * 2.5;
    for (const [k, n] of makers) expect(n, `maker ${k}`).toBeLessThanOrEqual(fair(makers, picks));
    for (const [k, n] of decoys) expect(n, `decoy ${k}`).toBeLessThanOrEqual(fair(decoys, 50));
    for (const [k, n] of twists) expect(n, `twist ${k}`).toBeLessThanOrEqual(fair(twists, 50));
    expect(makers.size).toBeGreaterThanOrEqual(15);
    expect(decoys.size).toBeGreaterThanOrEqual(4);
    expect(twists.size).toBeGreaterThanOrEqual(4);
  }, 180_000);
});

describe("memory across exercises", () => {
  for (const company of ["nexacorp", "medcore", "globallogis"]) {
    it(`${company}: consecutive sessions with history share no maker, decoy or twist`, () => {
      const past: { variety: VarietyRecord }[] = [];
      for (let k = 0; k < 4; k++) {
        const history = historyFromConfigs([...past].reverse());
        const { rec } = build(company, `${company}-run-${k}`, { history });
        if (past.length) {
          const prev = past[past.length - 1].variety;
          expect(rec.makers.filter(m => prev.makers.includes(m)), `run ${k} makers`).toEqual([]);
          if (rec.decoy) expect(rec.decoy).not.toBe(prev.decoy);
          if (rec.twist) expect(rec.twist).not.toBe(prev.twist);
          expect(rec.injects.filter(x => prev.injects.includes(x))).toEqual([]);
          expect(rec.stories.filter(x => prev.stories.includes(x))).toEqual([]);
        }
        expect(rec.makers.length).toBeGreaterThanOrEqual(2);
        past.push({ variety: rec });
      }
    }, 120_000);
  }

  it("history ranks the least recently used first and ignores sessions older than five", () => {
    const rec = (m: string): { variety: VarietyRecord } => ({ variety: { v: 1, makers: [m], decoy: null, twist: null, injects: [], stories: [] } });
    const h = historyFromConfigs([rec("a"), rec("b"), rec("a"), rec("c"), rec("d"), rec("e"), {} as never]);
    expect(h.makers).toEqual({ a: 1, b: 2, c: 4, d: 5 });
  });
});

describe("parameters vary per run", () => {
  it("two sessions of one company share no FP alert command line, decoy destination+size, or twist infrastructure", () => {
    const sig = (tl: TimelineEntry[]) => {
      const fp = tl.filter(e => origId(e).startsWith("fpa_"));
      const lead = tl.filter(e => ans(e).supports_inject === "msel_false_lead" && e.body.source === "firewall");
      const tw = tl.filter(e => ans(e).supports_inject === "msel_twist");
      return {
        cmd: new Set(fp.map(e => (e.body.process as { cmdline?: string } | undefined)?.cmdline).filter((x): x is string => typeof x === "string")),
        lead: new Set(lead.map(e => `${(e.body.network as { domain?: string }).domain}|${(e.body.network as { bytes_out?: number }).bytes_out}`)),
        twist: new Set(tw.flatMap(e => [e.body.dst_ip, (e.body.network as { domain?: string } | undefined)?.domain, (e.body.process as { cmdline?: string } | undefined)?.cmdline]).filter((x): x is string => typeof x === "string")),
      };
    };
    for (const [a, b] of [["p-1", "p-2"], ["p-3", "p-4"], ["p-5", "p-6"]]) {
      const A = sig(build("nexacorp", a).tl), B = sig(build("nexacorp", b).tl);
      for (const k of ["cmd", "lead", "twist"] as const) expect([...A[k]].filter(x => B[k].has(x)), k).toEqual([]);
    }
  }, 60_000);

  it("attacker and partner addresses introduced by the variants are documentation addresses, never real ones", () => {
    for (const seed of ["ip-1", "ip-2", "ip-3"]) {
      const { tl } = build("nexacorp", seed);
      for (const e of tl) {
        const id = origId(e);
        if (!/^(fpa_|msel_)/.test(id) || e.channel !== "feed") continue;
        for (const ip of [e.body.src_ip, e.body.dst_ip]) {
          if (typeof ip !== "string" || /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/.test(ip)) continue;
          expect(isDocIp(ip), `${id} ${ip}`).toBe(true);
        }
      }
    }
  });
});

// The public-payload checks of publicPayloadTells.test.ts and answerLeak.test.ts, plus the native gate,
// run on every variant: each maker, decoy and twist forced in turn.
const STACKS: [string, Stack][] = [
  ["nexacorp", {}],
  ["medcore", {}],
  ["rocketstack", {}],
  ["quantumbank", {}],
  ["globallogis", { edr: "crowdstrike", firewall: "fortigate", idp: "okta" }],
  ["nexacorp", { edr: "sentinelone", firewall: "checkpoint" }],
  // A Sentinel-console session: Microsoft detections render as their Graph alert.
  ["medcore", { edr: "mde", firewall: "paloalto", idp: "entra", collab: "m365", email_security: "defender_o365", detection_feed: "ms_graph" }],
];
function checkPublic(tl: TimelineEntry[], company: string, stack: Stack, only: (e: TimelineEntry) => boolean): string[] {
  const problems: string[] = [];
  for (const t of tl) {
    if (!only(t)) continue;
    const b = t.body as Record<string, unknown>;
    const a = ans(t);
    const id = origId(t);
    if (t.channel === "inject") {
      if (/\{\w+\}/.test(String(b.text))) problems.push(`${id}: unfilled placeholder`);
      for (const k of ["expected_response", "expected_decision", "linked_objective"]) if (k in b) problems.push(`${id}: ${k} public`);
      if (["twist", "false_lead"].includes(String(b.kind))) problems.push(`${id}: real kind public`);
      continue;
    }
    for (const k of TEAM_ANSWER_FIELDS) if (k in b) problems.push(`${id}: answer field ${k} public`);
    if ((b.mitre_technique || b.mitre_tactic) && !mitreVisible(b as never)) problems.push(`${id}: technique on a raw ${b.source}/${b.event_type} log`);
    if (b.is_detection === false) problems.push(`${id}: is_detection false`);
    for (const [k, v] of Object.entries(b)) if (v === null || (typeof v === "object" && !Array.isArray(v) && Object.keys(v as object).length === 0)) problems.push(`${id}: empty field ${k}`);
    const v = nativeView(b as unknown as TelemetryEvent, company, stack);
    const seen = (v ? JSON.stringify(v.log.record) + (v.log.rawLine ?? "") : JSON.stringify(b.raw ?? {})) + String(b.description ?? "");
    for (const conclusion of [a.fp_explanation, (a.it_context as { message?: string } | undefined)?.message]) {
      if (typeof conclusion !== "string") continue;
      const needle = conclusion.slice(0, 40);
      if (seen.includes(needle)) problems.push(`${id}: authored conclusion in what the analyst sees: ${needle}`);
    }
    if (v) {
      const viol = validateNative(v.log, NATIVE_SOURCES[v.log.sourceId]!.schema);
      if (viol.length) problems.push(`${id} [${v.log.sourceId}]: ${viol.slice(0, 3).map(x => `${x.problem}:${x.path}`).join(", ")}`);
    }
  }
  return problems;
}

describe("every variant passes the public-payload leak checks and the native log gate", () => {
  it("each benign-positive maker (forced), with and without a covering ticket", () => {
    const problems: string[] = [];
    const ran = new Set<string>();
    for (const m of FP_MAKERS) for (const [company, stack] of STACKS) for (const miss of [false, true]) {
      if (miss && !m.canMiss) continue;
      const { tl, rec } = build(company, `leak-${m.id}`, { force: { makers: [m.id], miss } }, stack, "hard");
      if (!rec.makers.includes(m.id)) continue;   // not a product this company runs
      ran.add(m.id);
      problems.push(...checkPublic(tl, company, stack, e => /^(fpa_|itsm_)/.test(origId(e))).map(p => `${company} ${m.id}: ${p}`));
    }
    expect(problems.slice(0, 15)).toEqual([]);
    expect([...ran].sort()).toEqual(FP_MAKERS.map(m => m.id).sort());   // every maker ran somewhere
  }, 400_000);

  it("each decoy and each twist (forced)", () => {
    const problems: string[] = [];
    const decoys = new Set<string>(), twists = new Set<string>();
    for (const [company, stack] of STACKS) {
      for (const d of DECOY_KINDS) {
        const { tl, rec } = build(company, `leak-d-${d}`, { force: { decoy: d } }, stack);
        if (rec.decoy !== d) continue;
        decoys.add(d);
        problems.push(...checkPublic(tl, company, stack, e => origId(e).startsWith("msel_false_lead")).map(p => `${company} ${d}: ${p}`));
      }
      for (const k of TWIST_KINDS) {
        // A twist kind follows from what the story achieved (msel.ts twistGround, review 2026-11-08 K4): when the
        // session's own story cannot carry it, the kind runs on a story that can (code ran, a sign-in worked, a spray failed).
        let { tl, rec } = build(company, `leak-t-${k}`, { force: { twist: k } }, stack);
        for (const story of TWIST_STORIES) {
          if (rec.twist === k) break;
          ({ tl, rec } = build(company, `leak-t-${k}`, { force: { twist: k } }, stack, "medium", story));
        }
        // A story with no host of its own (a cloud spray) lends the twist to the session's other attack when there are
        // two: an exercise of one attack runs it alone.
        for (const story of TWIST_STORIES) {
          if (rec.twist === k) break;
          const one = loadWithPlan(teamLoad("medium", roster), { count: 1, slots: [story], bonus: false });
          let r: VarietyRecord | null = null;
          const t = buildTeamTimeline(company, "medium", `leak-t-${k}`, story, one, stack, null, null, { force: { twist: k }, onVariety: x => { r = x; } });
          if (r) ({ tl, rec } = { tl: t, rec: r });
        }
        if (rec.twist !== k) continue;
        twists.add(k);
        problems.push(...checkPublic(tl, company, stack, e => origId(e).startsWith("msel_twist")).map(p => `${company} ${k}: ${p}`));
      }
    }
    expect(problems.slice(0, 15)).toEqual([]);
    expect([...decoys].sort()).toEqual([...DECOY_KINDS].sort());
    expect([...twists].sort()).toEqual([...TWIST_KINDS].sort());
  }, 400_000);
});

describe("no answer in the shape", () => {
  it("a ticket nearby does not mark a false positive; attacks open with tickets nearby too; some tickets do not cover", () => {
    // (a covering ticket is always BEFORE its alert, at a varied distance: far tickets are counted by number)
    let fpWithTicketJustBefore = 0, fpAlerts = 0, attackOpeningsWithTicket = 0, openings = 0, misses = 0, farTickets = 0;
    for (let i = 0; i < 16; i++) {
      const { tl } = build(i % 2 ? "nexacorp" : "medcore", `shape-${i}`, {}, {}, "hard");
      const feed = tl.filter(e => e.channel === "feed");
      const isTicket = (e?: TimelineEntry) => !!e && e.body.source === "soar";
      feed.forEach((e, k) => {
        const id = origId(e);
        if (/^fpa_/.test(id) && e.body.is_detection) {
          fpAlerts++;
          if (feed.slice(Math.max(0, k - 3), k).some(isTicket)) fpWithTicketJustBefore++;
          if (ans(e).expected_verdict === "escalate") misses++;
          const num = /(CHG|RITM|INC)\d+/.exec(String(ans(e).fp_explanation ?? (ans(e).it_context as { message?: string } | undefined)?.message ?? ""))?.[0];
          const t = num ? feed.findIndex(x => (x.body.raw as Record<string, unknown> | undefined)?.["servicenow.number"] === num) : -1;
          if (t >= 0 && k - t > 6) farTickets++;
        }
      });
      const seenInc = new Set<string>();
      feed.forEach((e, k) => {
        const inc = String(ans(e).incident_id ?? "");
        if (ans(e).origin !== "story" || !["tp", "escalate"].includes(String(ans(e).expected_verdict)) || seenInc.has(inc)) return;
        seenInc.add(inc); openings++;
        if (feed.slice(Math.max(0, k - 3), k).some(isTicket)) attackOpeningsWithTicket++;
      });
    }
    expect(fpAlerts).toBeGreaterThan(30);
    expect(fpWithTicketJustBefore / fpAlerts).toBeLessThan(0.75);
    expect(farTickets).toBeGreaterThan(0);
    expect(attackOpeningsWithTicket / openings).toBeGreaterThan(0.25);
    expect(misses).toBeGreaterThan(0);
  }, 120_000);

  it("an uncovered alert is escalate, its own incident, and its ticket names something else", () => {
    let checked = 0;
    for (const id of FP_MAKERS.filter(m => m.canMiss).map(m => m.id)) for (const company of ["nexacorp", "rocketstack"]) {
      const { tl } = build(company, `miss-${id}`, { force: { makers: [id], miss: true } }, {}, "hard");
      const alert = tl.find(e => origId(e).startsWith("fpa_") && ans(e).expected_verdict === "escalate");
      if (!alert) continue;
      checked++;
      expect(String(ans(alert).incident_id)).toMatch(/^solo:fpa_/);
      expect((ans(alert).it_context as { result?: string }).result).toBe("unverified");
      expect(ans(alert).fp_explanation).toBeUndefined();
    }
    expect(checked).toBeGreaterThanOrEqual(3);
  }, 60_000);

  it("no person carries two decoys, and no decoy lands on an attack victim; the scanner is one asset record", () => {
    for (let i = 0; i < 12; i++) {
      const { tl } = build(i % 2 ? "nexacorp" : "globallogis", `people-${i}`);
      const owner = new Map<string, string>();
      const victims = new Set(tl.filter(e => ["tp", "escalate"].includes(String(ans(e).expected_verdict)) && ans(e).origin === "story").map(e => e.body.user_email).filter(Boolean));
      for (const e of tl) {
        const id = origId(e);
        // A maker's evidence rows (fpa_<maker>ev_<n>_<k>) belong to its alert (fpa_<maker>_<n>).
        const group = id.startsWith("fpa_") ? id.replace(/^fpa_(vpnfail|lockout)_/, "fpa_lock_").replace(/^fpa_([a-z]+)ev_(\d+)_\d+/, "fpa_$1_$2").replace(/_\d+$/, "") : id.startsWith("msel_false_lead") ? "lead" : null;
        if (!group || ans(e).expected_verdict === "benign" && group !== "lead") continue;
        const u = e.body.user_email as string | undefined;
        if (!u || id === "msel_false_lead_itsm") continue;
        expect(owner.get(u) ?? group, `${u} in ${owner.get(u)} and ${group}`).toBe(group);
        owner.set(u, group);
        expect(victims.has(u), `${group} on victim ${u}`).toBe(false);
      }
      const scan = tl.find(e => /^fpa_scan/.test(origId(e)));
      if (scan) {
        const host = String(scan.body.hostname), ip = String(scan.body.src_ip);
        const others = tl.filter(e => e.channel === "feed" && e.body.hostname === host);
        for (const o of others) if (o.body.src_ip) expect(o.body.src_ip).toBe(ip);
        const ticket = tl.find(e => e.body.source === "soar" && JSON.stringify(e.body.raw).includes(host));
        if (ticket) expect(JSON.stringify(ticket.body.raw)).toContain(host);
      }
    }
  }, 60_000);
});
