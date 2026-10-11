// Forensic review: Tier-3 findings graded against the truth through the rows they cite,
// evidence preservation, confidence calibration, and the reports to the SOC Manager.
import { describe, expect, it, vi } from "vitest";
vi.mock("server-only", () => ({}));
import type { TelemetryEvent } from "@/lib/sim/types";
import type { Ev, RosterMember } from "@/lib/team/types";
import { buildTeamTimeline } from "@/lib/team/buildTimeline";
import { withRebasedTime } from "@/lib/sim/rebaseTime";
import { hostKey } from "@/lib/team/format";
import { buildEvidenceView, hostStateOf, type FeedRow } from "@/lib/forensics/workbench";
import { computeForensicReview } from "./forensicReview";
import { computeReport } from "./computeReport";

const SID = "fr-test-session";
const T0 = Date.parse("2026-10-10T08:00:00.000Z");
const iso = (ms: number) => new Date(ms).toISOString();
const tl = buildTeamTimeline("nexacorp", "medium", "fr-demo-1").filter(e => e.channel === "feed").sort((a, b) => a.due_offset_ms - b.due_offset_ms);
const isAtk = (e: (typeof tl)[number]) => ["tp", "escalate"].includes(String(e.answer?.expected_verdict));

// public feed (what players saw) and revealed feed (answers joined), same seqs and times
const publicFeed: Ev[] = tl.map((e, i) => ({ seq: i + 1, type: "feed.event", actor_id: null, role: "system", payload: e.body as Record<string, unknown>, occurred_at: iso(T0 + e.due_offset_ms) }));
const revealedFeed: Ev[] = tl.map((e, i) => ({ ...publicFeed[i], payload: { ...(e.body as Record<string, unknown>), ...(e.answer ?? {}) } }));
const attackIds = new Set(tl.filter(isAtk).map(e => String(e.body.id)));

// the attacked endpoint host, an attacker process on it, and a host with no attack activity
const atkEndpoint = tl.filter(e => isAtk(e) && ["edr", "sysmon"].includes(String(e.body.source)) && (e.body as { process?: { pid?: number } }).process?.pid);
const counts = new Map<string, number>(); for (const e of atkEndpoint) counts.set(String(e.body.hostname), (counts.get(String(e.body.hostname)) ?? 0) + 1);
const HOST = [...counts.entries()].sort((a, b) => b[1] - a[1])[0][0];
const ATK_PID = Number((atkEndpoint.filter(e => e.body.hostname === HOST).at(-1)!.body as { process: { pid: number } }).process.pid);
const attackedHosts = new Set(tl.filter(isAtk).map(e => hostKey(String(e.body.hostname ?? ""))));
const CLEAN = String(tl.find(e => e.body.hostname && !String(e.body.hostname).includes("@") && !attackedHosts.has(hostKey(String(e.body.hostname))))!.body.hostname);
const END = T0 + tl.at(-1)!.due_offset_ms + 60_000;

const T3 = "u-t3", T3B = "u-t3b", MGR = "u-mgr";
const roster: RosterMember[] = [
  { user_id: T3, role: "t3", status: "active", name: "Hunter", handle: null },
  { user_id: T3B, role: "t3", status: "active", name: "Second", handle: null },
  { user_id: MGR, role: "mgr", status: "active", name: "Boss", handle: null },
];
let seq = publicFeed.length;
const act = (actor: string, role: string, type: string, payload: Record<string, unknown>, atMs: number): Ev => ({ seq: ++seq, type, actor_id: actor, role, payload, occurred_at: iso(atMs) });

/** The ref of the row standing for `key` in an evidence item, exactly as the workbench shows it. */
function refFor(evidenceId: string, kind: "memory" | "triage", snapshotMs: number, events: Ev[], key: string): string {
  const rows: FeedRow[] = publicFeed.map(e => ({ ev: withRebasedTime(e.payload as unknown as TelemetryEvent, e.occurred_at!), atMs: Date.parse(e.occurred_at!) }));
  const v = buildEvidenceView({ feed: rows, host: HOST, evidenceId, kind, snapshotMs, state: hostStateOf(events, HOST), sessionId: SID });
  for (const t of v.tables) { const i = t.keys.indexOf(key); if (i >= 0) return t.refs[i]; }
  throw new Error(`no row ${key} in ${evidenceId}`);
}

function scenario() {
  seq = publicFeed.length;
  const actions: Ev[] = [];
  actions.push(act(T3, "t3", "forensic.collected", { host: HOST, kind: "memory", evidence_id: "MEM-001" }, END));
  const goodRef = refFor("MEM-001", "memory", END, actions, `pid:${ATK_PID}`);
  actions.push(act(T3, "t3", "forensic.report", { kind: "containment_ready", summary: "ready already", readiness: "ready", next_update_min: 15 }, END + 10_000));         // before any status: premature
  actions.push(act(T3, "t3", "forensic.finding", { kind: "host_status", host: HOST, status: "compromised", summary: "attacker process in memory", confidence: "high", evidence: [goodRef] }, END + 60_000));
  actions.push(act(T3, "t3", "forensic.finding", { kind: "host_status", host: CLEAN, status: "compromised", summary: "looks bad", confidence: "high", evidence: [] }, END + 70_000));
  actions.push(act(T3, "t3", "forensic.finding", { kind: "c2", host: HOST, summary: "beacons to 198.51.100.77", confidence: "moderate", evidence: [] }, END + 75_000));
  actions.push(act(T3B, "t3", "forensic.finding", { kind: "host_status", host: HOST, status: "compromised", summary: "compromised, trust me", confidence: "low", evidence: [] }, END + 80_000));
  actions.push(act(T3B, "t3", "forensic.finding", { kind: "note", host: HOST, summary: "check backups", confidence: "low", evidence: [] }, END + 85_000));
  actions.push(act(T3, "t3", "rtr.action", { host: HOST, action: "kill", pid: ATK_PID, name: "x" }, END + 90_000));                                                       // after MEM-001: preserved
  actions.push(act(T3, "t3", "forensic.report", { kind: "containment_ready", summary: "now backed", readiness: "ready", next_update_min: 30 }, END + 110_000));               // inside the 15-min promise
  return actions;
}
const review = (actions: Ev[]) => computeForensicReview({
  events: [...revealedFeed, ...actions], publicEvents: [...publicFeed, ...actions], sessionId: SID, attackIds, roster,
  endMs: END + 600_000, relS: t => (t == null ? null : Math.round((t - T0) / 1000)),
})!;

describe("forensic review", () => {
  const actions = scenario();
  const r = review(actions);
  const f = (summary: string) => r.findings.find(x => x.summary === summary)!;

  it("confirms a right finding whose cited row shows it", () => {
    expect(f("attacker process in memory").verdict).toBe("confirmed");
    expect(f("attacker process in memory").supportedBy).toMatch(/^MEM-001\/(pslist|pstree|cmdline|netscan)#\d+$/);
  });
  it("a right call with no evidence is a guess, a wrong one is wrong, notes are not graded", () => {
    expect(f("compromised, trust me").verdict).toBe("guess");
    expect(f("looks bad").verdict).toBe("wrong");
    expect(f("looks bad").reason).toMatch(/no attack activity/);
    expect(f("beacons to 198.51.100.77").verdict).toBe("wrong");
    expect(f("check backups").verdict).toBe("ungraded");
  });
  it("citing a row that does not show it does not confirm", () => {
    const a = scenario();
    const bg = refFor("MEM-001", "memory", END, a, "pid:4");            // the System process
    const fake = act(T3B, "t3", "forensic.finding", { kind: "host_status", host: HOST, status: "compromised", summary: "cites System", confidence: "low", evidence: [bg] }, END + 95_000);
    expect(review([...a, fake]).findings.find(x => x.summary === "cites System")!.verdict).toBe("guess");
  });
  it("evidence taken after the finding cannot back it", () => {
    seq = publicFeed.length;
    const late = act(T3, "t3", "forensic.collected", { host: HOST, kind: "memory", evidence_id: "MEM-002" }, END + 200_000);
    const lateRef = refFor("MEM-002", "memory", END + 200_000, [late], "pid:" + ATK_PID);
    const early = act(T3B, "t3", "forensic.finding", { kind: "host_status", host: HOST, status: "compromised", summary: "from the future", confidence: "low", evidence: [lateRef] }, END + 150_000);
    expect(review([late, early]).findings.find(x => x.summary === "from the future")!.verdict).toBe("guess");
  });
  it("per-user scores: accuracy, support, calibration", () => {
    const me = r.perUser[T3];
    expect(me.graded).toBe(3);                        // HOST confirmed, CLEAN wrong, c2 wrong
    expect(me.confirmed).toBe(1);
    expect(me.accPct).toBe(33);
    expect(me.supportedPct).toBe(100);
    expect(me.highTotal).toBe(2); expect(me.highRight).toBe(1); expect(me.calibrationPct).toBe(50);
    const second = r.perUser[T3B];
    expect(second.guess).toBe(1); expect(second.accPct).toBe(50); expect(second.supportedPct).toBe(0);
  });
  it("memory captured before the kill = evidence preserved; a kill first destroys it", () => {
    expect(r.hosts.find(h => hostKey(h.host) === hostKey(HOST))!.kill?.preserved).toBe(true);
    expect(r.perUser[T3].preservationPct).toBe(100);
    seq = publicFeed.length;
    const killFirst = [act(T3, "t3", "rtr.action", { host: HOST, action: "kill", pid: ATK_PID, name: "x" }, END - 5_000), act(T3, "t3", "forensic.collected", { host: HOST, kind: "memory", evidence_id: "MEM-001" }, END)];
    const d = review(killFirst);
    expect(d.hosts.find(h => hostKey(h.host) === hostKey(HOST))!.kill?.preserved).toBe(false);
    expect(d.perUser[T3].preservationPct).toBe(0);
  });
  it("READY before any confirmed status is premature; after it, backed; the promised update was kept", () => {
    const [first, second] = r.reports;
    expect(first.readinessCheck).toBe("premature");
    expect(second.readinessCheck).toBe("backed");
    expect(first.promiseKept).toBe(true);
    expect(second.promiseKept).toBe(null);           // the shift ended before the next update was due
    expect(r.perUser[T3].reportPoints).toBe(8);      // sent + promise kept, but one premature READY
  });
  it("a Tier-3 who examined evidence but never reported scores 0 on reporting", () => {
    seq = publicFeed.length;
    const quiet = review([act(T3B, "t3", "forensic.collected", { host: HOST, kind: "triage", evidence_id: "TRI-001" }, END)]);
    expect(quiet.perUser[T3B].reportPoints).toBe(0);
  });
  it("no forensic activity = no review (a hunt-only Tier-3 is not penalised)", () => {
    expect(computeForensicReview({ events: revealedFeed, sessionId: SID, attackIds, roster, endMs: END, relS: () => 0 })).toBeNull();
  });
  it("the after-action report adds the forensic cells to Tier-3 and lists every judged finding", () => {
    const evs = [act(MGR, "mgr", "session.started", {}, T0 - 1000), ...revealedFeed, ...actions].sort((a, b) => Date.parse(a.occurred_at!) - Date.parse(b.occurred_at!));
    const rep = computeReport(evs, roster, { sessionId: SID, publicEvents: [...publicFeed, ...actions] });
    const t3 = rep.perUser.find(u => u.user_id === T3)!;
    expect(t3.rubric.map(c => c.label)).toEqual(expect.arrayContaining(["Forensic findings", "Findings backed by evidence", "Evidence preserved", "Confidence calibration", "Reporting to the SOC Manager"]));
    expect(t3.forensic?.confirmed).toBe(1);
    expect(rep.team.forensic?.findings.length).toBe(5);
    expect(rep.perUser.find(u => u.user_id === MGR)!.rubric.some(c => c.label === "Forensic findings")).toBe(false);
  });
});
