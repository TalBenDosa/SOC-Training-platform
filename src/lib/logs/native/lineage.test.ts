// Process lineage gate (expert review #3 / #21 / #24): within one story, every reference to a
// process — a child's parent ids, an action's actor ids (DNS / network / file / registry / task),
// an alert's triggering-process and parent ids — equals that process's OWN ids on its own record,
// whenever that record is in the story. Checked for every story, company and EDR product, on the
// exact events the feed renders (instantiateStory with the session's EDR). Windows pids are
// multiples of 4, and one user's Explorer never parents another user's process.
import { describe, it, expect } from "vitest";
import { storiesForCompany, instantiateStory } from "@/app/(app)/dashboard/attackStories";
import { COMPANY_EVENTS } from "@/lib/sim/companyProfiles";
import { BENIGN_EVENTS } from "@/app/(app)/dashboard/benignEvents";
import { applyStack, authoredOf, NATIVE_SOURCES } from "./index";
import { makeCtx } from "./ctx";
import { PRODUCT_LABEL, type Stack } from "./stack";
import { edrFacts, taskFacts, schtasksTask } from "./sources/edr-normalize";
import type { NativeLog, SourceId } from "./types";
import type { TelemetryEvent } from "@/lib/sim/types";

const COMPANIES = ["nexacorp", "rocketstack", "medcore", "globallogis", "quantumbank"];
const EDRS: SourceId[] = ["crowdstrike", "sentinelone", "mde"];

interface Proc { host: string; name: string; id?: string; pid?: string; t: number; os?: string }
interface Ref extends Proc { what: string; ev: string }

const lc = (s: unknown) => String(s ?? "").toLowerCase();
const base = (p: unknown) => lc(String(p ?? "").split(/[\\/]/).pop());
const firstTok = (c: unknown) => base((/^"([^"]+)"|^(\S+)/.exec(String(c ?? "").trim()) ?? [])[1] ?? (/^"([^"]+)"|^(\S+)/.exec(String(c ?? "").trim()) ?? [])[2]);
const str = (v: unknown) => (v === undefined || v === null || v === "" ? undefined : String(v));

/** Own process records and process references of one rendered record. */
function extract(log: NativeLog, ev: TelemetryEvent): { own: Proc[]; refs: Ref[] } {
  const r = log.record as Record<string, any>;
  const own: Proc[] = [], refs: Ref[] = [];
  const t = log.timeMs;
  const ref = (what: string, host: string, name: unknown, id: unknown, pid?: unknown) => {
    if (name && (str(id) || str(pid))) refs.push({ what, ev: ev.id, host: lc(host), name: lc(name), id: str(id), pid: str(pid), t });
  };
  const f = edrFacts(ev);
  if (log.sourceId === "crowdstrike") {
    const host = r.ComputerName ?? r.device?.hostname;
    if (log.kind === "ProcessRollup2") {
      // Raw PR2 has no FileName: the image is the ImageFileName's last segment (else the event's process name).
      own.push({ host: lc(host), name: base(r.ImageFileName) || lc(f.proc.name) || firstTok(r.CommandLine), id: r.TargetProcessId, pid: r.RawProcessId, t, os: r.event_platform });
      ref("PR2.ParentProcessId", host, r.ParentBaseFileName, r.ParentProcessId);
    } else if (log.kind === "ScheduledTaskRegistered") {
      const reg = (taskFacts(ev, f) ?? schtasksTask(f))?.registrar;
      ref("ScheduledTaskRegistered.RpcClientProcessId", host, reg?.name ?? base(reg?.path), r.RpcClientProcessId);
    } else if (log.kind === "alert") {
      ref("alert.process_id", host, r.filename, r.process_id, r.local_process_id);
      if (r.parent_details) ref("alert.parent_details", host, r.parent_details.filename, r.parent_details.process_id, r.parent_details.local_process_id);
    } else if (r.ContextProcessId) {
      // Registry events carry no ContextBaseFileName (card §3h): the actor is the event's process.
      ref(`${log.kind}.ContextProcessId`, host, r.ContextBaseFileName ?? (r.ContextBaseFileName === undefined && /Value/.test(log.kind) ? f.proc.name : undefined), r.ContextProcessId);
    }
  } else if (log.sourceId === "sentinelone") {
    if (log.kind === "threat") return { own, refs };
    const host = r["endpoint.name"];
    if (log.kind === "Process Creation") own.push({ host: lc(host), name: lc(r["tgt.process.name"]), id: r["tgt.process.uid"], pid: String(r["tgt.process.pid"]), t, os: r["endpoint.os"] === "windows" ? "Win" : r["endpoint.os"] });
    ref(`${log.kind}.src.process`, host, r["src.process.name"], r["src.process.uid"], r["src.process.pid"]);
    ref(`${log.kind}.src.process.parent`, host, r["src.process.parent.name"], r["src.process.parent.uid"], r["src.process.parent.pid"]);
  } else if (log.sourceId === "mde") {
    const p = r.properties ?? {};
    const host = p.DeviceName;
    if (log.kind === "DeviceProcessEvents") own.push({ host: lc(host), name: lc(p.FileName), id: p.ProcessUniqueId, pid: String(p.ProcessId), t, os: /^[A-Za-z]:\\/.test(String(p.FolderPath ?? "")) ? "Win" : undefined });
    if (log.kind === "AlertEvidence") {
      if (p.EntityType === "Process" && p.AdditionalFields) ref("AlertEvidence.ProcessId", host, p.FileName, undefined, JSON.parse(p.AdditionalFields).ProcessId);
    } else {
      ref(`${log.kind}.InitiatingProcess`, host, p.InitiatingProcessFileName, p.InitiatingProcessUniqueId, p.InitiatingProcessId);
      ref(`${log.kind}.InitiatingProcessParent`, host, p.InitiatingProcessParentFileName, undefined, p.InitiatingProcessParentId);
    }
  }
  return { own, refs };
}

function renderStory(events: TelemetryEvent[], company: string, edr: SourceId): { log: NativeLog; ev: TelemetryEvent }[] {
  const mod = NATIVE_SOURCES[edr]!;
  const ctx = makeCtx(company);
  const out: { log: NativeLog; ev: TelemetryEvent }[] = [];
  for (const e of events) {
    if (e.source !== "edr" && e.source !== "av") continue;
    const ev = authoredOf(applyStack(e, company, { edr } as Stack));
    const log = mod.fromTelemetry(ev, ctx);
    if (log) out.push({ log, ev });
    for (const c of mod.companions?.(ev, ctx) ?? []) out.push({ log: c, ev });
  }
  return out;
}

describe("process lineage within a story", () => {
  for (const edr of EDRS) {
    it(`${edr}: every parent / actor / alert reference equals the process's own ids`, () => {
      const problems = new Set<string>();
      let checked = 0, stories = 0;
      for (const company of COMPANIES) {
        const pool = (COMPANY_EVENTS[company]?.length ? COMPANY_EVENTS[company] : BENIGN_EVENTS) as TelemetryEvent[];
        const seen = new Set<string>();
        for (const diff of ["easy", "medium", "hard"] as const) for (const s of storiesForCompany(company, diff)) {
          if (seen.has(s.id)) continue;
          seen.add(s.id);
          const rendered = renderStory(instantiateStory(s, pool, PRODUCT_LABEL[edr], company).events ?? [], company, edr);
          if (!rendered.length) continue;
          stories++;
          const own = new Map<string, Proc[]>();
          const refs: Ref[] = [];
          for (const { log, ev } of rendered) {
            const x = extract(log, ev);
            for (const o of x.own) own.set(`${o.host}|${o.name}`, [...(own.get(`${o.host}|${o.name}`) ?? []), o]);
            refs.push(...x.refs);
            // Windows pids are multiples of 4.
            for (const o of x.own) if (o.os === "Win" && o.pid && Number(o.pid) % 4 !== 0) problems.add(`${company} ${s.id} ${o.name} pid ${o.pid} not a multiple of 4`);
          }
          // One process instance → one id set, however many records describe it.
          for (const [k, list] of own) {
            const ids = new Set(list.map(o => `${o.id}/${o.pid}`));
            if (ids.size > 1) problems.add(`${company} ${s.id} ${k}: ${list.length} own records disagree (${[...ids].join(" vs ")})`);
          }
          for (const ref of refs) {
            const target = own.get(`${ref.host}|${ref.name}`)?.[0];
            if (!target) continue;
            checked++;
            if (ref.id !== undefined && target.id !== undefined && ref.id !== target.id) problems.add(`${company} ${s.id} ${ref.ev} ${ref.what} ${ref.name}: id ${ref.id} ≠ own ${target.id}`);
            if (ref.pid !== undefined && target.pid !== undefined && ref.pid !== target.pid) problems.add(`${company} ${s.id} ${ref.ev} ${ref.what} ${ref.name}: pid ${ref.pid} ≠ own ${target.pid}`);
          }
        }
      }
      console.log(`[lineage] ${edr}: ${stories} stories, ${checked} references checked against the referenced process's own record`);
      expect(checked).toBeGreaterThan(20);
      expect([...problems].slice(0, 25)).toEqual([]);
    });
  }

  it("session-scoped parents: one user's Explorer never parents another user's process, or the next day's", () => {
    const ctx = makeCtx("nexacorp");
    const mk = (id: string, ts: string, user: string): TelemetryEvent => ({
      id, ts, source: "edr", vendor: "CrowdStrike Falcon", event_type: "process_create", hostname: "WS-OPS-2214", user_email: `${user}@nexacorp.com`,
      process: { name: "notepad.exe", pid: 1, parent_name: "explorer.exe", cmdline: "notepad.exe" }, raw: {},
    } as unknown as TelemetryEvent);
    const cs = NATIVE_SOURCES.crowdstrike!;
    const ppid = (e: TelemetryEvent) => cs.fromTelemetry(e, ctx)!.record.ParentProcessId;
    const a = ppid(mk("a", "2026-05-20T09:00:00Z", "m.levi"));
    expect(ppid(mk("b", "2026-05-20T15:30:00Z", "m.levi"))).toBe(a);          // same user, same day: same Explorer
    expect(ppid(mk("c", "2026-05-20T09:05:00Z", "s.cohen"))).not.toBe(a);     // another user
    expect(ppid(mk("d", "2026-05-22T09:00:00Z", "m.levi"))).not.toBe(a);      // another day
  });
});
