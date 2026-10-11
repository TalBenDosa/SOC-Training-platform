// Endpoint-record consistency gate (storyline review 2026-10-02 §C.2/§C.3): every attack story, instantiated
// for every company and rendered on every endpoint product (MDE, CrowdStrike, SentinelOne, Sophos, Sysmon),
// must read as ONE host's telemetry:
//   - one binary on one host → one hash, whether a row shows it as the process, a parent, an actor, an
//     alert's file or a written file (authored hash wins; an unhashed binary hashes the same everywhere);
//   - a parent / actor referenced by pid or unique id is the process's own row (when that row is shown);
//   - no process is its own parent;
//   - a file / registry row names the process that wrote it;
// and, in a shop that runs two endpoint products on one host (NexaCorp: Defender + Sysmon), both products give
// the same binary the same hash and the same user the same SID.
import { describe, it, expect } from "vitest";
import { ATTACK_STORIES, instantiateStory } from "@/app/(app)/dashboard/attackStories";
import { BENIGN_EVENTS } from "@/app/(app)/dashboard/benignEvents";
import { COMPANY_EVENTS } from "@/lib/sim/companyProfiles";
import { applyStack, authoredOf, nativize, stackFor, NATIVE_SOURCES } from "./index";
import { makeCtx } from "./ctx";
import { PRODUCT_LABEL, type Stack } from "./stack";
import type { NativeLog, SourceId } from "./types";
import type { TelemetryEvent } from "@/lib/sim/types";

const COMPANIES = ["nexacorp", "rocketstack", "medcore", "globallogis", "quantumbank"];
const PRODUCTS: SourceId[] = ["mde", "crowdstrike", "sentinelone", "sophos", "sysmon"];
type Rec = Record<string, any>;
const lc = (s: unknown) => String(s ?? "").toLowerCase();
const base = (p: unknown) => lc(String(p ?? "").split(/[\\/]/).pop());
const v = (x: unknown) => (x === undefined || x === null || x === "" || x === "-" ? undefined : String(x));

interface Row { ev: string; role: "own" | "parent" | "actor" | "alert" | "file"; host: string; name: string; sha256?: string; pid?: string; uid?: string }
interface Extract { rows: Row[]; selfParent: string[]; noActor: string[] }

/** The process / file identities one native record states, in its product's own field names. */
function extract(log: NativeLog, evId: string): Extract {
  const rows: Row[] = [], selfParent: string[] = [], noActor: string[] = [];
  const r = log.record as Rec;
  const add = (role: Row["role"], host: unknown, x: { name?: string; path?: string; sha256?: string; pid?: string; uid?: string }) => {
    const name = x.name ? lc(x.name) : base(x.path);
    if (name) rows.push({ ev: evId, role, host: lc(String(host ?? "").split(".")[0]), name, sha256: x.sha256 ? lc(x.sha256) : undefined, pid: x.pid, uid: x.uid });
  };
  if (log.sourceId === "mde") {
    const p = r.properties as Rec, h = p.DeviceName;
    if (log.kind === "DeviceProcessEvents") {
      add("own", h, { name: v(p.FileName), sha256: v(p.SHA256), pid: v(p.ProcessId), uid: v(p.ProcessUniqueId) });
      if (p.ProcessId != null && p.ProcessId === p.InitiatingProcessId) selfParent.push(`${evId} ProcessId = InitiatingProcessId`);
    }
    if (log.kind === "AlertEvidence") {
      if (p.EntityType === "Process") add("alert", h, { name: v(p.FileName), sha256: v(p.SHA256), pid: p.AdditionalFields ? v(JSON.parse(p.AdditionalFields).ProcessId) : undefined });
      if (p.EntityType === "File") add("file", h, { name: v(p.FileName), sha256: v(p.SHA256) });
      return { rows, selfParent, noActor };
    }
    if (log.kind === "DeviceFileEvents") add("file", h, { name: v(p.FileName), sha256: v(p.SHA256) });
    if (log.kind === "DeviceEvents" && p.ActionType === "OpenProcessApiCall") add("own", h, { name: v(p.FileName), sha256: v(p.SHA256), pid: v(p.ProcessId) });
    add(log.kind === "DeviceProcessEvents" ? "parent" : "actor", h, { name: v(p.InitiatingProcessFileName), sha256: v(p.InitiatingProcessSHA256), pid: v(p.InitiatingProcessId), uid: v(p.InitiatingProcessUniqueId) });
    if (p.InitiatingProcessId != null && p.InitiatingProcessId === p.InitiatingProcessParentId) selfParent.push(`${evId} InitiatingProcessId = InitiatingProcessParentId`);
    if (/DeviceFileEvents|DeviceRegistryEvents/.test(log.kind) && !p.InitiatingProcessFileName) noActor.push(`${evId} ${log.kind}`);
  } else if (log.sourceId === "crowdstrike") {
    const h = r.ComputerName ?? r.device?.hostname;
    if (log.kind === "ProcessRollup2") {
      add("own", h, { path: v(r.ImageFileName), sha256: v(r.SHA256HashData), pid: v(r.RawProcessId), uid: v(r.TargetProcessId) });
      add("parent", h, { name: v(r.ParentBaseFileName), uid: v(r.ParentProcessId) });
      if (r.TargetProcessId === r.ParentProcessId) selfParent.push(`${evId} TargetProcessId = ParentProcessId`);
    } else if (log.kind === "alert") {
      add("alert", h, { name: v(r.filename), sha256: v(r.sha256), pid: v(r.local_process_id), uid: v(r.process_id) });
      if (r.parent_details) add("parent", h, { name: v(r.parent_details.filename), pid: v(r.parent_details.local_process_id), uid: v(r.parent_details.process_id) });
      if (r.process_id && r.process_id === r.parent_process_id) selfParent.push(`${evId} alert process_id = parent_process_id`);
    } else {
      if (/Written$/.test(log.kind)) add("file", h, { path: v(r.TargetFileName), sha256: v(r.SHA256HashData) });
      add("actor", h, { name: v(r.ContextBaseFileName), uid: v(r.ContextProcessId) });
      if (/Written$/.test(log.kind) && !r.ContextProcessId) noActor.push(`${evId} ${log.kind}`);
    }
  } else if (log.sourceId === "sentinelone") {
    const h = r["endpoint.name"];
    if (log.kind === "threat") return { rows, selfParent, noActor };
    if (log.kind === "Process Creation" || log.kind === "Open Remote Process Handle") {
      add("own", h, { name: v(r["tgt.process.name"]), sha256: v(r["tgt.process.image.sha256"]), pid: v(r["tgt.process.pid"]), uid: v(r["tgt.process.uid"]) });
      if (r["tgt.process.uid"] === r["src.process.uid"]) selfParent.push(`${evId} tgt.process.uid = src.process.uid`);
    }
    if (/^File /.test(log.kind)) add("file", h, { path: v(r["tgt.file.path"]), sha256: v(r["tgt.file.sha256"]) });
    add(log.kind === "Process Creation" ? "parent" : "actor", h, { name: v(r["src.process.name"]), sha256: v(r["src.process.image.sha256"]), pid: v(r["src.process.pid"]), uid: v(r["src.process.uid"]) });
    add("parent", h, { name: v(r["src.process.parent.name"]), sha256: v(r["src.process.parent.image.sha256"]), pid: v(r["src.process.parent.pid"]), uid: v(r["src.process.parent.uid"]) });
    if (r["src.process.uid"] && r["src.process.uid"] === r["src.process.parent.uid"]) selfParent.push(`${evId} src.process.uid = src.process.parent.uid`);
    if (/^File /.test(log.kind) && !r["src.process.name"]) noActor.push(`${evId} ${log.kind}`);
  } else if (log.sourceId === "sophos") {
    if (log.kind === "running_processes_windows_sophos") {
      add("own", r.meta_hostname, { name: v(r.name), sha256: v(r.sha256), pid: v(r.pid) });
      add("parent", r.meta_hostname, { name: v(r.parent_name), pid: r.parent ? String(r.parent) : undefined });
      if (r.pid && r.pid === r.parent) selfParent.push(`${evId} pid = parent`);
    } else if (log.kind === "detection") {
      const rd = r.rawData ?? {};
      add("alert", rd.meta_hostname, { name: v(rd.process_name), sha256: v(rd.process_sha256), pid: v(rd.process_pid) });
    }
  } else if (log.sourceId === "sysmon") {
    const h = r.Computer;
    const sha = (hs: unknown) => v(/SHA256=([0-9A-Fa-f]{64})/.exec(String(hs ?? ""))?.[1]);
    if (log.kind === "1") {
      add("own", h, { path: v(r.Image), sha256: sha(r.Hashes), pid: v(r.ProcessId), uid: v(r.ProcessGuid) });
      if (v(r.ParentImage)) add("parent", h, { path: v(r.ParentImage), pid: v(r.ParentProcessId), uid: v(r.ParentProcessGuid) });
      if (r.ProcessGuid === r.ParentProcessGuid || r.ProcessId === r.ParentProcessId) selfParent.push(`${evId} ProcessGuid/Id = Parent`);
    } else if (log.kind === "10") {
      add("actor", h, { path: v(r.SourceImage), pid: v(r.SourceProcessId), uid: v(r.SourceProcessGUID) });
      add("own", h, { path: v(r.TargetImage), pid: v(r.TargetProcessId), uid: v(r.TargetProcessGUID) });
    } else {
      if (r.Image !== "<unknown process>") add("actor", h, { path: v(r.Image), pid: v(r.ProcessId), uid: v(r.ProcessGuid) });
      if (/^(11|12|13)$/.test(log.kind) && (!v(r.Image) || r.Image === "<unknown process>")) noActor.push(`${evId} Sysmon ${log.kind}`);
    }
  }
  return { rows, selfParent, noActor };
}

/** Every story, instantiated for the company on the product (EDR as the session's EDR; Sysmon as host telemetry). */
function* renderedStories(product: SourceId): Generator<{ company: string; story: string; logs: { log: NativeLog; ev: string }[] }> {
  const mod = NATIVE_SOURCES[product]!;
  for (const company of COMPANIES) {
    const pool = (COMPANY_EVENTS[company]?.length ? COMPANY_EVENTS[company] : BENIGN_EVENTS) as TelemetryEvent[];
    const ctx = makeCtx(company);
    const edr = product === "sysmon" ? undefined : product;
    for (const s of ATTACK_STORIES) {
      const logs: { log: NativeLog; ev: string }[] = [];
      for (const e of instantiateStory(s, pool, edr ? PRODUCT_LABEL[edr] : undefined, company).events ?? []) {
        if (!["edr", "av", "sysmon"].includes(e.source) || (edr && e.source === "sysmon")) continue;
        const log = mod.fromTelemetry(authoredOf(applyStack(e, company, (edr ? { edr } : {}) as Stack)), ctx);
        if (log) logs.push({ log, ev: e.id });
      }
      if (logs.length) yield { company, story: s.id, logs };
    }
  }
}

describe("endpoint records of one story agree (every story × company × product)", () => {
  for (const product of PRODUCTS) {
    it(`${product}: one hash per binary, parents are their own rows, nothing self-parents, writes name their writer`, () => {
      const problems: string[] = [];
      let stories = 0, refs = 0;
      for (const { company, story, logs } of renderedStories(product)) {
        stories++;
        const rows: Row[] = [];
        for (const { log, ev } of logs) {
          const x = extract(log, ev);
          rows.push(...x.rows);
          for (const m of x.selfParent) problems.push(`${company} ${story} self-parent: ${m}`);
          for (const m of x.noActor) problems.push(`${company} ${story} no initiating process: ${m}`);
        }
        const byImage = new Map<string, Row[]>();
        for (const r of rows) byImage.set(`${r.host}|${r.name}`, [...(byImage.get(`${r.host}|${r.name}`) ?? []), r]);
        for (const [img, list] of byImage) {
          const hashes = new Set(list.map(r => r.sha256).filter(Boolean));
          if (hashes.size > 1) problems.push(`${company} ${story} ${img}: ${hashes.size} hashes (${list.filter(r => r.sha256).map(r => `${r.ev}/${r.role}=${r.sha256!.slice(0, 8)}`).join(" ")})`);
          const own = list.filter(r => r.role === "own");
          if (!own.length) continue;
          const ownPids = new Set(own.map(r => r.pid).filter(Boolean)), ownUids = new Set(own.map(r => r.uid).filter(Boolean));
          for (const r of list) {
            if (r.role === "own" || r.role === "file") continue;
            refs++;
            if (r.pid && ownPids.size && !ownPids.has(r.pid)) problems.push(`${company} ${story} ${r.ev} ${r.role} ${img}: pid ${r.pid} is no own row's (${[...ownPids].join(", ")})`);
            if (r.uid && ownUids.size && !ownUids.has(r.uid)) problems.push(`${company} ${story} ${r.ev} ${r.role} ${img}: id ${r.uid} is no own row's (${[...ownUids].join(", ")})`);
          }
        }
      }
      console.log(`[endpoint] ${product}: ${stories} stories, ${refs} parent / actor / alert references checked`);
      expect(stories).toBeGreaterThan(30);
      expect(problems.slice(0, 25)).toEqual([]);
    });
  }

  it("two products on one host (NexaCorp: Defender + Sysmon) give one binary one hash and one user one SID", () => {
    const company = "nexacorp";
    const stack = stackFor(company);
    const pool = (COMPANY_EVENTS[company]?.length ? COMPANY_EVENTS[company] : BENIGN_EVENTS) as TelemetryEvent[];
    const problems: string[] = [];
    for (const s of ATTACK_STORIES) {
      const hashes = new Map<string, Set<string>>(), sids = new Map<string, Set<string>>();
      const note = (m: Map<string, Set<string>>, k: string, val: unknown) => { if (val) m.set(k, (m.get(k) ?? new Set()).add(lc(val))); };
      for (const e of instantiateStory(s, pool, PRODUCT_LABEL[stack.edr!], company).events ?? []) {
        const log = nativize(authoredOf(applyStack(e, company, stack)), company, stack);
        if (!log) continue;
        const r = ((log.record as Rec).properties ?? log.record) as Rec;
        if (log.sourceId === "mde") {
          const h = lc(r.DeviceName);
          if (log.kind === "DeviceProcessEvents") note(hashes, `${h}|${lc(r.FileName)}`, r.SHA256);
          if (r.InitiatingProcessFileName) note(hashes, `${h}|${lc(r.InitiatingProcessFileName)}`, r.InitiatingProcessSHA256);
          if (r.AccountName && r.AccountSid) note(sids, lc(r.AccountName), r.AccountSid);
        } else if (log.sourceId === "sysmon") {
          const h = lc(String(r.Computer).split(".")[0]);
          if (log.kind === "1") note(hashes, `${h}|${base(r.Image)}`, /SHA256=([0-9A-Fa-f]{64})/.exec(String(r.Hashes))?.[1]);
          const m = /^HKU\\(S-1-5-21-[\d-]+)\\/.exec(String(r.TargetObject ?? ""));
          if (m) note(sids, base(r.User), m[1]);
        }
      }
      for (const [k, set] of hashes) if (set.size > 1) problems.push(`${s.id} ${k}: hashes ${[...set].map(x => x.slice(0, 8)).join(" vs ")}`);
      for (const [k, set] of sids) if (set.size > 1) problems.push(`${s.id} ${k}: SIDs ${[...set].join(" vs ")}`);
    }
    expect(problems).toEqual([]);
  });
});

describe("decisive endpoint evidence keeps its native shape", () => {
  const story = ATTACK_STORIES.find(s => s.id === "ntlm-relay")!;
  const render = (product: SourceId, id: string) => {
    const company = "nexacorp";
    const edr = product === "sysmon" ? undefined : product;
    const e = instantiateStory(story, BENIGN_EVENTS as TelemetryEvent[], edr ? PRODUCT_LABEL[edr] : undefined, company).events!.find(x => x.id === id)!;
    return NATIVE_SOURCES[product]!.fromTelemetry(authoredOf(applyStack(e, company, (edr ? { edr } : {}) as Stack)), makeCtx(company))!;
  };

  it("an lsass handle open is an access record (target + rights), not the opener's process start", () => {
    const mde = render("mde", "ntlm_09_lsass_dump");
    const p = (mde.record as Rec).properties;
    expect([mde.kind, p.ActionType, p.FileName, p.InitiatingProcessFileName]).toEqual(["DeviceEvents", "OpenProcessApiCall", "lsass.exe", "cmd.exe"]);
    expect(JSON.parse(p.AdditionalFields).DesiredAccess).toBe(0x1fffff);
    expect(p.InitiatingProcessAccountSid).toBe("S-1-5-18"); // the opener ran as SYSTEM (authored)
    const s1 = render("sentinelone", "ntlm_09_lsass_dump");
    expect([s1.kind, (s1.record as Rec)["tgt.process.name"], (s1.record as Rec)["src.process.name"]]).toEqual(["Open Remote Process Handle", "lsass.exe", "cmd.exe"]);
    const cs = render("crowdstrike", "ntlm_09_lsass_dump");
    expect([cs.kind, (cs.record as Rec).technique_id, (cs.record as Rec).filename]).toEqual(["alert", "T1003.001", "cmd.exe"]);
    const sm = render("sysmon", "ntlm_09_lsass_dump");
    expect([sm.kind, (sm.record as Rec).TargetImage, (sm.record as Rec).GrantedAccess]).toEqual(["10", "C:\\Windows\\System32\\lsass.exe", "0x1FFFFF"]);
    // Every product gives lsass.exe the same pid (one process instance per host).
    expect((sm.record as Rec).TargetProcessId).toBe(String(p.ProcessId));
  });

  it("a service binary started by services.exe is a ServiceInstalled record on Defender", () => {
    const p = (render("mde", "ntlm_06_psexec_service").record as Rec).properties;
    expect([p.ActionType, p.FileName, p.InitiatingProcessFileName, JSON.parse(p.AdditionalFields).ServiceName]).toEqual(["ServiceInstalled", "PSEXESVC.exe", "services.exe", "PSEXESVC"]);
  });
});
