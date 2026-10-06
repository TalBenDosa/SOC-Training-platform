// Expert-review fidelity fixes (docs/qa/EXPERT-REVIEW-2026-10-02.md), checked on synthetic events
// and on the whole corpus: task registration records (#4), Falcon disposition semantics (#8/#16),
// S1 telemetry vs threats and one mitigation mode per agent (#13), Windows pid granularity (#21),
// PAN-OS URL log actions (#23), MDE completeness (#25), no cross-tenant constants (#28), MDO verdict
// at delivery (#12) and Okta's view of corporate users (#17).
import { describe, it, expect } from "vitest";
import { NATIVE_SOURCES, nativize, canonicalPids } from "./index";
import { makeCtx } from "./ctx";
import { validateNative } from "./validate";
import { corpus } from "./testing/corpus";
import { egressIp } from "./sources/firewall-shared";
import type { NativeLog, SourceId } from "./types";
import type { TelemetryEvent } from "@/lib/sim/types";

const ctx = makeCtx("nexacorp");
const mod = (id: SourceId) => NATIVE_SOURCES[id]!;
const render = (id: SourceId, ev: TelemetryEvent, c = ctx) => mod(id).fromTelemetry(ev, c)!;
const valid = (l: NativeLog) => expect(validateNative(l, mod(l.sourceId).schema), `${l.sourceId}/${l.kind}`).toEqual([]);
const P = (l: NativeLog) => (l.record as { properties: Record<string, unknown> }).properties;
const ev = (o: Partial<TelemetryEvent> & { id: string }): TelemetryEvent =>
  ({ ts: "2026-05-29T20:16:00.000Z", source: "edr", vendor: "Microsoft Defender for Endpoint", hostname: "WS-ENG-2093", user_email: "y.golan@nexacorp.com", raw: {}, ...o } as TelemetryEvent);

const installer = ev({
  id: "fx-installer", event_type: "process_create",
  process: { name: "Office_Pro_2026_Activator_Setup.exe", pid: 6120, parent_name: "explorer.exe", parent_pid: 3140, cmdline: "\"C:\\Users\\y.golan\\Downloads\\Office_Pro_2026_Activator_Setup.exe\"" },
});
// The authored MDE row the review found dropped: a ScheduledTaskCreated whose only process is the registrar.
const taskCreated = ev({
  id: "fx-task", ts: "2026-05-29T20:16:40.000Z", event_type: "scheduled_task",
  raw: { ActionType: "ScheduledTaskCreated", TaskName: "OfficeLicenseRefresh", FolderPath: "C:\\ProgramData\\OfficeTools\\svchelper.exe",
    InitiatingProcessFileName: "Office_Pro_2026_Activator_Setup.exe", InitiatingProcessAccountName: "y.golan", DeviceName: "WS-ENG-2093" },
});
const schtasks = ev({
  id: "fx-schtasks", ts: "2026-05-29T20:16:40.000Z", event_type: "process_create",
  process: { name: "schtasks.exe", pid: 6456, path: "C:\\Windows\\System32\\schtasks.exe", parent_name: "Office_Pro_2026_Activator_Setup.exe", parent_pid: 6120,
    cmdline: "schtasks.exe /create /tn \"OfficeLicenseRefresh\" /tr \"C:\\ProgramData\\OfficeTools\\svchelper.exe\" /sc minute /mo 30 /f" },
});

describe("#4 scheduled-task registration is its own record", () => {
  it("CrowdStrike ScheduledTaskRegistered: TaskName / TaskExecCommand, RpcClientProcessId = the registrar's TargetProcessId", () => {
    const t = render("crowdstrike", taskCreated);
    valid(t);
    expect(t.kind).toBe("ScheduledTaskRegistered");
    expect(t.record.TaskName).toBe("\\OfficeLicenseRefresh");
    expect(t.record.TaskExecCommand).toBe("C:\\ProgramData\\OfficeTools\\svchelper.exe");
    expect(t.record.TaskAuthor).toBe("NEXACORP\\y.golan");
    expect(t.record.RpcClientProcessId).toBe(render("crowdstrike", installer).record.TargetProcessId);
  });
  it("SentinelOne Task Register: task.name / task.path, src.process = the registrar", () => {
    const t = render("sentinelone", taskCreated);
    valid(t);
    expect(t.kind).toBe("Task Register");
    expect(t.record["task.name"]).toBe("OfficeLicenseRefresh");
    expect(t.record["task.path"]).toBe("\\OfficeLicenseRefresh");
    expect(t.record["src.process.uid"]).toBe(render("sentinelone", installer).record["tgt.process.uid"]);
  });
  it("Defender DeviceEvents ScheduledTaskCreated with TaskName / TaskContent", () => {
    const t = render("mde", taskCreated);
    valid(t);
    expect(t.kind).toBe("DeviceEvents");
    expect(P(t).ActionType).toBe("ScheduledTaskCreated");
    const add = JSON.parse(String(P(t).AdditionalFields));
    expect(add.TaskName).toBe("\\OfficeLicenseRefresh");
    expect(add.TaskContent).toContain("<Command>C:\\ProgramData\\OfficeTools\\svchelper.exe</Command>");
    expect(P(t).InitiatingProcessUniqueId).toBe(P(render("mde", installer)).ProcessUniqueId);
  });
  it("a schtasks.exe /create process start carries the registration as a companion record", () => {
    for (const id of ["crowdstrike", "sentinelone", "mde"] as SourceId[]) {
      const main = render(id, schtasks);
      const comp = mod(id).companions!(schtasks, ctx);
      expect(comp.length, id).toBe(1);
      valid(comp[0]);
      expect(JSON.stringify(comp[0].record)).toContain("OfficeLicenseRefresh");
      if (id === "crowdstrike") { expect(comp[0].record.RpcClientProcessId).toBe(main.record.TargetProcessId); expect(comp[0].record.id).not.toBe(main.record.id); }
      if (id === "sentinelone") { expect(comp[0].record["src.process.uid"]).toBe(main.record["tgt.process.uid"]); expect(comp[0].record["event.id"]).not.toBe(main.record["event.id"]); }
    }
  });
});

describe("#8/#16 Falcon dispositions follow what the sensor did", () => {
  const anydesk = (raw: Record<string, unknown>, extra: Partial<TelemetryEvent> = {}) => ev({
    id: `fx-ad-${JSON.stringify(raw).length}-${extra.description?.length ?? 0}`, ts: "2026-05-27T14:06:00.000Z", vendor: "CrowdStrike Falcon", event_type: "av_quarantine", severity: "critical",
    process: { name: "AnyDesk.exe", pid: 5210, parent_name: "explorer.exe", cmdline: "\"C:\\Users\\y.golan\\Downloads\\AnyDesk.exe\"" }, raw, ...extra,
  });
  const disp = (l: NativeLog) => ({ code: l.record.pattern_disposition, flags: Object.entries(l.record.pattern_disposition_details as Record<string, boolean>).filter(([, v]) => v).map(([k]) => k) });
  it("a running process that is stopped is KILLED (2048), never 'blocked from execution'", () => {
    for (const r of [{ action_result: "process_killed" }, { action_result: "blocked" }, { "s1.mitigation_status": "mitigated" }]) {
      const a = render("crowdstrike", anydesk(r));
      expect(disp(a), JSON.stringify(r)).toEqual({ code: 2048, flags: ["kill_process"] });
    }
  });
  it("kill AND quarantine → 2304 with both flags; execution prevented → 16 process_blocked", () => {
    expect(disp(render("crowdstrike", anydesk({ action_result: "quarantined", "process.killed": "true" })))).toEqual({ code: 2304, flags: ["kill_process", "quarantine_file"] });
    const blocked = render("crowdstrike", anydesk({ action_result: "blocked" }, { description: "Falcon blocked AnyDesk.exe from executing." }));
    expect(disp(blocked)).toEqual({ code: 16, flags: ["process_blocked"] });
  });
  it("the description is Falcon's detection wording, never an action claim that could contradict the flags", () => {
    const a = render("crowdstrike", anydesk({ action_result: "process_killed", "crowdstrike.DetectDescription": "The file and its parent process were quarantined and killed." }));
    expect(String(a.record.description)).not.toMatch(/kill|quarantin|terminat/i);
  });
  it("a download is a file write, not an alert (a reshape's generic DetectionSummaryEvent name is not a verdict)", () => {
    const dl = ev({ id: "fx-dl", vendor: "CrowdStrike Falcon", event_type: "file_create", file: { path: "C:\\Users\\y.golan\\Downloads\\AnyDesk.exe", sha256: "a".repeat(64) },
      raw: { "crowdstrike.event_simpleName": "DetectionSummaryEvent", "file.path": "C:\\Users\\y.golan\\Downloads\\AnyDesk.exe" } });
    expect(render("crowdstrike", dl).kind).toBe("PeFileWritten");
  });
});

describe("#13 SentinelOne: telemetry steps are Process Creation; one mitigation mode per agent", () => {
  it("an alert-grade process step with no product verdict renders as Process Creation with its command line", () => {
    const step = ev({ id: "fx-wscript", vendor: "SentinelOne", event_type: "process_create", is_detection: true, severity: "high",
      process: { name: "wscript.exe", pid: 9312, parent_name: "explorer.exe", cmdline: "wscript.exe \"C:\\Users\\y.golan\\Downloads\\Chrome_Update.js\"" } });
    const l = render("sentinelone", step);
    expect(l.kind).toBe("Process Creation");
    expect(l.record["tgt.process.cmdline"]).toContain("Chrome_Update.js");
  });
  it("agentMitigationMode is the same on every threat of a host, mitigated or not", () => {
    const threat = (id: string, raw: Record<string, unknown>) => render("sentinelone", ev({ id, vendor: "SentinelOne", event_type: "edr_alert", severity: "critical",
      process: { name: "powershell.exe", pid: 1, parent_name: "wscript.exe", cmdline: "powershell.exe -enc AAAA" }, raw }));
    const modes = [threat("fx-t1", { action_result: "allowed" }), threat("fx-t2", { action_result: "process_killed" })]
      .flatMap(l => [(l.record.agentRealtimeInfo as Record<string, unknown>).agentMitigationMode, (l.record.agentDetectionInfo as Record<string, unknown>).agentMitigationMode]);
    expect(new Set(modes).size).toBe(1);
  });
});

describe("#21 Windows pids / tids are multiples of 4", () => {
  it("EDR pids (authored 5550 / 9021) and Sysmon pid / tid fields across the corpus", () => {
    const p = ev({ id: "fx-pid", event_type: "process_create", process: { name: "AnyDesk.exe", pid: 5550, parent_name: "explorer.exe", parent_pid: 9021, cmdline: "AnyDesk.exe" } });
    expect(Number(render("crowdstrike", p).record.RawProcessId) % 4).toBe(0);
    expect(Number(render("sentinelone", p).record["tgt.process.pid"]) % 4).toBe(0);
    expect(Number(P(render("mde", p)).ProcessId) % 4).toBe(0);
    expect(Number(P(render("mde", p)).InitiatingProcessId) % 4).toBe(0);
    const bad: string[] = [];
    for (const c of corpus().filter(x => x.ev.source === "sysmon")) {
      const l = mod("sysmon").fromTelemetry(c.ev, makeCtx(c.companyId));
      if (!l) continue;
      for (const k of ["ProcessId", "ParentProcessId", "SourceProcessId", "TargetProcessId", "ProcessID", "ThreadID", "SourceThreadId"]) {
        const v = l.record[k];
        if (v !== undefined && /^\d+$/.test(String(v)) && Number(v) !== 0 && Number(v) % 4 !== 0) bad.push(`${c.ev.id} ${k}=${v}`);
      }
    }
    expect(bad.slice(0, 10)).toEqual([]);
  });
});

describe("canonicalPids — the pid every EDR record prints, for UIs that show process.pid", () => {
  it("equals CrowdStrike RawProcessId, S1 tgt.process.pid and Defender ProcessId / InitiatingProcessId", () => {
    const c = canonicalPids(installer, "nexacorp");
    expect(String(c.pid)).toBe(render("crowdstrike", installer).record.RawProcessId);
    expect(c.pid).toBe(render("sentinelone", installer).record["tgt.process.pid"]);
    expect(c.pid).toBe(P(render("mde", installer)).ProcessId);
    expect(c.parentPid).toBe(P(render("mde", installer)).InitiatingProcessId);
  });
});

describe("#23 PAN-OS URL-filtering logs", () => {
  it("an allowed-and-logged URL entry is action 'alert' (PAN-OS writes no 'allow' URL log)", () => {
    const bad: string[] = [];
    for (const c of corpus().filter(x => x.ev.source === "firewall")) {
      for (const company of ["nexacorp", "quantumbank"]) {
        const l = nativize(c.ev, company, { firewall: "paloalto" });
        if (l?.kind === "THREAT" && l.record.subtype === "url" && !["alert", "block-url", "continue", "override", "block-continue", "block-override"].includes(String(l.record.action))) bad.push(`${c.ev.id} ${l.record.action}`);
      }
    }
    expect(bad).toEqual([]);
  });
});

describe("#25 Defender completeness", () => {
  it("creator columns are filled where derivable (Explorer's path / command line / hash / parent)", () => {
    const p = P(render("mde", installer));
    expect(p.InitiatingProcessFolderPath).toBe("C:\\Windows\\explorer.exe");
    expect(p.InitiatingProcessCommandLine).toBe("C:\\WINDOWS\\Explorer.EXE");
    expect(String(p.InitiatingProcessSHA256)).toMatch(/^[0-9a-f]{64}$/);
    expect(p.InitiatingProcessParentFileName).toBe("userinit.exe");
  });
  it("a user's hand copy to the Desktop is Explorer's write", () => {
    const copy = ev({ id: "fx-copy", event_type: "file_create", file: { path: "C:\\Users\\y.golan\\Desktop\\USB_Backup_Tool.exe", sha256: "b".repeat(64) } });
    const p = P(render("mde", copy));
    expect(p.InitiatingProcessFileName).toBe("explorer.exe");
    expect(p.InitiatingProcessUniqueId).toBe(P(render("mde", installer)).InitiatingProcessUniqueId); // the same Explorer that later starts the tool
  });
  it("AlertEvidence names the family when the detection does; another engine's signature becomes a Defender-style title", () => {
    const av = (id: string, name: string) => P(render("mde", ev({ id, event_type: "av_quarantine", severity: "critical", file: { path: "C:\\ProgramData\\x\\svchelper.exe", sha256: "c".repeat(64) },
      raw: { ThreatName: name, action_result: "quarantined" } })));
    expect(av("fx-av1", "Trojan:Win32/Wacatac.B!ml").ThreatFamily).toBe("Wacatac");
    const pua = av("fx-av2", "PUA.RemoteAdmin.AnyDesk");
    expect(pua.ThreatFamily).toBe("AnyDesk");
    expect(pua.Title).toBe("'AnyDesk' unwanted software was prevented");
  });
});

describe("#28 no constants shared between tenants", () => {
  it("S1 threat ids, NAT source ports and MDO NetworkMessageIds differ per company; a file's hash does not", () => {
    const med = makeCtx("medcore"), qb = makeCtx("quantumbank");
    const threat = ev({ id: "fx-threat", vendor: "SentinelOne", event_type: "av_quarantine", severity: "critical", file: { path: "C:\\Users\\a\\Desktop\\x.exe", sha256: "d".repeat(64) }, raw: { action_result: "quarantined" } });
    expect(render("sentinelone", threat, med).record.id).not.toBe(render("sentinelone", threat, qb).record.id);
    const out = ev({ id: "fx-fw", source: "firewall", vendor: "Palo Alto Networks", event_type: "net_connection", src_ip: "10.10.40.63", dst_ip: "185.220.101.204", dst_port: 443, protocol: "tcp", raw: {} });
    const pa = (c: typeof med) => render("paloalto", out, c).record.natsport, cp = (c: typeof med) => render("checkpoint", out, c).record.xlatesport;
    expect(pa(med)).not.toBe(pa(qb));
    expect(cp(med)).not.toBe(cp(qb));
    const mail = ev({ id: "fx-mail", source: "email_gateway", vendor: "Microsoft Defender for Office 365", event_type: "email_received", user_email: "r.avraham@nexacorp.com",
      raw: { "email.from.address": "n@shiptrack-express.info", "data.office365.NetworkMessageId": "e7a91c4f-3b62-4d18-9e05-6c8f2a7b19e3" } });
    const nm = (c: typeof med) => P(render("defender_o365", mail, c)).NetworkMessageId;
    expect(nm(med)).not.toBe(nm(qb));
    expect(nm(med)).toBe(nm(makeCtx("medcore"))); // still one id per message within a tenant
    const file = ev({ id: "fx-file", event_type: "file_create", file: { path: "C:\\Users\\a\\Downloads\\x.exe", sha256: "e".repeat(64) } });
    expect(P(render("mde", file, med)).SHA1).toBe(P(render("mde", file, qb)).SHA1);
  });
  it("an S1 child never reuses its parent's trace.id / packet.id", () => {
    const parent = render("sentinelone", ev({ id: "fx-p", vendor: "SentinelOne", event_type: "process_create", process: { name: "a.exe", pid: 1, parent_name: "explorer.exe", cmdline: "a.exe" } }));
    const child = render("sentinelone", ev({ id: "fx-c", ts: "2026-05-29T20:16:10.000Z", vendor: "SentinelOne", event_type: "process_create", process: { name: "b.exe", pid: 2, parent_name: "a.exe", cmdline: "b.exe" } }));
    expect(child.record["trace.id"]).not.toBe(parent.record["trace.id"]);
    expect(child.record["packet.id"]).not.toBe(parent.record["packet.id"]);
  });
});

describe("#12 Defender for Office 365 verdicts", () => {
  const lure = (event_type: string, raw: Record<string, unknown> = {}) => ev({
    id: `fx-lure-${event_type}`, ts: "2026-05-20T10:15:00.000Z", source: "email_gateway", vendor: "Microsoft Defender for Office 365", event_type: event_type as TelemetryEvent["event_type"], user_email: "r.avraham@nexacorp.com",
    raw: { "email.from.address": "notifications@shiptrack-express.info", "email.attachment.name": "Delivery_Notice_48213.zip", "threat.category": "Phishing", "spf.result": "fail", ...raw },
  });
  it("a weaponised attachment is a Malware verdict from File detonation", () => {
    const p = P(render("defender_o365", lure("email_blocked")));
    expect(p.ThreatTypes).toBe("Malware");
    expect(JSON.parse(String(p.DetectionMethods))).toEqual({ Malware: ["File detonation"] });
    expect(p.EmailActionPolicy).toBe("Safe Attachments");
  });
  it("delivered with no override = clean at delivery (no high-confidence verdict on a delivered message)", () => {
    const p = P(render("defender_o365", lure("email_received", { action_result: "delivered" })));
    expect(p.DeliveryAction).toBe("Delivered");
    expect(p.ThreatTypes).toBe("");
    expect(p.DetectionMethods).toBe("");
  });
  it("an authored org-level allow shows the override, but no allow delivers a Malware verdict (clean at delivery, ZAP later)", () => {
    const p = P(render("defender_o365", lure("email_received", { action_result: "delivered", OrgLevelAction: "Allow", OrgLevelPolicy: "Tenant Allow/Block List" })));
    expect(p.DeliveryAction).toBe("Delivered");
    expect(p.ThreatTypes).not.toContain("Malware");
    expect(p.OrgLevelAction).toBe("Allow");
  });
});

describe("#17 Okta sees the egress, not a private address", () => {
  it("corporate sign-ins carry the company egress + the Corporate zone; external ones are outside every zone", () => {
    let corp = 0;
    for (const c of corpus().filter(x => x.ev.source === "okta")) {
      const l = mod("okta").fromTelemetry(c.ev, makeCtx(c.companyId));
      const client = l?.record.client as { ipAddress: string | null; zone: string } | undefined;
      if (!client?.ipAddress) continue;
      expect(client.ipAddress, c.ev.id).not.toMatch(/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/);
      const isEgress = client.ipAddress === egressIp(makeCtx(c.companyId));
      expect(client.zone, c.ev.id).toBe(isEgress ? "Corporate HQ" : "null");
      if (isEgress) corp++;
    }
    expect(corp).toBeGreaterThan(0);
  });
});
