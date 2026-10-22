/**
 * Extra vendor-log EMITTERS used by the batch-6 scenario packs (scheduled-task-persistence,
 * windows-privesc-token, lateral-movement-pth, edge-vpn-cve-exploit, ...).
 *
 * Same contract as the other emitters in this folder: a typed call renders a complete
 * TelemetryEvent whose raw block uses only fields the named product really writes, so the
 * packs stay 100% emitter-authored (see scenario-packs/emitter-authored.test.ts). Kept in its
 * own module so the shared emitters used by every other scenario are untouched.
 */
import type { TelemetryEvent, Severity } from "../types";
import { assetsFor } from "../fabric";
import { domainSidFor } from "./windowsSecurity";

const WINSEC = "Windows Security";
const SYSMON = "Microsoft Sysmon";

function fqdn(companyId: string | undefined, host: string, override?: string): string {
  return override ?? `${host}.${assetsFor(companyId)?.domain ?? "local"}`;
}
function netbios(companyId: string | undefined, override?: string): string {
  return (override ?? assetsFor(companyId)?.netbios ?? "WORKGROUP").toUpperCase();
}

interface WinBase {
  id: string;
  ts: string;
  companyId?: string;
  /** the machine that wrote the event (short name) */
  host: string;
  /** the account the event is about (sam) */
  user: string;
  userEmail?: string;
  userSid?: string;
  domain?: string;
  incidentId?: string;
  severity?: Severity;
  mitre?: string;
  tactic?: string;
  description?: string;
}

// ── Security 4698 — a scheduled task was created ─────────────────────────────────────
export interface WinTaskCreatedOpts extends WinBase {
  taskName: string;              // "\NetFixOptimizer"
  taskContent: string;           // the task XML schtasks stores
  subjectLogonId: string;
}
export function winTaskCreated(o: WinTaskCreatedOpts): TelemetryEvent {
  const nb = netbios(o.companyId, o.domain);
  return {
    id: o.id, ts: o.ts, source: "windows_security", vendor: WINSEC, event_type: "scheduled_task",
    severity: o.severity ?? "medium", hostname: o.host, user_email: o.userEmail,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, incident_id: o.incidentId,
    description: o.description ?? `4698 — scheduled task ${o.taskName} created by ${o.user} on ${o.host}`,
    raw: {
      "winlog.event_id": "4698",
      "winlog.channel": "Security",
      "winlog.computer_name": fqdn(o.companyId, o.host),
      "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
      "winlog.event_data.SubjectUserSid": o.userSid ?? domainSidFor(o.companyId, o.user),
      "winlog.event_data.SubjectUserName": o.user,
      "winlog.event_data.SubjectDomainName": nb,
      "winlog.event_data.SubjectLogonId": o.subjectLogonId,
      "winlog.event_data.TaskName": o.taskName,
      "winlog.event_data.TaskContent": o.taskContent,
      "event.code": "4698",
      "event.action": "scheduled-task-created",
      "event.outcome": "success",
      "user.name": o.user,
      "user.domain": nb,
    },
  };
}

// ── Sysmon 17 — a named pipe was created ───────────────────────────────────────────────
// (PrintSpoofer / potato tools create the pipe the SYSTEM spooler is then coerced into
// connecting to; the shared sysmon emitter only covers Event 18, the connect side.)
export interface SysmonPipeCreatedOpts {
  id: string;
  ts: string;
  companyId?: string;
  host: string;
  userEmail?: string;
  /** the account the creating process runs as (DOMAIN\user) */
  runAsUser: string;
  image: string;                   // the creating process (full path)
  pid: number;
  processGuid?: string;
  pipeName: string;                // as Sysmon prints it: "\WEB-APP-04\pipe\spoolss"
  incidentId?: string;
  severity?: Severity;
  mitre?: string;
  tactic?: string;
  description?: string;
}
export function sysmonPipeCreated(o: SysmonPipeCreatedOpts): TelemetryEvent {
  const name = o.image.split(/[\\/]/).pop() ?? o.image;
  return {
    id: o.id, ts: o.ts, source: "sysmon", vendor: SYSMON, event_type: "file_create",
    severity: o.severity ?? "high", hostname: o.host, user_email: o.userEmail,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, incident_id: o.incidentId,
    process: { pid: o.pid, name, path: o.image, user: o.runAsUser },
    file: { name: o.pipeName.split("\\").pop() ?? o.pipeName, path: `\\\\.\\pipe${o.pipeName}` },
    description: o.description ?? `${name} created the named pipe ${o.pipeName} on ${o.host} (Sysmon 17)`,
    raw: {
      "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
      "winlog.provider_name": "Microsoft-Windows-Sysmon",
      "winlog.computer_name": o.host,
      "winlog.event_id": "17",
      "winlog.event_data.EventType": "CreatePipe",
      ...(o.processGuid ? { "winlog.event_data.ProcessGuid": o.processGuid } : {}),
      "winlog.event_data.ProcessId": String(o.pid),
      "winlog.event_data.PipeName": o.pipeName,
      "winlog.event_data.Image": o.image,
      "winlog.event_data.User": o.runAsUser,
      "event.code": "17",
      "event.category": "file",
      "event.action": "pipe-created",
      "host.name": o.host,
    },
  };
}
