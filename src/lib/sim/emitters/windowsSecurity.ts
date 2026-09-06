/**
 * Windows Security event-log EMITTERS (the microsoft-active-directory vendor).
 *
 * The AD / identity half of the estate — the Security event log a domain controller or
 * a member server writes: 4625 failed logon, 4624 successful logon, 5140 share access,
 * 4663 object access. These are the events the brute-force / lateral-movement scenarios
 * live in. Same contract as the endpoint emitters: a typed call renders a complete
 * TelemetryEvent whose raw block uses only registry-valid fields (the winlog. /
 * winlog.event_data. prefixes + the shared ECS fields), with the domain drawn from the
 * company fabric. These are control-plane events (source:"ad"), so they carry no process.
 */
import type { TelemetryEvent, Severity } from "../types";
import { assetsFor } from "../fabric";

const VENDOR = "Windows Security";
const NO_SID = "S-1-0-0";

interface WinCtx {
  id: string;
  ts: string;
  companyId?: string;
  host: string;                 // the server that logged the event (its short name)
  fqdn?: string;                // computer_name in the raw; defaults host.<domain>
  targetUser: string;          // the account (sam)
  targetSid?: string;
  /** override the derived mailbox; null = no mailbox (a 0xC0000064 no-such-user 4625) */
  userEmail?: string | null;
  srcIp: string;
  domain?: string;              // NetBIOS realm; defaults from the fabric
  geo?: { country?: string; city?: string; latitude?: number; longitude?: number };
  mitre?: string;
  tactic?: string;
  severity?: Severity;
  incidentId?: string;
  description?: string;
}
function realm(c: WinCtx): string {
  return (c.domain ?? assetsFor(c.companyId)?.netbios ?? "WORKGROUP").toUpperCase();
}
function fqdnOf(c: WinCtx): string {
  return c.fqdn ?? `${c.host}.${assetsFor(c.companyId)?.domain ?? "local"}`;
}
function emailOf(c: WinCtx): string | undefined {
  if (c.userEmail !== undefined) return c.userEmail ?? undefined;
  const d = assetsFor(c.companyId)?.domain;
  return d ? `${c.targetUser}@${d}` : undefined;
}

// ── 4625 — an account failed to log on ───────────────────────────────────────────────
export interface WinFailedLogonOpts extends WinCtx {
  subStatus: string;            // 0xC0000064 (no such user) | 0xC000006A (bad password) …
  logonType?: number;           // 3 network, 10 RemoteInteractive …
  authPackage?: string;         // "NTLM" | "Kerberos" | "Negotiate"
  workstation?: string;
  srcPort?: string;
  recordId?: string;
}
export function winFailedLogon(o: WinFailedLogonOpts): TelemetryEvent {
  const nb = realm(o);
  const logonType = o.logonType ?? 3;
  const pkg = o.authPackage ?? "NTLM";
  return {
    id: o.id, ts: o.ts, source: "ad", vendor: VENDOR, event_type: "auth_failure",
    severity: o.severity ?? "medium", hostname: o.host, src_ip: o.srcIp, user_email: emailOf(o),
    mitre_technique: o.mitre, mitre_tactic: o.tactic, geo: o.geo, incident_id: o.incidentId,
    authentication: { method: pkg, result: "failure", logon_type: logonType },
    description: o.description ?? `4625 — logon failure for ${o.targetUser} on ${o.host} from ${o.srcIp}`,
    raw: {
      "winlog.event_id": "4625",
      "winlog.channel": "Security",
      "winlog.computer_name": fqdnOf(o),
      "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
      ...(o.recordId ? { "winlog.record_id": o.recordId } : {}),
      "winlog.event_data.SubjectUserSid": NO_SID,
      "winlog.event_data.SubjectUserName": "-",
      "winlog.event_data.SubjectDomainName": "-",
      "winlog.event_data.TargetUserSid": NO_SID,
      "winlog.event_data.TargetUserName": o.targetUser,
      "winlog.event_data.TargetDomainName": nb,
      "winlog.event_data.LogonType": String(logonType),
      "winlog.event_data.Status": "0xC000006D",
      "winlog.event_data.SubStatus": o.subStatus,
      "winlog.event_data.FailureReason": "%%2313",
      "winlog.event_data.LogonProcessName": "NtLmSsp ",
      "winlog.event_data.AuthenticationPackageName": pkg,
      "winlog.event_data.WorkstationName": o.workstation ?? "WORKSTATION",
      "winlog.event_data.IpAddress": o.srcIp,
      "winlog.event_data.IpPort": o.srcPort ?? "0",
      "winlog.event_data.ProcessName": "-",
      "event.code": "4625",
      "event.action": "logon-failed",
      "event.outcome": "failure",
      "source.ip": o.srcIp,
      "user.name": o.targetUser,
      "user.domain": nb,
    },
  };
}

// ── 4624 — an account was successfully logged on ─────────────────────────────────────
export interface WinLogonOpts extends WinCtx {
  logonType?: number;
  authPackage?: string;
  workstation?: string;
  logonId?: string;
  srcPort?: string;
  recordId?: string;
  logonProcess?: string;        // "NtLmSsp " | "User32 " | "Kerberos"
  subjectSid?: string;          // the caller (e.g. SRV$ for a RemoteInteractive)
  subjectUser?: string;
  processName?: string;
}
export function winLogon(o: WinLogonOpts): TelemetryEvent {
  const nb = realm(o);
  const logonType = o.logonType ?? 3;
  const pkg = o.authPackage ?? "NTLM";
  return {
    id: o.id, ts: o.ts, source: "ad", vendor: VENDOR, event_type: "auth_success",
    severity: o.severity ?? "high", hostname: o.host, src_ip: o.srcIp, user_email: emailOf(o),
    mitre_technique: o.mitre, mitre_tactic: o.tactic, geo: o.geo, incident_id: o.incidentId,
    authentication: { method: pkg, result: "success", logon_type: logonType },
    description: o.description ?? `4624 — successful logon for ${o.targetUser} on ${o.host} from ${o.srcIp}`,
    raw: {
      "winlog.event_id": "4624",
      "winlog.channel": "Security",
      "winlog.computer_name": fqdnOf(o),
      "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
      ...(o.recordId ? { "winlog.record_id": o.recordId } : {}),
      "winlog.event_data.SubjectUserSid": o.subjectSid ?? NO_SID,
      "winlog.event_data.SubjectUserName": o.subjectUser ?? "-",
      "winlog.event_data.SubjectDomainName": o.subjectUser ? nb : "-",
      "winlog.event_data.TargetUserSid": o.targetSid ?? NO_SID,
      "winlog.event_data.TargetUserName": o.targetUser,
      "winlog.event_data.TargetDomainName": nb,
      ...(o.logonId ? { "winlog.event_data.TargetLogonId": o.logonId } : {}),
      "winlog.event_data.LogonType": String(logonType),
      "winlog.event_data.LogonProcessName": o.logonProcess ?? "NtLmSsp ",
      "winlog.event_data.AuthenticationPackageName": pkg,
      "winlog.event_data.WorkstationName": o.workstation ?? "WORKSTATION",
      "winlog.event_data.IpAddress": o.srcIp,
      "winlog.event_data.IpPort": o.srcPort ?? "0",
      "winlog.event_data.ProcessName": o.processName ?? "-",
      "event.code": "4624",
      "event.action": "logged-in",
      "event.outcome": "success",
      "source.ip": o.srcIp,
      "user.name": o.targetUser,
      "user.domain": nb,
    },
  };
}

// ── 5140 — a network share object was accessed ───────────────────────────────────────
export interface WinShareAccessOpts extends WinCtx {
  shareName: string;            // \\*\HR-Confidential
  shareLocalPath?: string;
  subjectLogonId?: string;
  recordId?: string;
}
export function winShareAccess(o: WinShareAccessOpts): TelemetryEvent {
  const nb = realm(o);
  return {
    id: o.id, ts: o.ts, source: "ad", vendor: VENDOR, event_type: "file_access",
    severity: o.severity ?? "medium", hostname: o.host, src_ip: o.srcIp, user_email: emailOf(o),
    mitre_technique: o.mitre, mitre_tactic: o.tactic, incident_id: o.incidentId,
    description: o.description ?? `5140 — ${o.targetUser} connected to ${o.shareName} on ${o.host}`,
    raw: {
      "winlog.event_id": "5140",
      "winlog.channel": "Security",
      "winlog.computer_name": fqdnOf(o),
      "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
      ...(o.recordId ? { "winlog.record_id": o.recordId } : {}),
      "winlog.event_data.SubjectUserSid": o.targetSid ?? NO_SID,
      "winlog.event_data.SubjectUserName": o.targetUser,
      "winlog.event_data.SubjectDomainName": nb,
      ...(o.subjectLogonId ? { "winlog.event_data.SubjectLogonId": o.subjectLogonId } : {}),
      "winlog.event_data.ObjectType": "File",
      "winlog.event_data.IpAddress": o.srcIp,
      "winlog.event_data.ShareName": o.shareName,
      ...(o.shareLocalPath ? { "winlog.event_data.ShareLocalPath": o.shareLocalPath } : {}),
      "winlog.event_data.AccessMask": "0x1",
      "winlog.event_data.AccessList": "%%4416",
      "event.code": "5140",
      "event.action": "share-accessed",
      "event.outcome": "success",
      "source.ip": o.srcIp,
      "user.name": o.targetUser,
      "user.domain": nb,
    },
  };
}

// ── 4663 — an attempt was made to access an object (a file read) ──────────────────────
export interface WinObjectAccessOpts extends WinCtx {
  objectName: string;           // full path of the file
  fileName?: string;
  subjectLogonId?: string;
  accessMask?: string;
  processName?: string;
  recordId?: string;
}
export function winObjectAccess(o: WinObjectAccessOpts): TelemetryEvent {
  const nb = realm(o);
  const name = o.fileName ?? (o.objectName.split(/[\\/]/).pop() ?? o.objectName);
  return {
    id: o.id, ts: o.ts, source: "ad", vendor: VENDOR, event_type: "file_access",
    severity: o.severity ?? "medium", hostname: o.host, src_ip: o.srcIp, user_email: emailOf(o),
    mitre_technique: o.mitre, mitre_tactic: o.tactic, incident_id: o.incidentId,
    file: { name, path: o.objectName },
    description: o.description ?? `4663 — ${o.targetUser} read ${name} on ${o.host}`,
    raw: {
      "winlog.event_id": "4663",
      "winlog.channel": "Security",
      "winlog.computer_name": fqdnOf(o),
      "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
      ...(o.recordId ? { "winlog.record_id": o.recordId } : {}),
      "winlog.event_data.SubjectUserSid": o.targetSid ?? NO_SID,
      "winlog.event_data.SubjectUserName": o.targetUser,
      "winlog.event_data.SubjectDomainName": nb,
      ...(o.subjectLogonId ? { "winlog.event_data.SubjectLogonId": o.subjectLogonId } : {}),
      "winlog.event_data.ObjectServer": "Security",
      "winlog.event_data.ObjectType": "File",
      "winlog.event_data.ObjectName": o.objectName,
      "winlog.event_data.AccessMask": o.accessMask ?? "0x1",
      "winlog.event_data.AccessList": "%%4416",
      "winlog.event_data.ProcessName": o.processName ?? "System",
      "event.code": "4663",
      "event.action": "file-accessed",
      "event.outcome": "success",
      "source.ip": o.srcIp,
      "user.name": o.targetUser,
      "user.domain": nb,
    },
  };
}
