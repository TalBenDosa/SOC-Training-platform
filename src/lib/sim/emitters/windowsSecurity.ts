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
import type { TelemetryEvent, Severity, EventType, ExpectedVerdict } from "../types";
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
  srcIp?: string;               // remote source; omit for a host-local event (service logon, 4672/4673)
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
      "winlog.event_data.IpAddress": o.srcIp ?? "-",
      "winlog.event_data.IpPort": o.srcPort ?? "0",
      "winlog.event_data.ProcessName": "-",
      "event.code": "4625",
      "event.action": "logon-failed",
      "event.outcome": "failure",
      ...(o.srcIp ? { "source.ip": o.srcIp } : {}),
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
  lmPackage?: string;           // LmPackageName (e.g. "NTLM V2") — an NTLM-logon tell
  keyLength?: string;           // KeyLength (e.g. "0" for NTLM)
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
      ...(o.lmPackage ? { "winlog.event_data.LmPackageName": o.lmPackage } : {}),
      ...(o.keyLength ? { "winlog.event_data.KeyLength": o.keyLength } : {}),
      "winlog.event_data.WorkstationName": o.workstation ?? "WORKSTATION",
      "winlog.event_data.IpAddress": o.srcIp ?? "-",
      "winlog.event_data.IpPort": o.srcPort ?? "0",
      "winlog.event_data.ProcessName": o.processName ?? "-",
      "event.code": "4624",
      "event.action": "logged-in",
      "event.outcome": "success",
      ...(o.srcIp ? { "source.ip": o.srcIp } : {}),
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
      "winlog.event_data.IpAddress": o.srcIp ?? "-",
      "winlog.event_data.ShareName": o.shareName,
      ...(o.shareLocalPath ? { "winlog.event_data.ShareLocalPath": o.shareLocalPath } : {}),
      "winlog.event_data.AccessMask": "0x1",
      "winlog.event_data.AccessList": "%%4416",
      "event.code": "5140",
      "event.action": "share-accessed",
      "event.outcome": "success",
      ...(o.srcIp ? { "source.ip": o.srcIp } : {}),
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
      ...(o.srcIp ? { "source.ip": o.srcIp } : {}),
      "user.name": o.targetUser,
      "user.domain": nb,
    },
  };
}

// ── 4672 — special privileges assigned to a new logon ─────────────────────────────────
const ADMIN_PRIVS = "SeSecurityPrivilege\n\t\t\tSeBackupPrivilege\n\t\t\tSeRestorePrivilege\n\t\t\tSeTakeOwnershipPrivilege\n\t\t\tSeDebugPrivilege\n\t\t\tSeTcbPrivilege";
export interface WinSpecialPrivsOpts extends WinCtx {
  logonId?: string;
  privilegeList?: string;
  eventType?: EventType;           // default privilege_escalation
  eventAction?: string;            // default "logged-in-special"
  recordId?: string;
}
export function winSpecialPrivileges(o: WinSpecialPrivsOpts): TelemetryEvent {
  const nb = realm(o);
  return {
    id: o.id, ts: o.ts, source: "ad", vendor: VENDOR, event_type: o.eventType ?? "privilege_escalation",
    severity: o.severity ?? "medium", hostname: o.host, src_ip: o.srcIp, user_email: emailOf(o),
    mitre_technique: o.mitre, mitre_tactic: o.tactic, geo: o.geo, incident_id: o.incidentId,
    description: o.description ?? `4672 — special privileges assigned to ${o.targetUser} on ${o.host}`,
    raw: {
      "winlog.event_id": "4672",
      "winlog.channel": "Security",
      "winlog.computer_name": fqdnOf(o),
      "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
      ...(o.recordId ? { "winlog.record_id": o.recordId } : {}),
      "winlog.event_data.SubjectUserSid": o.targetSid ?? NO_SID,
      "winlog.event_data.SubjectUserName": o.targetUser,
      "winlog.event_data.SubjectDomainName": nb,
      ...(o.logonId ? { "winlog.event_data.SubjectLogonId": o.logonId } : {}),
      "winlog.event_data.PrivilegeList": o.privilegeList ?? ADMIN_PRIVS,
      "event.code": "4672",
      "event.action": o.eventAction ?? "logged-in-special",
      "event.outcome": "success",
      "user.name": o.targetUser,
      "user.domain": nb,
    },
  };
}

// ── 4673 — a privileged service was called (sensitive-privilege use) ──────────────────
export interface WinSensitivePrivUseOpts extends WinCtx {
  logonId?: string;
  privilegeUsed?: string;          // e.g. "SeImpersonatePrivilege"
  processName: string;             // full path of the calling process
  processId?: string;              // hex
  service?: string;
  recordId?: string;
}
export function winSensitivePrivUse(o: WinSensitivePrivUseOpts): TelemetryEvent {
  const nb = realm(o);
  return {
    id: o.id, ts: o.ts, source: "ad", vendor: VENDOR, event_type: "privileged_operation",
    severity: o.severity ?? "high", hostname: o.host, src_ip: o.srcIp, user_email: emailOf(o),
    mitre_technique: o.mitre, mitre_tactic: o.tactic, incident_id: o.incidentId,
    description: o.description ?? `4673 — ${o.privilegeUsed ?? "SeImpersonatePrivilege"} used by ${o.processName} on ${o.host}`,
    raw: {
      "winlog.event_id": "4673",
      "winlog.channel": "Security",
      "winlog.computer_name": fqdnOf(o),
      "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
      ...(o.recordId ? { "winlog.record_id": o.recordId } : {}),
      "winlog.event_data.SubjectUserSid": o.targetSid ?? NO_SID,
      "winlog.event_data.SubjectUserName": o.targetUser,
      "winlog.event_data.SubjectDomainName": nb,
      ...(o.logonId ? { "winlog.event_data.SubjectLogonId": o.logonId } : {}),
      "winlog.event_data.ObjectServer": "Security",
      "winlog.event_data.Service": o.service ?? "-",
      "winlog.event_data.PrivilegeList": o.privilegeUsed ?? "SeImpersonatePrivilege",
      ...(o.processId ? { "winlog.event_data.ProcessId": o.processId } : {}),
      "winlog.event_data.ProcessName": o.processName,
      "event.code": "4673",
      "event.action": "sensitive-privilege-use",
      "event.outcome": "success",
      "user.name": o.targetUser,
      "user.domain": nb,
    },
  };
}

// ── 7045 — a new service was installed (SCM; the PsExec / remote-service pattern) ──────
export interface WinServiceInstallOpts extends WinCtx {
  serviceName: string;
  imagePath: string;
  accountName?: string;            // default LocalSystem
  serviceType?: string;            // default "user mode service"
  startType?: string;              // default "auto start"
  recordId?: string;
}
export function winServiceInstall(o: WinServiceInstallOpts): TelemetryEvent {
  return {
    id: o.id, ts: o.ts, source: "ad", vendor: VENDOR, event_type: "service_install",
    severity: o.severity ?? "high", hostname: o.host, src_ip: o.srcIp, user_email: emailOf(o),
    mitre_technique: o.mitre, mitre_tactic: o.tactic, incident_id: o.incidentId,
    description: o.description ?? `7045 — service ${o.serviceName} installed on ${o.host} (${o.imagePath})`,
    raw: {
      "winlog.event_id": "7045",
      "winlog.channel": "System",
      "winlog.computer_name": fqdnOf(o),
      "winlog.provider_name": "Service Control Manager",
      ...(o.recordId ? { "winlog.record_id": o.recordId } : {}),
      "winlog.event_data.AccountName": o.accountName ?? "LocalSystem",
      "winlog.event_data.ServiceName": o.serviceName,
      "winlog.event_data.ImagePath": o.imagePath,
      "winlog.event_data.ServiceType": o.serviceType ?? "user mode service",
      "winlog.event_data.StartType": o.startType ?? "auto start",
      "event.code": "7045",
      "event.action": "service-installed",
      "event.outcome": "success",
    },
  };
}

// ── 4688 — a new process was created (Windows Security process-creation auditing) ──────
export interface WinProcessCreateOpts extends WinCtx {
  processName: string;
  processPath: string;
  cmdline: string;
  parentPath: string;
  pid?: number;
  subjectUser?: string;            // the creating principal (e.g. "SRV-FILE-03$")
  subjectSid?: string;             // default S-1-5-18 (SYSTEM)
  runAsUser?: string;              // the process token owner (process.user), default subjectUser
  integrity?: "low" | "medium" | "high" | "system";
  tokenElevation?: string;         // %%1936 (full) / %%1937 / %%1938
  eventType?: EventType;           // override (default process_create)
  recordId?: string;
}
const MAND_LABEL: Record<string, string> = { low: "S-1-16-4096", medium: "S-1-16-8192", high: "S-1-16-12288", system: "S-1-16-16384" };
export function winProcessCreate(o: WinProcessCreateOpts): TelemetryEvent {
  const nb = realm(o);
  const pid = o.pid ?? 4096;
  const subj = o.subjectUser ?? `${o.host}$`;
  const runAs = o.runAsUser ?? "NT AUTHORITY\SYSTEM";
  const integrity = o.integrity ?? "system";
  return {
    id: o.id, ts: o.ts, source: "ad", vendor: VENDOR, event_type: o.eventType ?? "process_create",
    severity: o.severity ?? "high", hostname: o.host, src_ip: o.srcIp, user_email: emailOf(o),
    mitre_technique: o.mitre, mitre_tactic: o.tactic, incident_id: o.incidentId,
    process: { pid, name: o.processName, path: o.processPath, cmdline: o.cmdline, parent_name: o.parentPath.split(/[\/]/).pop(), user: runAs },
    description: o.description ?? `4688 — ${o.processName} created on ${o.host}`,
    raw: {
      "winlog.event_id": "4688",
      "winlog.channel": "Security",
      "winlog.computer_name": fqdnOf(o),
      "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
      ...(o.recordId ? { "winlog.record_id": o.recordId } : {}),
      "winlog.event_data.SubjectUserSid": o.subjectSid ?? "S-1-5-18",
      "winlog.event_data.SubjectUserName": subj,
      "winlog.event_data.SubjectDomainName": nb,
      "winlog.event_data.SubjectLogonId": "0x3E7",
      "winlog.event_data.NewProcessId": `0x${pid.toString(16)}`,
      "winlog.event_data.NewProcessName": o.processPath,
      "winlog.event_data.CommandLine": o.cmdline,
      "winlog.event_data.ParentProcessName": o.parentPath,
      "winlog.event_data.TokenElevationType": o.tokenElevation ?? "%%1936",
      "winlog.event_data.MandatoryLabel": MAND_LABEL[integrity],
      "event.code": "4688",
      "event.action": "created-process",
      "event.outcome": "success",
      "user.name": subj,
      "user.domain": nb,
    },
  };
}

// ── 4662 — an operation was performed on a directory-service object ───────────────────
// The DACL-audited AD object read/write (DCSync source object, AD FS DKM key, …). The
// acting principal is the subject; there is no target user, so `targetUser` carries the
// subject account name.
export interface WinDirectoryAccessOpts extends WinCtx {
  subjectSid?: string;
  subjectLogonId?: string;
  objectServer?: string;        // default "DS"
  operationType?: string;       // default "Object Access"
  objectType: string;           // schema GUID / class
  objectName: string;           // the DN of the object
  accessList?: string;          // e.g. "%%7688" (Read Property)
  accessMask?: string;          // e.g. "0x10"
  properties?: string;          // the specific attribute(s) touched
  recordId?: string;
}
export function winDirectoryAccess(o: WinDirectoryAccessOpts): TelemetryEvent {
  const nb = realm(o);
  return {
    id: o.id, ts: o.ts, source: "ad", vendor: VENDOR, event_type: "file_access",
    severity: o.severity ?? "high", hostname: o.host, src_ip: o.srcIp, user_email: emailOf(o),
    mitre_technique: o.mitre, mitre_tactic: o.tactic, geo: o.geo, incident_id: o.incidentId,
    description: o.description ?? `4662 — directory-service object accessed on ${o.host} by ${o.targetUser}`,
    raw: {
      "winlog.event_id": "4662",
      "winlog.channel": "Security",
      "winlog.computer_name": fqdnOf(o),
      "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
      ...(o.recordId ? { "winlog.record_id": o.recordId } : {}),
      "winlog.event_data.SubjectUserSid": o.subjectSid ?? NO_SID,
      "winlog.event_data.SubjectUserName": o.targetUser,
      "winlog.event_data.SubjectDomainName": nb,
      ...(o.subjectLogonId ? { "winlog.event_data.SubjectLogonId": o.subjectLogonId } : {}),
      "winlog.event_data.ObjectServer": o.objectServer ?? "DS",
      "winlog.event_data.OperationType": o.operationType ?? "Object Access",
      "winlog.event_data.ObjectType": o.objectType,
      "winlog.event_data.ObjectName": o.objectName,
      ...(o.accessList ? { "winlog.event_data.AccessList": o.accessList } : {}),
      ...(o.accessMask ? { "winlog.event_data.AccessMask": o.accessMask } : {}),
      ...(o.properties ? { "winlog.event_data.Properties": o.properties } : {}),
      "event.code": "4662",
      "event.action": "directory-service-object-accessed",
      "event.outcome": "success",
      ...(o.srcIp ? { "source.ip": o.srcIp } : {}),
      "user.name": o.targetUser,
      "user.domain": nb,
    },
  };
}

// ── 5058 — key file operation (CNG/private-key read/export) ───────────────────────────
export interface WinKeyFileOpOpts extends WinCtx {
  subjectSid?: string;
  subjectLogonId?: string;
  operation?: string;           // e.g. "Read persisted key from file."
  keyName: string;              // KeyName
  keyType?: string;             // e.g. "Machine key."
  providerName?: string;        // e.g. "Microsoft Software Key Storage Provider"
  algorithmName?: string;       // e.g. "RSA"
  returnCode?: string;          // e.g. "0x0"
  keyFilePath?: string;
  exportedSha256?: string;
  recordId?: string;
}
export function winKeyFileOp(o: WinKeyFileOpOpts): TelemetryEvent {
  const nb = realm(o);
  return {
    id: o.id, ts: o.ts, source: "ad", vendor: VENDOR, event_type: "file_access",
    severity: o.severity ?? "critical", hostname: o.host, src_ip: o.srcIp, user_email: emailOf(o),
    mitre_technique: o.mitre, mitre_tactic: o.tactic, geo: o.geo, incident_id: o.incidentId,
    ...(o.keyFilePath ? { file: { name: o.keyFilePath.split("\\").pop() ?? o.keyFilePath, path: o.keyFilePath, ...(o.exportedSha256 ? { sha256: o.exportedSha256 } : {}) } } : {}),
    description: o.description ?? `5058 — key file operation on ${o.host} by ${o.targetUser}`,
    raw: {
      "winlog.event_id": "5058",
      "winlog.channel": "Security",
      "winlog.computer_name": fqdnOf(o),
      "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
      ...(o.recordId ? { "winlog.record_id": o.recordId } : {}),
      "winlog.event_data.SubjectUserSid": o.subjectSid ?? NO_SID,
      "winlog.event_data.SubjectUserName": o.targetUser,
      "winlog.event_data.SubjectDomainName": nb,
      ...(o.subjectLogonId ? { "winlog.event_data.SubjectLogonId": o.subjectLogonId } : {}),
      "winlog.event_data.Operation": o.operation ?? "Read persisted key from file.",
      "winlog.event_data.KeyName": o.keyName,
      "winlog.event_data.KeyType": o.keyType ?? "Machine key.",
      "winlog.event_data.ProviderName": o.providerName ?? "Microsoft Software Key Storage Provider",
      "winlog.event_data.AlgorithmName": o.algorithmName ?? "RSA",
      "winlog.event_data.ReturnCode": o.returnCode ?? "0x0",
      ...(o.keyFilePath ? { "winlog.event_data.KeyFilePath": o.keyFilePath } : {}),
      ...(o.exportedSha256 ? { "winlog.event_data.ExportedKeyFileSha256": o.exportedSha256, "file.hash.sha256": o.exportedSha256 } : {}),
      "event.code": "5058",
      "event.action": "key-file-operation",
      "event.outcome": "success",
      ...(o.srcIp ? { "source.ip": o.srcIp } : {}),
      "user.name": o.targetUser,
      "user.domain": nb,
    },
  };
}

// ── AD FS 1200 — a federation token was issued (AD FS/Admin audit) ────────────────────
// The attributable record every genuine federation token leaves on the AD FS server; its
// ABSENCE is the Golden-SAML tell. Distinct channel/provider from the Security log.
export interface AdfsTokenIssueOpts extends WinCtx {
  instanceId: string;           // correlates to the Entra federatedTokenId
  relyingParty: string;
  tokenType?: string;           // default the SAML 2.0 assertion URN
  authnMethods?: string;        // AuthnMethodsReferences
  issuerUri: string;
  clientIp?: string;
  resultStatus?: string;        // default "Success"
  recordId?: string;
  expectedVerdict?: ExpectedVerdict;
  fpExplanation?: string;
}
export function adfsTokenIssue(o: AdfsTokenIssueOpts): TelemetryEvent {
  const nb = realm(o);
  return {
    id: o.id, ts: o.ts, source: "ad", vendor: VENDOR, event_type: "auth_success",
    severity: o.severity ?? "informational", hostname: o.host, src_ip: o.srcIp ?? o.clientIp, user_email: emailOf(o),
    mitre_technique: o.mitre, mitre_tactic: o.tactic, geo: o.geo, incident_id: o.incidentId,
    expected_verdict: o.expectedVerdict, ...(o.fpExplanation ? { fp_explanation: o.fpExplanation } : {}),
    authentication: { method: "Federation", result: "success" },
    description: o.description ?? `AD FS 1200 — token issued for ${o.targetUser} to ${o.relyingParty} on ${o.host}`,
    raw: {
      "winlog.event_id": "1200",
      "winlog.channel": "AD FS/Admin",
      "winlog.provider_name": "AD FS Auditing",
      "winlog.computer_name": fqdnOf(o),
      ...(o.recordId ? { "winlog.record_id": o.recordId } : {}),
      "winlog.event_data.InstanceId": o.instanceId,
      "winlog.event_data.RelyingParty": o.relyingParty,
      "winlog.event_data.TokenType": o.tokenType ?? "urn:oasis:names:tc:SAML:2.0:assertion",
      "winlog.event_data.UserId": `${nb}\\${o.targetUser}`,
      ...(o.authnMethods ? { "winlog.event_data.AuthnMethodsReferences": o.authnMethods } : {}),
      "winlog.event_data.IssuerUri": o.issuerUri,
      ...(o.clientIp ? { "winlog.event_data.ClientIpAddress": o.clientIp } : {}),
      "winlog.event_data.ResultStatus": o.resultStatus ?? "Success",
      "event.code": "1200",
      "event.action": "adfs-token-issued",
      "event.outcome": "success",
      ...(o.clientIp ? { "source.ip": o.clientIp } : {}),
      "user.name": o.targetUser,
      "user.domain": nb,
    },
  };
}
