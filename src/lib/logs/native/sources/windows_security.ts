/**
 * Microsoft Windows Security event log (+ System-log 7045) — native module
 * (card: docs/log-schemas/windows-security.md).
 *
 * Record: one EVTX event as the FLAT JSON the card standardises on — the System keys
 * we keep (`EventID` int, `Computer` FQDN, `TimeCreated` ISO-8601 UTC with 7 fractional
 * digits, `Channel`, `Provider`, `EventRecordID` int, `Keywords` hex string) followed
 * by every `EventData/Data` element under its exact Windows PascalCase name, in the
 * documented order, every EventData value a STRING exactly as the XML holds it
 * (`"LogonType": "3"`, `"Status": "0xc000006d"`). `%%NNNN` placeholders stay as-is.
 * `rawLine` = the rendered EVTX XML of the same event.
 *
 * The EventData is rebuilt per event id into the card's real shape (never a copy of the
 * authored `winlog.event_data.*` map): a 4740 puts the caller in `TargetDomainName`
 * (there is no `CallerComputerName` field), a 4769 drops `kerberos.*` normalisation,
 * etc. Evidence (user, SIDs, logon ids, IPs, ports, service name, encryption type,
 * status codes, privileges, group, process) is carried verbatim from the authored
 * `winlog.event_data.*` keys and structured fields; the remaining native fields are
 * filled with deterministic, per-entity values from `ctx` (same user → same SID, same
 * host → same domain SID, same logon session → same LogonId) so a re-homed org reads
 * natively and the story correlates across rows.
 *
 * Category-wide: besides Windows-Security-authored events, any onprem_ad event (source
 * "ad" / "windows_security") renders here — it is always Windows. An event whose id is
 * not a documented Security/System event (5140/5145/4663 share access, TerminalServices
 * 1149/21/23, TaskScheduler 201, PowerShell 4104, 4798 …) or that carries no resolvable
 * EventID (an MDI alert filed under "ad") returns null → it keeps the legacy view.
 */
import { accountSid, logonLuid } from "./_proc-identity";
import type { NativeSource, NativeLog, KindSchema, UseCase, NativeCtx } from "../types";
import type { TelemetryEvent } from "@/lib/sim/types";

// ── schema (card §3.2, documented field order) ────────────────────────────────
const SYS = ["EventID", "Computer", "TimeCreated", "Channel", "Provider", "EventRecordID", "Keywords"];
const k = (...ed: string[]): KindSchema => ({ required: [...SYS, ...ed], optional: ["KeywordsText"] });
const kOpt = (req: string[], opt: string[]): KindSchema => ({ required: [...SYS, ...req], optional: [...opt, "KeywordsText"] });

const LOGON_4624 = ["SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "TargetUserSid", "TargetUserName", "TargetDomainName", "TargetLogonId", "LogonType", "LogonProcessName", "AuthenticationPackageName", "WorkstationName", "LogonGuid", "TransmittedServices", "LmPackageName", "KeyLength", "ProcessId", "ProcessName", "IpAddress", "IpPort", "ImpersonationLevel", "RestrictedAdminMode", "TargetOutboundUserName", "TargetOutboundDomainName", "VirtualAccount", "TargetLinkedLogonId", "ElevatedToken"];
const ACCT_MGMT = ["TargetUserName", "TargetDomainName", "TargetSid", "SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "PrivilegeList", "SamAccountName", "DisplayName", "UserPrincipalName", "HomeDirectory", "HomePath", "ScriptPath", "ProfilePath", "UserWorkstations", "PasswordLastSet", "AccountExpires", "PrimaryGroupId", "AllowedToDelegateTo", "OldUacValue", "NewUacValue", "UserAccountControl", "UserParameters", "SidHistory", "LogonHours"];
const ACCT_STATUS = ["TargetUserName", "TargetDomainName", "TargetSid", "SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId"];
const GROUP_MEMBER = ["MemberName", "MemberSid", "TargetUserName", "TargetDomainName", "TargetSid", "SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "PrivilegeList"];
const KERB_2025 = ["AccountSupportedEncryptionTypes", "AccountAvailableKeys", "ServiceSupportedEncryptionTypes", "ServiceAvailableKeys", "DCSupportedEncryptionTypes", "DCAvailableKeys", "ClientAdvertizedEncryptionTypes", "SessionKeyEncryptionType"];

const kinds: Record<string, KindSchema> = {
  "4624": k(...LOGON_4624),
  "4625": k("SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "TargetUserSid", "TargetUserName", "TargetDomainName", "Status", "FailureReason", "SubStatus", "LogonType", "LogonProcessName", "AuthenticationPackageName", "WorkstationName", "TransmittedServices", "LmPackageName", "KeyLength", "ProcessId", "ProcessName", "IpAddress", "IpPort"),
  "4634": k("TargetUserSid", "TargetUserName", "TargetDomainName", "TargetLogonId", "LogonType"),
  "4648": k("SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "LogonGuid", "TargetUserName", "TargetDomainName", "TargetLogonGuid", "TargetServerName", "TargetInfo", "ProcessId", "ProcessName", "IpAddress", "IpPort"),
  "4672": k("SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "PrivilegeList"),
  "4688": k("SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "NewProcessId", "NewProcessName", "TokenElevationType", "ProcessId", "CommandLine", "TargetUserSid", "TargetUserName", "TargetDomainName", "TargetLogonId", "ParentProcessName", "MandatoryLabel"),
  "4697": k("SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "ServiceName", "ServiceFileName", "ServiceType", "ServiceStartType", "ServiceAccount"),
  // Account management
  "4720": k(...ACCT_MGMT),
  "4738": k("Dummy", ...ACCT_MGMT),
  "4722": k(...ACCT_STATUS), "4723": k(...ACCT_STATUS), "4724": k(...ACCT_STATUS),
  "4725": k(...ACCT_STATUS), "4726": k(...ACCT_STATUS), "4767": k(...ACCT_STATUS),
  // Group membership (global 4728/4729, local 4732/4733, universal 4756/4757)
  "4728": k(...GROUP_MEMBER), "4729": k(...GROUP_MEMBER), "4732": k(...GROUP_MEMBER),
  "4733": k(...GROUP_MEMBER), "4756": k(...GROUP_MEMBER), "4757": k(...GROUP_MEMBER),
  // Lockout (caller computer sits in TargetDomainName — card §3.2 note)
  "4740": k("TargetUserName", "TargetDomainName", "TargetSid", "SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId"),
  // Kerberos / NTLM on the DC
  "4768": kOpt(["TargetUserName", "TargetDomainName", "TargetSid", "ServiceName", "ServiceSid", "TicketOptions", "Status", "TicketEncryptionType", "PreAuthType", "IpAddress", "IpPort", "CertIssuerName", "CertSerialNumber", "CertThumbprint"], ["ResponseTicket", ...KERB_2025, "PreAuthEncryptionType"]),
  "4769": kOpt(["TargetUserName", "TargetDomainName", "ServiceName", "ServiceSid", "TicketOptions", "TicketEncryptionType", "IpAddress", "IpPort", "Status", "LogonGuid", "TransmittedServices"], ["RequestTicketHash", "ResponseTicketHash", ...KERB_2025]),
  "4771": k("TargetUserName", "TargetSid", "ServiceName", "TicketOptions", "Status", "PreAuthType", "IpAddress", "IpPort", "CertIssuerName", "CertSerialNumber", "CertThumbprint"),
  "4776": k("PackageName", "TargetUserName", "Workstation", "Status"),
  // Directory service
  "4662": k("SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "ObjectServer", "ObjectType", "ObjectName", "OperationType", "HandleId", "AccessList", "AccessMask", "Properties", "AdditionalInfo", "AdditionalInfo2"),
  "5136": k("OpCorrelationID", "AppCorrelationID", "SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "DSName", "DSType", "ObjectDN", "ObjectGUID", "ObjectClass", "AttributeLDAPDisplayName", "AttributeSyntaxOID", "AttributeValue", "OperationType"),
  // Log cleared (System-log twin 1102 lives on the Security channel, provider Eventlog)
  "1102": k("SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId"),
  // Service installed (System log, Service Control Manager)
  "7045": k("ServiceName", "ImagePath", "ServiceType", "StartType", "AccountName"),
};

export function kindOf(record: Record<string, unknown>): string | null {
  const id = record.EventID;
  if (id === undefined || id === null) return null;
  const kk = String(id);
  return kinds[kk] ? kk : null;
}

// ── helpers ──────────────────────────────────────────────────────────────────
const str = (v: unknown): string | undefined =>
  v === undefined || v === null || v === "" ? undefined : Array.isArray(v) ? (v.length ? v.map(String).join(", ") : undefined) : String(v);
const short = (h: string) => h.split(".")[0];
const isPrivate = (ip: string) => /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|::ffff:(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)|127\.|::1\b|fe80:)/i.test(ip);

/** One stable S-1-5-21 domain identifier per company. */
function domainId(ctx: NativeCtx): string {
  return [0, 1, 2].map(i => ctx.int(`${ctx.companyId}:winsec:domsid:${i}`, 1_000_000_000, 3_999_999_999)).join("-");
}
const SYSTEM_SIDS: Record<string, string> = { system: "S-1-5-18", "local service": "S-1-5-19", "network service": "S-1-5-20", "local system": "S-1-5-18" };
/** Stable domain SID for an account (well-known for SYSTEM / service identities). */
function userSid(ctx: NativeCtx, sam: string | undefined): string {
  if (!sam) return "S-1-0-0";
  const lc = sam.toLowerCase().replace(/\$$/, "");
  if (SYSTEM_SIDS[lc]) return SYSTEM_SIDS[lc];
  // The endpoint renderers' formula (one SID per user across EDR, Sysmon and the Security log).
  return accountSid(ctx, lc);
}
/** A well-known privileged-group SID by name, else a stable domain group SID. */
function groupSid(ctx: NativeCtx, name: string | undefined): string {
  const g = (name ?? "").toLowerCase();
  const RID: Record<string, string> = { "domain admins": "512", "domain users": "513", "domain guests": "514", "domain computers": "515", "domain controllers": "516", "enterprise admins": "519", "schema admins": "518", "group policy creator owners": "520", "administrators": "S-1-5-32-544", "account operators": "S-1-5-32-548", "backup operators": "S-1-5-32-551", "remote desktop users": "S-1-5-32-555" };
  const r = RID[g];
  if (r) return r.startsWith("S-1-5-32") ? r : `S-1-5-21-${domainId(ctx)}-${r}`;
  return `S-1-5-21-${domainId(ctx)}-${ctx.int(`${ctx.companyId}:winsec:grid:${g}`, 1200, 4999)}`;
}
/** A logon session id (hex LUID) — one per (host, account) so a story's session correlates. */
function logonId(ctx: NativeCtx, host: string, sam: string): string {
  const lc = sam.toLowerCase();
  if (lc === "system" || lc.endsWith("$")) return "0x3e7";
  // The endpoint renderers' session (an EDR row's LogonId equals this 4624's TargetLogonId).
  return `0x${logonLuid(ctx, host, lc, 0).toString(16).toUpperCase()}`;
}
function logonGuid(ctx: NativeCtx, host: string, sam: string): string {
  return ctx.uuid(`${ctx.companyId}:${host.toLowerCase()}:${sam.toLowerCase()}:logonguid`).toUpperCase();
}
const curly = (g: string) => (g.startsWith("{") ? g : `{${g}}`);
/** A client ephemeral source port (Windows dynamic range). */
const ephemeral = (ctx: NativeCtx, seed: string) => String(ctx.int(`${seed}:winsecport`, 49152, 65535));
/** TimeCreated: ISO-8601 UTC with 7 fractional digits, as the card keeps the SystemTime attribute. */
function timeCreated(ms: number): string {
  return new Date(ms).toISOString().replace(/\.(\d{3})Z$/, (_, x) => `.${x}0000Z`);
}

// ── conversion ────────────────────────────────────────────────────────────────
function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  const raw = ev.raw ?? {};
  const r = (key: string) => str(raw[key]);
  const ed = (name: string) => r(`winlog.event_data.${name}`);

  const id = r("winlog.event_id") ?? r("event.code");
  if (!id || !kinds[id]) return null;

  const timeMs = Date.parse(ev.ts);
  if (!Number.isFinite(timeMs)) return null;

  const netbios = ctx.netbios;
  const domain = ctx.domain;
  // The computer that wrote the record (FQDN).
  const hostName = ev.hostname ?? r("host.name") ?? r("winlog.computer_name");
  const hostShort = hostName ? short(hostName) : "DC01";
  const computer = r("winlog.computer_name") && r("winlog.computer_name")!.includes(".")
    ? r("winlog.computer_name")!
    : hostName && hostName.includes(".") ? hostName : `${hostShort}.${domain}`;

  const email = ev.user_email ?? ev.user?.email;
  // The account the event is ABOUT (target). Keep the authored form verbatim (evidence).
  const samOf = (v?: string) => (v && v.includes("\\") ? v.split("\\").pop() : v);
  const targetSam = ed("TargetUserName") ?? samOf(r("user.name")) ?? (email ? email.split("@")[0] : undefined);
  const targetDomain = ed("TargetDomainName") ?? r("user.domain") ?? netbios;

  const srcIp = ev.src_ip ?? r("source.ip") ?? ed("IpAddress");
  // On a DC Kerberos/directory event Windows logs the IPv4-mapped form; member servers log plain IPv4.
  const dcKerbIp = (): string | undefined => {
    const a = ed("IpAddress") ?? srcIp;
    if (!a) return undefined;
    return a.startsWith("::ffff:") || !/^\d{1,3}(\.\d{1,3}){3}$/.test(a) ? a : `::ffff:${a}`;
  };

  // The caller (Subject) — on a logon/session event the local computer account.
  const subjectSid = ed("SubjectUserSid") ?? "S-1-5-18";
  const subjectName = ed("SubjectUserName") ?? `${hostShort}$`;
  const subjectDomain = ed("SubjectDomainName") ?? netbios;
  const subjectLogonId = ed("SubjectLogonId") ?? "0x3e7";

  const keyw = (ok: boolean) => (ok ? "0x8020000000000000" : "0x8010000000000000");
  const recId = ed("EventRecordID") ?? r("winlog.record_id");
  const eventRecordID = recId && /^\d+$/.test(recId) ? Number(recId) : ctx.int(`${ctx.companyId}:${hostShort.toLowerCase()}:winsec:rec:${ev.id}`, 1_000_000, 90_000_000);

  let provider = r("winlog.provider_name") ?? "Microsoft-Windows-Security-Auditing";
  let channel = "Security";
  let keywords = keyw(true);
  let data: Record<string, string> = {};

  switch (id) {
    case "4624": {
      const lt = ed("LogonType") ?? str(raw["logon.type"]) ?? "3";
      const authPkg = ed("AuthenticationPackageName") ?? r("authentication.protocol") ?? (lt === "3" ? "NTLM" : "Negotiate");
      const network = lt === "3";
      const logonProc = ed("LogonProcessName") ?? (authPkg === "Kerberos" ? "Kerberos" : authPkg === "NTLM" ? "NtLmSsp " : network ? "Kerberos" : "User32 ");
      const interactive = lt === "2" || lt === "7" || lt === "10" || lt === "11";
      data = {
        SubjectUserSid: network ? (ed("SubjectUserSid") ?? "S-1-0-0") : subjectSid,
        SubjectUserName: network ? (ed("SubjectUserName") ?? "-") : subjectName,
        SubjectDomainName: network ? (ed("SubjectDomainName") ?? "-") : subjectDomain,
        SubjectLogonId: network ? (ed("SubjectLogonId") ?? "0x0") : subjectLogonId,
        TargetUserSid: ed("TargetUserSid") ?? userSid(ctx, targetSam),
        TargetUserName: targetSam ?? "-",
        TargetDomainName: targetDomain,
        TargetLogonId: ed("TargetLogonId") ?? logonId(ctx, hostShort, targetSam ?? "-"),
        LogonType: lt,
        LogonProcessName: logonProc,
        AuthenticationPackageName: authPkg,
        WorkstationName: ed("WorkstationName") ?? (interactive ? hostShort : "-"),
        LogonGuid: ed("LogonGuid") ?? (authPkg === "NTLM" ? "{00000000-0000-0000-0000-000000000000}" : curly(logonGuid(ctx, hostShort, targetSam ?? "-"))),
        TransmittedServices: ed("TransmittedServices") ?? "-",
        LmPackageName: ed("LmPackageName") ?? (authPkg === "NTLM" ? "NTLM V2" : "-"),
        KeyLength: ed("KeyLength") ?? (authPkg === "NTLM" ? "128" : "0"),
        ProcessId: ed("ProcessId") ?? (interactive ? "0x1f0" : "0x0"),
        ProcessName: ed("ProcessName") ?? (interactive ? "C:\\Windows\\System32\\svchost.exe" : "-"),
        IpAddress: ed("IpAddress") ?? srcIp ?? "-",
        IpPort: ed("IpPort") ?? (srcIp ? ephemeral(ctx, `${ev.id}:ip`) : "0"),
        ImpersonationLevel: ed("ImpersonationLevel") ?? "%%1833",
        RestrictedAdminMode: ed("RestrictedAdminMode") ?? "-",
        TargetOutboundUserName: ed("TargetOutboundUserName") ?? "-",
        TargetOutboundDomainName: ed("TargetOutboundDomainName") ?? "-",
        VirtualAccount: ed("VirtualAccount") ?? "%%1843",
        TargetLinkedLogonId: ed("TargetLinkedLogonId") ?? "0x0",
        ElevatedToken: ed("ElevatedToken") ?? "%%1843",
      };
      break;
    }
    case "4625": {
      keywords = keyw(false);
      const lt = ed("LogonType") ?? str(raw["logon.type"]) ?? "3";
      const authPkg = ed("AuthenticationPackageName") ?? r("authentication.protocol") ?? "NTLM";
      data = {
        SubjectUserSid: ed("SubjectUserSid") ?? "S-1-0-0",
        SubjectUserName: ed("SubjectUserName") ?? "-",
        SubjectDomainName: ed("SubjectDomainName") ?? "-",
        SubjectLogonId: ed("SubjectLogonId") ?? "0x0",
        TargetUserSid: "S-1-0-0",
        TargetUserName: targetSam ?? "-",
        TargetDomainName: targetDomain,
        Status: (ed("Status") ?? "0xC000006D").toLowerCase(),
        FailureReason: ed("FailureReason") ?? "%%2313",
        SubStatus: (ed("SubStatus") ?? "0xC000006A").toLowerCase(),
        LogonType: lt,
        LogonProcessName: ed("LogonProcessName") ?? "NtLmSsp ",
        AuthenticationPackageName: authPkg,
        WorkstationName: ed("WorkstationName") ?? "-",
        TransmittedServices: ed("TransmittedServices") ?? "-",
        LmPackageName: ed("LmPackageName") ?? "-",
        KeyLength: ed("KeyLength") ?? "0",
        ProcessId: ed("ProcessId") ?? "0x0",
        ProcessName: ed("ProcessName") ?? "-",
        IpAddress: ed("IpAddress") ?? srcIp ?? "-",
        IpPort: ed("IpPort") ?? (srcIp ? ephemeral(ctx, `${ev.id}:ip`) : "0"),
      };
      break;
    }
    case "4634": {
      data = {
        TargetUserSid: ed("TargetUserSid") ?? userSid(ctx, targetSam),
        TargetUserName: targetSam ?? "-",
        TargetDomainName: targetDomain,
        TargetLogonId: ed("TargetLogonId") ?? logonId(ctx, hostShort, targetSam ?? "-"),
        LogonType: ed("LogonType") ?? str(raw["logon.type"]) ?? "3",
      };
      break;
    }
    case "4648": {
      data = {
        SubjectUserSid: subjectSid, SubjectUserName: subjectName, SubjectDomainName: subjectDomain, SubjectLogonId: subjectLogonId,
        LogonGuid: ed("LogonGuid") ?? "{00000000-0000-0000-0000-000000000000}",
        TargetUserName: targetSam ?? "-",
        TargetDomainName: targetDomain,
        TargetLogonGuid: ed("TargetLogonGuid") ?? "{00000000-0000-0000-0000-000000000000}",
        TargetServerName: ed("TargetServerName") ?? r("destination.hostname") ?? "-",
        TargetInfo: ed("TargetInfo") ?? "-",
        ProcessId: ed("ProcessId") ?? "0x0",
        ProcessName: ed("ProcessName") ?? "-",
        IpAddress: ed("IpAddress") ?? srcIp ?? "-",
        IpPort: ed("IpPort") ?? (srcIp ? ephemeral(ctx, `${ev.id}:ip`) : "0"),
      };
      break;
    }
    case "4672": {
      const subj = targetSam ?? samOf(ed("SubjectUserName")) ?? "-";
      data = {
        SubjectUserSid: ed("SubjectUserSid") ?? userSid(ctx, subj),
        SubjectUserName: ed("SubjectUserName") ?? subj,
        SubjectDomainName: ed("SubjectDomainName") ?? (r("logon.type") === "5" || ed("SubjectDomainName") === "IIS APPPOOL" ? "NT AUTHORITY" : netbios),
        SubjectLogonId: ed("SubjectLogonId") ?? logonId(ctx, hostShort, subj),
        PrivilegeList: ed("PrivilegeList") ?? str(raw["privilege.names"]) ?? "SeSecurityPrivilege\n\t\t\tSeBackupPrivilege\n\t\t\tSeRestorePrivilege\n\t\t\tSeDebugPrivilege",
      };
      break;
    }
    case "4688": {
      const np = ev.process?.name ?? (ed("NewProcessName") ? ed("NewProcessName")!.split(/[\\/]/).pop() : undefined);
      const npPath = ed("NewProcessName") ?? ev.process?.path ?? (np ? `C:\\Windows\\System32\\${np}` : "-");
      const subj = targetSam ?? samOf(ed("SubjectUserName")) ?? "-";
      data = {
        SubjectUserSid: ed("SubjectUserSid") ?? userSid(ctx, subj),
        SubjectUserName: ed("SubjectUserName") ?? subj,
        SubjectDomainName: ed("SubjectDomainName") ?? netbios,
        SubjectLogonId: ed("SubjectLogonId") ?? logonId(ctx, hostShort, subj),
        NewProcessId: ed("NewProcessId") ?? (ev.process?.pid !== undefined ? `0x${ev.process.pid.toString(16)}` : "0x0"),
        NewProcessName: npPath,
        TokenElevationType: ed("TokenElevationType") ?? "%%1936",
        ProcessId: ed("ProcessId") ?? (ev.process?.parent_pid !== undefined ? `0x${ev.process.parent_pid.toString(16)}` : "0x0"),
        CommandLine: ed("CommandLine") ?? ev.process?.cmdline ?? "",
        TargetUserSid: ed("TargetUserSid") ?? "S-1-0-0",
        TargetUserName: ed("TargetUserName") === targetSam ? "-" : (ed("TargetUserName") ?? "-"),
        TargetDomainName: ed("TargetDomainName") === targetDomain && ed("NewProcessName") ? "-" : (ed("TargetDomainName") ?? "-"),
        TargetLogonId: ed("TargetLogonId") ?? "0x0",
        ParentProcessName: ed("ParentProcessName") ?? ev.process?.parent_name ?? r("process.parent.name") ?? "-",
        MandatoryLabel: ed("MandatoryLabel") ?? "S-1-16-8192",
      };
      break;
    }
    case "4697": {
      const subj = targetSam ?? samOf(ed("SubjectUserName")) ?? "-";
      data = {
        SubjectUserSid: ed("SubjectUserSid") ?? userSid(ctx, subj),
        SubjectUserName: ed("SubjectUserName") ?? subj,
        SubjectDomainName: ed("SubjectDomainName") ?? netbios,
        SubjectLogonId: ed("SubjectLogonId") ?? logonId(ctx, hostShort, subj),
        ServiceName: ed("ServiceName") ?? "-",
        ServiceFileName: ed("ServiceFileName") ?? "-",
        ServiceType: ed("ServiceType") ?? "0x10",
        ServiceStartType: ed("ServiceStartType") ?? "3",
        ServiceAccount: ed("ServiceAccount") ?? "LocalSystem",
      };
      break;
    }
    case "4720": case "4738": {
      const tgt = targetSam ?? ed("SamAccountName") ?? "-";
      const subj = samOf(ed("SubjectUserName")) ?? "-";
      const body: Record<string, string> = {
        TargetUserName: tgt,
        TargetDomainName: ed("TargetDomainName") ?? netbios,
        TargetSid: ed("TargetSid") ?? userSid(ctx, tgt),
        SubjectUserSid: ed("SubjectUserSid") ?? userSid(ctx, subj),
        SubjectUserName: ed("SubjectUserName") ?? subj,
        SubjectDomainName: ed("SubjectDomainName") ?? netbios,
        SubjectLogonId: ed("SubjectLogonId") ?? logonId(ctx, hostShort, subj),
        PrivilegeList: ed("PrivilegeList") ?? "-",
        SamAccountName: ed("SamAccountName") ?? tgt,
        DisplayName: ed("DisplayName") ?? tgt,
        UserPrincipalName: ed("UserPrincipalName") ?? `${tgt}@${domain}`,
        HomeDirectory: ed("HomeDirectory") ?? "-",
        HomePath: ed("HomePath") ?? "-",
        ScriptPath: ed("ScriptPath") ?? "-",
        ProfilePath: ed("ProfilePath") ?? "-",
        UserWorkstations: ed("UserWorkstations") ?? "-",
        PasswordLastSet: ed("PasswordLastSet") ?? "%%1794",
        AccountExpires: ed("AccountExpires") ?? "%%1794",
        PrimaryGroupId: ed("PrimaryGroupId") ?? "513",
        AllowedToDelegateTo: ed("AllowedToDelegateTo") ?? "-",
        OldUacValue: ed("OldUacValue") ?? "0x0",
        NewUacValue: ed("NewUacValue") ?? "0x15",
        UserAccountControl: ed("UserAccountControl") ?? "\n\t\t%%2080\n\t\t%%2082\n\t\t%%2084",
        UserParameters: ed("UserParameters") ?? "%%1793",
        SidHistory: ed("SidHistory") ?? "-",
        LogonHours: ed("LogonHours") ?? "%%1797",
      };
      data = id === "4738" ? { Dummy: "-", ...body } : body;
      break;
    }
    case "4722": case "4723": case "4724": case "4725": case "4726": case "4767": {
      const tgt = targetSam ?? "-";
      const subj = samOf(ed("SubjectUserName")) ?? "-";
      data = {
        TargetUserName: tgt,
        TargetDomainName: ed("TargetDomainName") ?? netbios,
        TargetSid: ed("TargetSid") ?? userSid(ctx, tgt),
        SubjectUserSid: ed("SubjectUserSid") ?? userSid(ctx, subj),
        SubjectUserName: ed("SubjectUserName") ?? subj,
        SubjectDomainName: ed("SubjectDomainName") ?? netbios,
        SubjectLogonId: ed("SubjectLogonId") ?? logonId(ctx, hostShort, subj),
      };
      break;
    }
    case "4728": case "4729": case "4732": case "4733": case "4756": case "4757": {
      const local = id === "4732" || id === "4733";
      const groupName = ed("TargetUserName") ?? str(raw["group.name"]) ?? "-";
      const memberSam = samOf(ed("MemberName")) ?? "-";
      const memberSid = ed("MemberSid") ?? userSid(ctx, memberSam.startsWith("CN=") ? memberSam.slice(3).split(",")[0] : memberSam);
      data = {
        MemberName: ed("MemberName") ?? (local ? "-" : "-"),
        MemberSid: memberSid,
        TargetUserName: groupName,
        TargetDomainName: ed("TargetDomainName") ?? (local ? "Builtin" : netbios),
        TargetSid: ed("TargetSid") ?? groupSid(ctx, groupName),
        SubjectUserSid: ed("SubjectUserSid") ?? userSid(ctx, samOf(ed("SubjectUserName"))),
        SubjectUserName: ed("SubjectUserName") ?? samOf(r("user.name")) ?? "-",
        SubjectDomainName: ed("SubjectDomainName") ?? netbios,
        SubjectLogonId: ed("SubjectLogonId") ?? logonId(ctx, hostShort, samOf(ed("SubjectUserName")) ?? "-"),
        PrivilegeList: ed("PrivilegeList") ?? "-",
      };
      break;
    }
    case "4740": {
      // The caller COMPUTER name sits in TargetDomainName (card §3.2) — carry the authored
      // CallerComputerName / source there (there is NO CallerComputerName field).
      const caller = ed("CallerComputerName") ?? (srcIp ? `\\\\${srcIp}` : ed("TargetDomainName") ?? "-");
      const tgt = targetSam ?? "-";
      data = {
        TargetUserName: tgt,
        TargetDomainName: caller,
        TargetSid: ed("TargetSid") ?? userSid(ctx, tgt),
        SubjectUserSid: ed("SubjectUserSid") ?? "S-1-5-18",
        SubjectUserName: ed("SubjectUserName") ?? `${hostShort}$`,
        SubjectDomainName: ed("SubjectDomainName") ?? netbios,
        SubjectLogonId: ed("SubjectLogonId") ?? "0x3e7",
      };
      break;
    }
    case "4768": {
      const status = (ed("Status") ?? "0x0").toLowerCase();
      keywords = keyw(status === "0x0");
      const tgt = targetSam ?? "-";
      data = {
        TargetUserName: tgt,
        TargetDomainName: ed("TargetDomainName") ?? netbios,
        TargetSid: ed("TargetSid") ?? userSid(ctx, tgt),
        ServiceName: ed("ServiceName") ?? "krbtgt",
        ServiceSid: ed("ServiceSid") ?? `S-1-5-21-${domainId(ctx)}-502`,
        TicketOptions: ed("TicketOptions") ?? "0x40810010",
        Status: status,
        TicketEncryptionType: (ed("TicketEncryptionType") ?? (status === "0x0" ? "0x12" : "0xffffffff")).toLowerCase(),
        PreAuthType: ed("PreAuthType") ?? "2",
        IpAddress: dcKerbIp() ?? "-",
        IpPort: ed("IpPort") ?? (srcIp ? ephemeral(ctx, `${ev.id}:ip`) : "0"),
        CertIssuerName: ed("CertIssuerName") ?? "",
        CertSerialNumber: ed("CertSerialNumber") ?? "",
        CertThumbprint: ed("CertThumbprint") ?? "",
      };
      break;
    }
    case "4769": {
      const status = (ed("Status") ?? "0x0").toLowerCase();
      keywords = keyw(status === "0x0");
      // TargetUserName is the requesting user as user@REALM.
      const reqUser = ed("TargetUserName") ?? (email ? `${email.split("@")[0]}@${domain.toUpperCase()}` : targetSam ?? "-");
      const svc = ed("ServiceName") ?? "-";
      data = {
        TargetUserName: reqUser,
        TargetDomainName: ed("TargetDomainName") ?? domain.toUpperCase(),
        ServiceName: svc,
        ServiceSid: ed("ServiceSid") ?? userSid(ctx, svc.replace(/\/.*$/, "").replace(/\$$/, "")),
        TicketOptions: ed("TicketOptions") ?? "0x40810000",
        TicketEncryptionType: (ed("TicketEncryptionType") ?? "0x12").toLowerCase(),
        IpAddress: dcKerbIp() ?? "-",
        IpPort: ed("IpPort") ?? (srcIp ? ephemeral(ctx, `${ev.id}:ip`) : "0"),
        Status: status,
        LogonGuid: ed("LogonGuid") ?? curly(logonGuid(ctx, hostShort, reqUser)),
        TransmittedServices: ed("TransmittedServices") ?? "-",
      };
      break;
    }
    case "4771": {
      keywords = keyw(false);
      const tgt = targetSam ?? "-";
      data = {
        TargetUserName: tgt,
        TargetSid: ed("TargetSid") ?? userSid(ctx, tgt),
        ServiceName: ed("ServiceName") ?? `krbtgt/${domain.toUpperCase()}`,
        TicketOptions: ed("TicketOptions") ?? "0x40810010",
        Status: (ed("Status") ?? "0x18").toLowerCase(),
        PreAuthType: ed("PreAuthType") ?? "2",
        IpAddress: dcKerbIp() ?? "-",
        IpPort: ed("IpPort") ?? (srcIp ? ephemeral(ctx, `${ev.id}:ip`) : "0"),
        CertIssuerName: ed("CertIssuerName") ?? "",
        CertSerialNumber: ed("CertSerialNumber") ?? "",
        CertThumbprint: ed("CertThumbprint") ?? "",
      };
      break;
    }
    case "4776": {
      const status = (ed("Status") ?? "0x0").toLowerCase();
      keywords = keyw(status === "0x0");
      data = {
        PackageName: ed("PackageName") ?? "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0",
        TargetUserName: targetSam ?? "-",
        Workstation: ed("Workstation") ?? r("destination.hostname") ?? hostShort,
        Status: status,
      };
      break;
    }
    case "4662": {
      const subj = samOf(ed("SubjectUserName")) ?? samOf(r("user.name")) ?? "-";
      const ldap = str(raw["ldap.filter"]);
      data = {
        SubjectUserSid: ed("SubjectUserSid") ?? userSid(ctx, subj),
        SubjectUserName: ed("SubjectUserName") ?? subj,
        SubjectDomainName: ed("SubjectDomainName") ?? netbios,
        SubjectLogonId: ed("SubjectLogonId") ?? logonId(ctx, hostShort, subj),
        ObjectServer: ed("ObjectServer") ?? "DS",
        ObjectType: ed("ObjectType") ?? "%{19195a5b-6da0-11d0-afd3-00c04fd930c9}",
        ObjectName: ed("ObjectName") ?? `DC=${domain.split(".").join(",DC=")}`,
        OperationType: ed("OperationType") ?? "Object Access",
        HandleId: ed("HandleId") ?? "0x0",
        AccessList: ed("AccessList") ?? "%%7688\r\n\t\t\t\t",
        AccessMask: ed("AccessMask") ?? "0x100",
        Properties: ed("Properties") ?? "%%7688",
        AdditionalInfo: ed("AdditionalInfo") ?? (ldap ? `LDAP filter: ${ldap}` : "-"),
        AdditionalInfo2: ed("AdditionalInfo2") ?? "",
      };
      break;
    }
    case "5136": {
      const subj = samOf(ed("SubjectUserName")) ?? samOf(r("user.name")) ?? "-";
      data = {
        OpCorrelationID: ed("OpCorrelationID") ?? curly(ctx.uuid(`${ev.id}:opcorr`)),
        AppCorrelationID: ed("AppCorrelationID") ?? "-",
        SubjectUserSid: ed("SubjectUserSid") ?? userSid(ctx, subj),
        SubjectUserName: ed("SubjectUserName") ?? subj,
        SubjectDomainName: ed("SubjectDomainName") ?? netbios,
        SubjectLogonId: ed("SubjectLogonId") ?? logonId(ctx, hostShort, subj),
        DSName: ed("DSName") ?? domain,
        DSType: ed("DSType") ?? "%%14676",
        ObjectDN: ed("ObjectDN") ?? str(raw["ad.object_dn"]) ?? `DC=${domain.split(".").join(",DC=")}`,
        ObjectGUID: ed("ObjectGUID") ?? curly(ctx.uuid(`${ev.id}:objguid`)),
        ObjectClass: ed("ObjectClass") ?? "domainDNS",
        AttributeLDAPDisplayName: ed("AttributeLDAPDisplayName") ?? "gPLink",
        AttributeSyntaxOID: ed("AttributeSyntaxOID") ?? "2.5.5.12",
        AttributeValue: ed("AttributeValue") ?? str(raw["ad.new_value"]) ?? "-",
        OperationType: ed("OperationType") ?? "%%14674",
      };
      break;
    }
    case "1102": {
      provider = r("winlog.provider_name") ?? "Microsoft-Windows-Eventlog";
      const subj = samOf(ed("SubjectUserName")) ?? samOf(r("user.name")) ?? "-";
      data = {
        SubjectUserSid: ed("SubjectUserSid") ?? userSid(ctx, subj),
        SubjectUserName: ed("SubjectUserName") ?? subj,
        SubjectDomainName: ed("SubjectDomainName") ?? netbios,
        SubjectLogonId: ed("SubjectLogonId") ?? logonId(ctx, hostShort, subj),
      };
      break;
    }
    case "7045": {
      provider = "Service Control Manager";
      channel = "System";
      keywords = "0x8080000000000000";
      data = {
        ServiceName: ed("ServiceName") ?? r("task.name") ?? "-",
        ImagePath: ed("ImagePath") ?? "-",
        ServiceType: ed("ServiceType") ?? "user mode service",
        StartType: ed("StartType") ?? "demand start",
        AccountName: ed("AccountName") ?? "LocalSystem",
      };
      break;
    }
    default:
      return null;
  }

  // Coherence guard (Tal's diagnostic, 2026-10-03): a Windows event whose id requires fields the
  // authored event doesn't carry (a 4688 with no process, a 4625 with no target / logon type) is
  // not rendered natively — it would read as a broken record. It stays in the legacy view instead.
  const missing = (REQUIRED_FIELDS[id] ?? []).filter(k => { const v = data[k]; return v === undefined || v === "" || v === "-"; });
  if (missing.length) return null;

  // The record is the Windows event as a SIEM ingests and shows it — the normalised JSON fields,
  // NOT raw EVTX XML. A SOC analyst reads the event in Sentinel / Elastic / Splunk, so that is what
  // the feed shows (Tal, 2026-10-03: "why did XML appear at all"). KeywordsText spells out the
  // Audit Success / Failure a hex Keywords bitmask encodes, as a normalised log does.
  const record: Record<string, unknown> = {
    EventID: Number(id),
    Computer: computer,
    TimeCreated: timeCreated(timeMs),
    Channel: channel,
    Provider: provider,
    EventRecordID: eventRecordID,
    Keywords: keywords,
    KeywordsText: keywords === "0x8020000000000000" ? "Audit Success" : keywords === "0x8010000000000000" ? "Audit Failure" : "Classic",
    ...data,
  };

  return { sourceId: "windows_security", kind: id, format: "json", record, timeMs };
}

/** Fields a given Event ID must carry to render as a coherent record. */
const REQUIRED_FIELDS: Record<string, string[]> = {
  "4624": ["TargetUserName", "LogonType"],
  "4625": ["TargetUserName", "LogonType", "Status"],
  "4634": ["TargetUserName"],
  "4648": ["TargetUserName"],
  "4672": ["SubjectUserName"],
  "4688": ["NewProcessName"],
  "4697": ["ServiceName"],
  "7045": ["ServiceName"],
  "4768": ["TargetUserName"],
  "4769": ["TargetUserName", "ServiceName"],
  "4771": ["TargetUserName"],
  "4776": ["TargetUserName"],
  "4740": ["TargetUserName"],
  "4662": ["ObjectName"],
  "5136": ["ObjectDN"],
  "4720": ["TargetUserName"],
  "4722": ["TargetUserName"], "4723": ["TargetUserName"], "4724": ["TargetUserName"],
  "4725": ["TargetUserName"], "4726": ["TargetUserName"], "4738": ["TargetUserName"], "4767": ["TargetUserName"],
  "4728": ["TargetUserName"], "4729": ["TargetUserName"],
  "4732": ["TargetUserName"], "4733": ["TargetUserName"],
  "4756": ["TargetUserName"], "4757": ["TargetUserName"],
};

// ── use cases (detections over the native Windows fields — no crypto) ─────────
const useCases: UseCase[] = [
  {
    id: "windows_security.password_spray", title: "Password spray — many accounts failing from one source",
    sourceId: "windows_security", kinds: ["4625", "4771"], severity: "high", mitre: ["T1110.003"],
    description: "One source produces authentication failures against multiple distinct accounts in a short window — the signature of a password spray, which stays under each account's lockout threshold. NTLM sprays leave 4625 on the member server; Kerberos sprays leave only 4771 (Status 0x18) on the DC.",
    logic: "SPL: (EventID=4625 Status=0xC000006D) OR (EventID=4771 Status=0x18) | stats dc(TargetUserName) as users by IpAddress bin=10m | where users>=2",
    match: { any: [
      { all: [{ field: "EventID", op: "eq", value: 4625 }, { field: "Status", op: "icontains", value: "0xc000006d" }] },
      { all: [{ field: "EventID", op: "eq", value: 4771 }, { field: "Status", op: "eq", value: "0x18" }] },
    ] },
    threshold: { groupBy: ["IpAddress"], distinct: "TargetUserName", count: 2, windowSec: 600 },
    falsePositives: ["A misconfigured service or scheduled task holding one stale credential (one account, not many).", "A shared kiosk after a company-wide password reset."],
  },
  {
    id: "windows_security.account_lockout_burst", title: "Multiple account lockouts from one caller (4740)",
    sourceId: "windows_security", kinds: ["4740"], severity: "medium", mitre: ["T1110"],
    description: "Several accounts lock out (4740) naming the same caller computer in a short window — brute force / spray reaching the lockout threshold.",
    logic: "SPL: EventID=4740 | stats dc(TargetUserName) as users by TargetDomainName bin=15m | where users>=2",
    match: { field: "EventID", op: "eq", value: 4740 },
    threshold: { groupBy: ["TargetDomainName"], distinct: "TargetUserName", count: 2, windowSec: 900 },
    falsePositives: ["A terminal server or app pool caching an expired service password locks several related accounts."],
  },
  {
    id: "windows_security.kerberoasting_rc4", title: "Kerberoasting — RC4 service tickets for many SPNs (4769)",
    sourceId: "windows_security", kinds: ["4769"], severity: "high", mitre: ["T1558.003"],
    description: "One source requests RC4-encrypted (0x17) service tickets for many distinct service accounts (SPN not ending in $, not krbtgt) in seconds — Kerberoasting to crack service-account passwords offline.",
    logic: "SPL: EventID=4769 TicketEncryptionType=0x17 Status=0x0 ServiceName!=\"*$\" ServiceName!=krbtgt | stats dc(ServiceName) as spns by IpAddress bin=5m | where spns>=3",
    match: { all: [
      { field: "EventID", op: "eq", value: 4769 },
      { field: "TicketEncryptionType", op: "eq", value: "0x17" },
      { field: "Status", op: "eq", value: "0x0" },
      { not: { field: "ServiceName", op: "endsWith", value: "$" } },
      { not: { field: "ServiceName", op: "startsWith", value: "krbtgt" } },
    ] },
    threshold: { groupBy: ["IpAddress"], distinct: "ServiceName", count: 3, windowSec: 300 },
    falsePositives: ["A legacy application that genuinely negotiates RC4 for one service account (single SPN, repeated)."],
  },
  {
    id: "windows_security.asrep_roasting", title: "AS-REP roasting — TGT issued without pre-authentication (4768)",
    sourceId: "windows_security", kinds: ["4768"], severity: "high", mitre: ["T1558.004"],
    description: "A TGT (4768) issued with PreAuthType 0 and Status 0x0 — the KDC handed out a ticket encrypted with the account's key with no proof of password, because the account has 'Do not require Kerberos preauthentication'. The attacker cracks it offline.",
    logic: "SPL: EventID=4768 PreAuthType=0 Status=0x0",
    match: { all: [{ field: "EventID", op: "eq", value: 4768 }, { field: "PreAuthType", op: "eq", value: "0" }, { field: "Status", op: "eq", value: "0x0" }] },
    falsePositives: ["A legacy account legitimately configured without pre-auth (inventory these and treat each as suspicious)."],
  },
  {
    id: "windows_security.dcsync", title: "DCSync — directory replication by a non-DC account (4662)",
    sourceId: "windows_security", kinds: ["4662"], severity: "critical", mitre: ["T1003.006"],
    description: "A 4662 with AccessMask 0x100 whose Properties include the DS-Replication-Get-Changes-All control-access right (1131f6ad-…) — pulling password hashes from the directory. Only domain controllers and the directory-sync account do this legitimately; any other subject is DCSync.",
    logic: "SPL: EventID=4662 AccessMask=0x100 Properties=\"*1131f6ad*\" NOT (SubjectUserName=\"*$\" OR SubjectUserName=\"MSOL_*\")",
    match: { all: [
      { field: "EventID", op: "eq", value: 4662 },
      { field: "AccessMask", op: "eq", value: "0x100" },
      { any: [
        { field: "Properties", op: "icontains", value: "1131f6ad" },
        { field: "Properties", op: "icontains", value: "1131f6aa" },
        { field: "Properties", op: "icontains", value: "89e95b76" },
      ] },
      { not: { field: "SubjectUserName", op: "endsWith", value: "$" } },
      { not: { field: "SubjectUserName", op: "startsWith", value: "MSOL_" } },
    ] },
    falsePositives: ["Entra Connect's MSOL_* sync account and the Entra Cloud Sync account (exclude by name)."],
  },
  {
    id: "windows_security.privileged_group_add", title: "Member added to a privileged domain group (4728/4756)",
    sourceId: "windows_security", kinds: ["4728", "4756", "4732"], severity: "high", mitre: ["T1098", "T1078.002"],
    description: "An account added to Domain Admins / Enterprise Admins / Schema Admins / Administrators / Group Policy Creator Owners. Verify against a change ticket — unplanned additions are privilege escalation or persistence.",
    logic: "SPL: EventID IN (4728,4756,4732) TargetSid IN (*-512,*-519,*-518,*-520,S-1-5-32-544)",
    match: { any: [
      { field: "TargetSid", op: "endsWith", value: "-512" },
      { field: "TargetSid", op: "endsWith", value: "-519" },
      { field: "TargetSid", op: "endsWith", value: "-518" },
      { field: "TargetSid", op: "endsWith", value: "-520" },
    ] },
    falsePositives: ["A planned administrator onboarding under an approved change ticket."],
  },
  {
    id: "windows_security.audit_log_cleared", title: "Security audit log cleared (1102)",
    sourceId: "windows_security", kinds: ["1102"], severity: "high", mitre: ["T1070.001"],
    description: "The Security event log was cleared (1102). Rare in normal operations and a classic anti-forensics step after hands-on-keyboard activity — correlate with what happened just before on the same host.",
    logic: "SPL: EventID=1102",
    match: { field: "EventID", op: "eq", value: 1102 },
    falsePositives: ["A sanctioned log-rotation or re-imaging task clearing logs (should run as a service / scheduled task, not an interactive admin)."],
  },
  {
    id: "windows_security.service_install_suspicious", title: "Suspicious service installed (7045/4697)",
    sourceId: "windows_security", kinds: ["7045", "4697"], severity: "high", mitre: ["T1543.003", "T1569.002"],
    description: "A new service whose binary runs from a temp / user-writable path, via cmd/powershell, or over an admin share — the PsExec / Impacket / Cobalt-Strike remote-execution and persistence pattern.",
    logic: "SPL: (EventID=7045 OR EventID=4697) (ImagePath=\"*\\\\Temp\\\\*\" OR ImagePath=\"*powershell*\" OR ImagePath=\"*%COMSPEC%*\" OR ImagePath=\"*ADMIN$*\" OR ServiceFileName=\"*\\\\Temp\\\\*\")",
    match: { any: [
      { field: "ImagePath", op: "regex", value: "\\\\(Temp|Users\\\\Public|ProgramData)\\\\|powershell|%COMSPEC%|cmd\\.exe|ADMIN\\$|\\\\\\\\127\\.0\\.0\\.1" },
      { field: "ServiceFileName", op: "regex", value: "\\\\(Temp|Users\\\\Public|ProgramData)\\\\|powershell|%COMSPEC%|cmd\\.exe|ADMIN\\$" },
    ] },
    falsePositives: ["Some legitimate software installs a helper service from ProgramData — confirm the publisher and signature."],
  },
  {
    id: "windows_security.account_created", title: "New domain account created (4720)",
    sourceId: "windows_security", kinds: ["4720"], severity: "medium", mitre: ["T1136.002"],
    description: "A new user account was created (4720). Benign under an onboarding ticket; suspicious when the creator is itself a freshly-created or compromised admin, or when the account is added to a privileged group moments later.",
    logic: "SPL: EventID=4720 | lookup onboarding_tickets SamAccountName OUTPUT ticket | where isnull(ticket)",
    match: { field: "EventID", op: "eq", value: 4720 },
    falsePositives: ["Routine HR onboarding performed by the service desk under an approved request."],
  },
  {
    id: "windows_security.external_rdp_logon", title: "Interactive/RDP logon from a non-corporate address (4624 type 10/2)",
    sourceId: "windows_security", kinds: ["4624"], severity: "high", mitre: ["T1021.001", "T1133"],
    description: "A RemoteInteractive (RDP, type 10) or Interactive (type 2) logon whose IpAddress is outside the corporate ranges — direct RDP exposure or a stolen credential used from the internet.",
    logic: "SPL: EventID=4624 LogonType IN (2,10) NOT (IpAddress=10.0.0.0/8 OR IpAddress=172.16.0.0/12 OR IpAddress=192.168.0.0/16 OR IpAddress=\"-\" OR IpAddress=\"0.0.0.0\")",
    match: { all: [
      { field: "EventID", op: "eq", value: 4624 },
      { any: [{ field: "LogonType", op: "eq", value: "10" }, { field: "LogonType", op: "eq", value: "2" }] },
      { field: "IpAddress", op: "notCidr", value: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"] },
      { not: { field: "IpAddress", op: "in", value: ["-", "0.0.0.0", "::1"] } },
    ] },
    falsePositives: ["An administrator connecting over a VPN that hands out public-looking addresses, or a jump host with a routable address."],
  },
  {
    id: "windows_security.sedebug_privilege_assigned", title: "SeDebugPrivilege assigned to a logon (4672)",
    sourceId: "windows_security", kinds: ["4672"], severity: "low", mitre: ["T1134", "T1003.001"],
    description: "A logon session was granted SeDebugPrivilege — needed to read another process's memory (e.g. LSASS). Expected for tier-0 admins and some agents; worth a glance for an account that should not have it.",
    logic: "SPL: EventID=4672 PrivilegeList=\"*SeDebugPrivilege*\"",
    match: { all: [{ field: "EventID", op: "eq", value: 4672 }, { field: "PrivilegeList", op: "icontains", value: "SeDebugPrivilege" }] },
    falsePositives: ["Domain admins, backup agents and EDR sensors legitimately hold SeDebugPrivilege."],
  },
];

export const source: NativeSource = {
  schema: {
    sourceId: "windows_security", category: "onprem_ad", card: "windows-security.md", product: "Windows Security",
    format: "json", vendorMatch: ["windows security", "windows terminalservices", "microsoft-windows-security", "active directory"], telemetrySources: ["ad", "windows_security"], kinds,
  },
  fromTelemetry,
  useCases,
};
