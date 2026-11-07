/**
 * Active Directory stories. On-premises Windows Security logs, so they run where a domain exists:
 * NexaCorp, MedCore, GlobalLogis and a named organization.
 *
 *  1. core-adcs-esc1: template enumeration, a certificate request naming a privileged UPN in the SAN
 *     (4886/4887), PKINIT as that account (4768 PreAuthType 16), a logon and a Domain Admins add.
 *  2. core-shadow-credentials: msDS-KeyCredentialLink written on a privileged account (5136), PKINIT as
 *     that account, a share read and removal of the value.
 *  3. core-gpo-scheduled-task: a GPO edited to deploy an immediate scheduled task (5136, 5145 SYSVOL),
 *     then domain members applying it and deleting their shadow copies.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";
import { csProcess } from "@/lib/sim/emitters/crowdstrike";
import { sysmonProcess } from "@/lib/sim/emitters/sysmon";
import { sentinelAlert } from "@/lib/sim/emitters/sentinel";
import { domainSidFor, winDetailedShareAccess, winGroupMemberAdd, winLogon } from "@/lib/sim/emitters/windowsSecurity";
import { winTaskCreated } from "@/lib/sim/emitters/scenarioExtras";
import { AD_COMPANIES, clock, incident, lookalike, type CoreStoryDef } from "./_kit";

const cx = "nexacorp";
const DC = "SRV-NXC-DC01";
// The CA role sits on the domain controller here, a common layout, so every company has the host.
const CA = DC;
const FS = "SRV-NXC-FS01";
const NB = "NEXACORP";

interface WinRow {
  id: string; ts: string; host: string; user: string; srcIp?: string; description: string;
  severity?: TelemetryEvent["severity"]; mitre?: string; tactic?: string; isDetection?: boolean;
  eventType?: TelemetryEvent["event_type"];
}
/** A Security-log record whose EventData this catalog authors directly (certificate and directory-change events). */
export function winRecord(o: WinRow, eventId: string, data: Record<string, string>): TelemetryEvent {
  const fields = Object.fromEntries(Object.entries(data).map(([k, v]) => [`winlog.event_data.${k}`, v]));
  return {
    id: o.id, ts: o.ts, source: "ad", vendor: "Windows Security", event_type: o.eventType ?? "account_modify",
    severity: o.severity ?? "medium", hostname: o.host, user_email: `${o.user}@nexacorp.com`, ...(o.srcIp ? { src_ip: o.srcIp } : {}),
    ...(o.mitre ? { mitre_technique: o.mitre } : {}), ...(o.tactic ? { mitre_tactic: o.tactic } : {}),
    description: o.description,
    raw: {
      "winlog.event_id": eventId, "winlog.channel": "Security", "winlog.computer_name": `${o.host}.nexacorp.com`,
      "winlog.provider_name": "Microsoft-Windows-Security-Auditing", "event.code": eventId, ...fields,
      "user.name": o.user, "user.domain": NB,
    },
  };
}
/** Attribute syntax OIDs (AD schema): msDS-KeyCredentialLink is DN-Binary, versionNumber Enumeration, gPCMachineExtensionNames String(Unicode). */
const SYNTAX: Record<string, string> = { "msDS-KeyCredentialLink": "2.5.5.7", versionNumber: "2.5.5.9", gPCMachineExtensionNames: "2.5.5.12" };
/** 5136 names no client address; SubjectLogonId is the join to the writer's 4624 on the same computer. */
const dirChange = (o: WinRow, logonId: string, dn: string, cls: string, attr: string, value: string, op: "%%14674" | "%%14675", subject = o.user): TelemetryEvent =>
  winRecord(o, "5136", { SubjectUserName: subject, SubjectDomainName: NB, SubjectLogonId: logonId, ObjectDN: dn, ObjectClass: cls, AttributeLDAPDisplayName: attr, AttributeSyntaxOID: SYNTAX[attr], AttributeValue: value, OperationType: op });
/** An inert msDS-KeyCredentialLink value of the declared length: B:<hex length>:<hex>:<owner DN>. */
function keyCredential(seed: string, dn: string): string {
  let hex = "0002000020000100";
  for (let i = 0; hex.length < 828; i++) hex += makeSha256(`${seed}:${i}`).toUpperCase();
  return `B:828:${hex.slice(0, 828)}:${dn}`;
}
const tgt = (o: WinRow, data: Record<string, string>): TelemetryEvent => winRecord({ ...o, eventType: "kerberos_tgt" }, "4768", data);

// ── 1. AD CS template abuse (ESC1) ───────────────────────────────────────────
function adcsEsc1(): TelemetryEvent[] {
  const T = clock("2026-10-09T21:15:00Z");
  const user = "d.okafor";
  const admin = "adm.rhale";
  const host = "WS-ENG-2093";
  const ip = "10.10.20.93";
  const tool = "C:\\Users\\d.okafor\\AppData\\Local\\Temp\\cfy.exe";
  const toolHash = makeSha256("core-esc1-template-enumerator");
  const caName = "NEXACORP-DC01-CA";
  const thumb = "7f3a91c40be2d65a18c7e0f4b93d2a6e15c8074d";
  const serial = "61000000a1f3c79e2b5d04aa9200000000a1";
  return incident("inc:core-esc1:1", [
    lookalike(winRecord({ id: "ces01", ts: T(0), host: CA, user: "m.tanaka", severity: "low", eventType: "privileged_operation", description: "CA log 4887 on SRV-NXC-DC01: certificate issued to NEXACORP\\m.tanaka from template WebServer-Internal with SAN dns=intranet.nexacorp.com." }, "4887", {
      RequestId: "48116", Requester: `${NB}\\m.tanaka`, Attributes: "CertificateTemplate:WebServer-Internal\nSAN:dns=intranet.nexacorp.com",
      Disposition: "3", SubjectKeyIdentifier: "4c1a7be0932f5d6e8a10c47f2b93de605a17c4e2", Subject: "CN=intranet.nexacorp.com",
    }), "Change ticket for the intranet server's yearly certificate renewal. A web server template carries a DNS name in the SAN by design; no user principal name is requested."),
    csProcess({
      companyId: cx, id: "ces02", ts: T(1200), host, user: `${user}@nexacorp.com`, srcIp: ip, processName: "cfy.exe", pid: 6640, processPath: tool, cmdline: `"${tool}" find /enrolleeSuppliesSubject`,
      parentName: "powershell.exe", parentPid: 6212, sha256: toolHash, signed: false, originalFileName: "Certify.exe", severity: "high", mitre: "T1649", tactic: "Credential Access",
      description: "cfy.exe, an unsigned binary in d.okafor's Temp folder whose embedded original name is Certify.exe, ran with the argument find /enrolleeSuppliesSubject on WS-ENG-2093.",
    }),
    sysmonProcess({
      companyId: cx, id: "ces02s", ts: T(1200), host, user: `${user}@nexacorp.com`, srcIp: ip, processName: "cfy.exe", pid: 6640, processPath: tool, cmdline: `"${tool}" find /enrolleeSuppliesSubject`,
      parentName: "powershell.exe", parentPid: 6212, sha256: toolHash, signed: false, originalFileName: "Certify.exe", integrity: "Medium", severity: "high", mitre: "T1649", tactic: "Credential Access",
      description: "Sysmon 1 on WS-ENG-2093: cfy.exe from d.okafor's Temp folder, OriginalFileName Certify.exe, with find /enrolleeSuppliesSubject.",
    }),
    csProcess({
      companyId: cx, id: "ces02r", ts: T(1496), host, user: `${user}@nexacorp.com`, srcIp: ip, processName: "cfy.exe", pid: 6702, processPath: tool, cmdline: `"${tool}" request /ca:${CA}.nexacorp.com\\${caName} /template:VPN-UserAuth /altname:${admin}`,
      parentName: "powershell.exe", parentPid: 6212, sha256: toolHash, signed: false, originalFileName: "Certify.exe", severity: "high", mitre: "T1649", tactic: "Credential Access",
      description: "cfy.exe ran on WS-ENG-2093 with request, template VPN-UserAuth and alternate name adm.rhale.",
    }),
    winRecord({ id: "ces03", ts: T(1500), host: CA, user, severity: "medium", mitre: "T1649", tactic: "Credential Access", eventType: "privileged_operation",
      description: "CA log 4886 on SRV-NXC-DC01: request 48207 received from NEXACORP\\d.okafor for template VPN-UserAuth with SAN upn=adm.rhale@nexacorp.com." }, "4886", {
      RequestId: "48207", Requester: `${NB}\\${user}`, Attributes: `CertificateTemplate:VPN-UserAuth\nSAN:upn=${admin}@nexacorp.com\nccm:${host}.nexacorp.com`,
    }),
    winRecord({ id: "ces04", ts: T(1501), host: CA, user, severity: "high", mitre: "T1649", tactic: "Credential Access", eventType: "privileged_operation",
      description: "CA log 4887 on SRV-NXC-DC01: request 48207 issued, Requester NEXACORP\\d.okafor, Subject CN=d.okafor, SAN upn=adm.rhale@nexacorp.com." }, "4887", {
      RequestId: "48207", Requester: `${NB}\\${user}`, Attributes: `CertificateTemplate:VPN-UserAuth\nSAN:upn=${admin}@nexacorp.com\nccm:${host}.nexacorp.com`,
      Disposition: "3", SubjectKeyIdentifier: "b2e6107fd94c3a58e1076da29c4f13ee8a50d7c9", Subject: `CN=${user}, OU=Engineering, DC=nexacorp, DC=com`,
    }),
    { ...sentinelAlert({
      companyId: cx, id: "ces05", ts: T(1560), user: `${user}@nexacorp.com`, host: CA, srcIp: ip, alertName: "Certificate issued where SAN differs from requester", severity: "high", mitre: "T1649", tactic: "Credential Access",
      detail: "An issued certificate names a user principal in the SAN that is not the requesting account.",
      extendedProperties: { RequestId: "48207", Requester: `${NB}\\${user}`, SubjectAlternativeName: `${admin}@nexacorp.com`, Template: "VPN-UserAuth" },
      description: "Sentinel analytic: request 48207 on SRV-NXC-DC01, Requester d.okafor, SAN adm.rhale@nexacorp.com.",
    }), edr_scope: "hybrid" as const },
    tgt({ id: "ces06", ts: T(1740), host: DC, user: admin, srcIp: ip, severity: "high", mitre: "T1649", tactic: "Credential Access",
      description: "DC log 4768 on SRV-NXC-DC01: TGT issued for adm.rhale to 10.10.20.93, PreAuthType 16, certificate issuer NEXACORP-DC01-CA." }, {
      TargetUserName: admin, TargetDomainName: "NEXACORP.COM", PreAuthType: "16", TicketEncryptionType: "0x12", Status: "0x0", IpAddress: ip,
      CertIssuerName: caName, CertSerialNumber: serial, CertThumbprint: thumb,
    }),
    winLogon({
      companyId: cx, id: "ces07", ts: T(1800), host: DC, targetUser: admin, logonType: 3, srcIp: ip, authPackage: "Kerberos", severity: "high", mitre: "T1078.002", tactic: "Privilege Escalation",
      description: "DC log 4624 on SRV-NXC-DC01: network logon for adm.rhale from 10.10.20.93 using Kerberos.",
    }),
    winGroupMemberAdd({
      companyId: cx, id: "ces08", ts: T(2040), host: DC, targetUser: user, userEmail: `${user}@nexacorp.com`, groupName: "Domain Admins", groupSid: domainSidFor(cx, admin).replace(/-\d+$/, "-512"),
      subjectUser: admin, subjectSid: domainSidFor(cx, admin), memberName: `CN=${user},OU=Engineering,DC=nexacorp,DC=com`, memberSid: domainSidFor(cx, user), srcIp: ip,
      severity: "critical", mitre: "T1098.007", tactic: "Persistence",
      description: "DC log 4728 on SRV-NXC-DC01: d.okafor added to Domain Admins by adm.rhale.",
    }),
  ]);
}

// ── 2. Shadow credentials ────────────────────────────────────────────────────
function shadowCredentials(): TelemetryEvent[] {
  const T = clock("2026-10-10T19:40:00Z");
  const user = "j.whitlock";
  const target = "adm.kpatel";
  const host = "WS-OPS-2214";
  const ip = "10.10.20.14";
  const tool = "C:\\Users\\Public\\wsk.exe";
  const toolHash = makeSha256("core-shadow-credential-writer");
  const targetDn = `CN=${target},OU=Tier0,OU=Admins,DC=nexacorp,DC=com`;
  const blob = keyCredential("core-shadow-key", targetDn);
  const session = "0x6B2F14";
  return incident("inc:core-shadow-creds:1", [
    lookalike(dirChange({ id: "csc01", ts: T(0), host: DC, user: "MSOL_8f2c1a9d", severity: "low", description: "DC log 5136 on SRV-NXC-DC01: msDS-KeyCredentialLink value added to user l.ferreira by MSOL_8f2c1a9d." }, "0x3E41A2",
      "CN=l.ferreira,OU=Staff,DC=nexacorp,DC=com", "user", "msDS-KeyCredentialLink", keyCredential("core-whfb-key", "CN=l.ferreira,OU=Staff,DC=nexacorp,DC=com"), "%%14674"),
      "Entra Connect's sync account writes this attribute back when a user enrols in Windows Hello for Business. The MSOL_ account does this for many users, every day."),
    csProcess({
      companyId: cx, id: "csc02", ts: T(2400), host, user: `${user}@nexacorp.com`, srcIp: ip, processName: "wsk.exe", pid: 5520, processPath: tool, cmdline: `"${tool}" add /target:${target}`,
      parentName: "cmd.exe", parentPid: 5012, sha256: toolHash, signed: false, originalFileName: "Whisker.exe", severity: "high", mitre: "T1556", tactic: "Credential Access",
      description: "wsk.exe, an unsigned binary in C:\\Users\\Public whose embedded original name is Whisker.exe, ran on WS-OPS-2214 with add /target:adm.kpatel.",
    }),
    sysmonProcess({
      companyId: cx, id: "csc02s", ts: T(2400), host, user: `${user}@nexacorp.com`, srcIp: ip, processName: "wsk.exe", pid: 5520, processPath: tool, cmdline: `"${tool}" add /target:${target}`,
      parentName: "cmd.exe", parentPid: 5012, sha256: toolHash, signed: false, originalFileName: "Whisker.exe", integrity: "Medium", severity: "high", mitre: "T1556", tactic: "Credential Access",
      description: "Sysmon 1 on WS-OPS-2214: wsk.exe from C:\\Users\\Public, OriginalFileName Whisker.exe, with add /target:adm.kpatel.",
    }),
    winLogon({
      companyId: cx, id: "csc02l", ts: T(2401), host: DC, targetUser: user, logonType: 3, srcIp: ip, authPackage: "Kerberos", logonId: session, severity: "low",
      description: "DC log 4624 on SRV-NXC-DC01: network logon for j.whitlock from 10.10.20.14 using Kerberos.",
    }),
    dirChange({ id: "csc03", ts: T(2402), host: DC, user, severity: "high", mitre: "T1556", tactic: "Credential Access", description: "DC log 5136 on SRV-NXC-DC01: msDS-KeyCredentialLink value added to adm.kpatel by j.whitlock." }, session,
      targetDn, "user", "msDS-KeyCredentialLink", blob, "%%14674"),
    { ...sentinelAlert({
      companyId: cx, id: "csc04", ts: T(2460), user: `${user}@nexacorp.com`, host: DC, srcIp: ip, alertName: "Key credential added to a privileged account", severity: "high", mitre: "T1556", tactic: "Credential Access",
      detail: "msDS-KeyCredentialLink was changed on a privileged account by an account that is not the directory sync account.",
      extendedProperties: { TargetObject: targetDn, Attribute: "msDS-KeyCredentialLink", SubjectUserName: user },
      description: "Sentinel analytic: 5136 msDS-KeyCredentialLink on adm.kpatel, subject j.whitlock.",
    }), edr_scope: "hybrid" as const },
    tgt({ id: "csc05", ts: T(2520), host: DC, user: target, srcIp: ip, severity: "high", mitre: "T1550", tactic: "Lateral Movement", description: "DC log 4768 on SRV-NXC-DC01: TGT issued for adm.kpatel to 10.10.20.14, PreAuthType 16, certificate subject the account itself." }, {
      TargetUserName: target, TargetDomainName: "NEXACORP.COM", PreAuthType: "16", TicketEncryptionType: "0x12", Status: "0x0", IpAddress: ip,
      CertIssuerName: `CN=${target}`, CertSerialNumber: "2fa1c07e93b64d18", CertThumbprint: "c09e41a7d2b8f35e6a10d7c43f8e2b915a06d3f7",
    }),
    winLogon({
      companyId: cx, id: "csc06", ts: T(2640), host: FS, targetUser: target, logonType: 3, srcIp: ip, authPackage: "Kerberos", logSource: "windows_security", severity: "high", mitre: "T1021.002", tactic: "Lateral Movement",
      description: "Security log 4624 on SRV-NXC-FS01: network logon for adm.kpatel from 10.10.20.14 using Kerberos.",
    }),
    winDetailedShareAccess({
      companyId: cx, id: "csc07", ts: T(2700), host: FS, targetUser: target, srcIp: ip, shareName: "\\\\*\\Finance$", shareLocalPath: "\\??\\D:\\Shares\\Finance", relativeTargetName: "Treasury\\2026\\bank-mandates.xlsx",
      accessMask: "0x1", accessList: "%%4416", logSource: "windows_security", severity: "high", mitre: "T1039", tactic: "Collection",
      description: "Security log 5145 on SRV-NXC-FS01: adm.kpatel read Treasury\\2026\\bank-mandates.xlsx on Finance$ from 10.10.20.14.",
    }),
    dirChange({ id: "csc08", ts: T(3300), host: DC, user, severity: "high", mitre: "T1070", tactic: "Stealth", description: "DC log 5136 on SRV-NXC-DC01: msDS-KeyCredentialLink value deleted from adm.kpatel by j.whitlock." }, session,
      targetDn, "user", "msDS-KeyCredentialLink", blob, "%%14675"),
  ]);
}

// ── 3. GPO scheduled task at scale ───────────────────────────────────────────
function gpoScheduledTask(): TelemetryEvent[] {
  const T = clock("2026-10-11T02:05:00Z");
  const user = "adm.cvoss";
  const host = "WS-ENG-2093";
  const ip = "10.10.20.93";
  const member1 = "SRV-NXC-FS01";
  const member2 = "WS-HR-1182";
  // The Default Domain Policy: linked at the domain, so it reaches member servers and workstations.
  const gpo = "{31B2F340-016D-11D2-945F-00C04FB984F9}";
  const session = "0x7A31C4";
  const gpoDn = `CN=${gpo},CN=Policies,CN=System,DC=nexacorp,DC=com`;
  const cse = "[{00000000-0000-0000-0000-000000000000}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}][{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]";
  const taskFile = `nexacorp.com\\Policies\\${gpo}\\Machine\\Preferences\\ScheduledTasks\\ScheduledTasks.xml`;
  const task = "\\Microsoft\\Windows\\WindowsUpdate\\UpdateHealthSync";
  const cmd = "cmd.exe /c vssadmin delete shadows /all /quiet";
  const cmdHash = makeSha256("windows_cmd_exe_signed_microsoft");
  // Started by the Task Scheduler as SYSTEM: the row belongs to no user, the admin never touched these machines.
  const memberRun = (id: string, sec: number, h: string, pid: number, description: string): TelemetryEvent => {
    const { user_email: _admin, ...row } = csProcess({
      companyId: cx, id, ts: T(sec), host: h, user: `${user}@nexacorp.com`, processName: "cmd.exe", pid, processPath: "C:\\Windows\\System32\\cmd.exe", cmdline: cmd,
      parentName: "svchost.exe", parentPid: 1184, sha256: cmdHash, signed: true, signatureSubject: "Microsoft Corporation", runAsUser: "NT AUTHORITY\\SYSTEM", integrity: "system", severity: "critical", mitre: "T1490", tactic: "Impact", description,
    });
    return row;
  };
  return incident("inc:core-gpo-task:1", [
    lookalike(dirChange({ id: "cgp01", ts: T(0), host: DC, user: "gpo.admin", severity: "low", description: "DC log 5136 on SRV-NXC-DC01: versionNumber changed on GPO {B7C4E1A2-5D3F-4E86-9A17-3F0C2D6E8B41} by gpo.admin." }, "0x5D20B7",
      "CN={B7C4E1A2-5D3F-4E86-9A17-3F0C2D6E8B41},CN=Policies,CN=System,DC=nexacorp,DC=com", "groupPolicyContainer", "versionNumber", "1048601", "%%14674"),
      "Planned change: the GPO administrator updated the screen-lock timeout under an approved change. No extension GUIDs changed and no task file was written."),
    winLogon({
      companyId: cx, id: "cgp02", ts: T(4800), host: DC, targetUser: user, logonType: 3, srcIp: ip, authPackage: "Kerberos", logonId: session, severity: "medium", mitre: "T1078.002", tactic: "Privilege Escalation",
      description: "DC log 4624 on SRV-NXC-DC01: network logon for adm.cvoss from WS-ENG-2093 (10.10.20.93) at 03:25 UTC.",
    }),
    dirChange({ id: "cgp03", ts: T(4920), host: DC, user, severity: "high", mitre: "T1484.001", tactic: "Stealth", description: `DC log 5136 on SRV-NXC-DC01: gPCMachineExtensionNames changed on GPO ${gpo} by adm.cvoss, value includes the scheduled-tasks extension GUIDs.` }, session,
      gpoDn, "groupPolicyContainer", "gPCMachineExtensionNames", cse, "%%14674"),
    winDetailedShareAccess({
      companyId: cx, id: "cgp04", ts: T(4925), host: DC, targetUser: user, srcIp: ip, shareName: "\\\\*\\SYSVOL", shareLocalPath: "\\??\\C:\\Windows\\SYSVOL\\sysvol", relativeTargetName: taskFile,
      accessMask: "0x2", accessList: "%%4417", severity: "high", mitre: "T1484.001", tactic: "Stealth",
      description: `DC log 5145 on SRV-NXC-DC01: adm.cvoss wrote ScheduledTasks.xml under the policy folder of GPO ${gpo} on SYSVOL.`,
    }),
    dirChange({ id: "cgp05", ts: T(4930), host: DC, user, severity: "high", mitre: "T1484.001", tactic: "Stealth", description: `DC log 5136 on SRV-NXC-DC01: versionNumber changed on GPO ${gpo} by adm.cvoss.` }, session,
      gpoDn, "groupPolicyContainer", "versionNumber", "2097158", "%%14674"),
    { ...sentinelAlert({
      companyId: cx, id: "cgp06", ts: T(4980), user: `${user}@nexacorp.com`, host: DC, srcIp: ip, alertName: "Scheduled task pushed through Group Policy", severity: "high", mitre: "T1484.001", tactic: "Stealth",
      detail: "A GPO gained the scheduled-tasks extension and ScheduledTasks.xml was written on SYSVOL in one session.",
      extendedProperties: { Gpo: gpo, SubjectUserName: user, RelativeTargetName: taskFile },
      description: `Sentinel analytic: GPO ${gpo} changed by adm.cvoss from 10.10.20.93 with a write to ScheduledTasks.xml.`,
    }), edr_scope: "hybrid" as const },
    winTaskCreated({
      companyId: cx, id: "cgp07", ts: T(5520), host: member1, user: "SYSTEM", userSid: "S-1-5-18", subjectLogonId: "0x3e7", taskName: task,
      taskContent: `<Task version="1.2"><Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Actions><Exec><Command>cmd.exe</Command><Arguments>/c vssadmin delete shadows /all /quiet</Arguments></Exec></Actions></Task>`,
      severity: "high", mitre: "T1053.005", tactic: "Persistence",
      description: "Security log 4698 on SRV-NXC-FS01: task \\Microsoft\\Windows\\WindowsUpdate\\UpdateHealthSync registered by SYSTEM, runs cmd.exe with vssadmin delete shadows.",
    }),
    memberRun("cgp08", 5522, member1, 4412, "cmd.exe started by the Task Scheduler service on SRV-NXC-FS01 as SYSTEM, deleting all shadow copies with vssadmin."),
    memberRun("cgp09", 6180, member2, 3964, "cmd.exe started by the Task Scheduler service on WS-HR-1182 as SYSTEM, deleting all shadow copies with vssadmin."),
  ]);
}

export const AD_STORIES: CoreStoryDef[] = [
  { id: "core-adcs-esc1", title: "AD CS Template Abuse: Certificate Requested for an Admin, Then a Domain Admins Add", complexity: "advanced", companies: AD_COMPANIES, events: adcsEsc1() },
  { id: "core-shadow-credentials", title: "Shadow Credentials: Key Credential on an Admin, Certificate Logon, Value Removed", complexity: "advanced", companies: AD_COMPANIES, events: shadowCredentials() },
  { id: "core-gpo-scheduled-task", title: "Group Policy Abuse: Scheduled Task Pushed Through a GPO to Delete Shadow Copies", complexity: "advanced", companies: AD_COMPANIES, events: gpoScheduledTask() },
];
