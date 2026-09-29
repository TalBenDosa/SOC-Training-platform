/**
 * AI-related attack stories — CORE tier.
 *
 * Defensive training telemetry: what the SOC's log sources would record when AI is part of
 * the attack (a cloned voice at the help desk), the insider risk (a leaver moving data into
 * an enterprise AI workspace) or the abused surface (Microsoft 365 Copilot oversharing).
 *
 *  1. ai-helpdesk-voice-reset        — voice-clone impersonation → MFA reset → new-device
 *                                       sign-in → mailbox forwarding rule
 *  2. ai-claude-enterprise-departure — resignation → after-hours bulk uploads to Claude
 *                                       Enterprise (Compliance API activity records)
 *  3. ai-copilot-oversharing-probe   — Copilot jailbreak prompts + sensitivity-labelled
 *                                       HR / IT / finance files read on behalf of a user who
 *                                       never opens them
 *
 * Authored against the NexaCorp estate; instantiateStory() rewrites victim, hosts, domain and
 * private IPs for MedCore / GlobalLogis. Names of people are deliberately never written into
 * prose (only UPNs) so the victim swap stays consistent in descriptions and raw blocks.
 *
 * Log-shape notes
 *  - Purview CopilotInteraction carries NO prompt text — only message ids and the
 *    JailbreakDetected flag, plus AccessedResources (Name / Type / SensitivityLabelId / Status).
 *  - Claude Enterprise audit events carry NO prompt or file content — only ids, filename,
 *    actor, type — the activity record as it lands in the SIEM, no collector envelope.
 *  - SharePoint records intentionally carry SourceRelativeUrl (site + library path) but no
 *    absolute tenant host, so no company-specific host survives the per-company swap.
 */

import type { TelemetryEvent } from "@/lib/sim/types";
import { entraSignIn, entraAudit } from "@/lib/sim/emitters/entra";
import { serviceNowRecord } from "@/lib/sim/emitters/servicenow";
import { m365Operation } from "@/lib/sim/emitters/m365";
import { claudeActivity, type ClaudeActivityType } from "@/lib/sim/emitters/claudeEnterprise";

export interface AiStoryDef {
  id: string;
  title: string;
  complexity: "foundation" | "core" | "advanced";
  companies: string[];
  events: TelemetryEvent[];
}

// ── small deterministic helpers ────────────────────────────────────────────────

/** Deterministic lowercase hex fragment (for GUID-shaped ids). */
function hexOf(seed: string, len: number): string {
  let out = "";
  let s = seed;
  while (out.length < len) {
    let x = 2166136261;
    for (let i = 0; i < s.length; i++) { x ^= s.charCodeAt(i); x = Math.imul(x, 16777619); }
    out += (x >>> 0).toString(16).padStart(8, "0");
    s = `${s}|${out.length}`;
  }
  return out.slice(0, len);
}

/** Deterministic mixed-case alphanumeric id fragment (looks like a real opaque id). */
function opaque(seed: string, len: number): string {
  let out = "";
  let s = seed;
  while (out.length < len) {
    let x = 2166136261;
    for (let i = 0; i < s.length; i++) { x ^= s.charCodeAt(i); x = Math.imul(x, 16777619); }
    out += (x >>> 0).toString(36);
    s = `${s}|${out.length}`;
  }
  return out
    .slice(0, len)
    .split("")
    .map((c, i) => (/[a-z]/.test(c) && (i * 7 + seed.length) % 3 === 0 ? c.toUpperCase() : c))
    .join("");
}

const EDGE_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36 Edg/151.0.0.0";
const CHROME_WIN_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36";

const OFFICE_IP = "82.132.31.8";   // corporate office egress
const OFFICE_GEO = { country: "United Kingdom", city: "London", latitude: 51.5074, longitude: -0.1278 };

/** Deterministic lowercase hex of a given length (stable across rebuilds). */
function hexId(seed: string, len: number): string {
  let h = 2166136261 >>> 0;
  let out = "";
  for (let n = 0; out.length < len; n++) {
    for (let k = 0; k < seed.length; k++) {
      h ^= seed.charCodeAt(k) + n;
      h = Math.imul(h, 16777619) >>> 0;
    }
    out += h.toString(16).padStart(8, "0");
  }
  return out.slice(0, len);
}

/** Deterministic version-4-shaped GUID (audit record ids, SharePoint site/list ids). */
function guid(seed: string): string {
  const x = hexId(seed, 32);
  return `${x.slice(0, 8)}-${x.slice(8, 12)}-4${x.slice(13, 16)}-a${x.slice(17, 20)}-${x.slice(20, 32)}`;
}

/** The NexaCorp Microsoft 365 tenant (the same id the Copilot audit records carry). */
const TENANT_ID = "6d1f9a3e-4b27-4c85-9e10-a7c53f82b9d4";

/** Milliseconds after an event's ts at which the SIEM ingested it (event.created). */
const ingested = (ts: string, ms: number): string => new Date(Date.parse(ts) + ms).toISOString();

/**
 * Fields the Unified Audit Log writes on every SharePointFileOperation record (RecordType 6):
 * the record id, tenant, site / web / list / item ids and the browser. There is deliberately no
 * ObjectId or SiteUrl (absolute tenant host), only SourceRelativeUrl, so no company-specific host
 * survives the per-company swap.
 */
const spFileAudit = (id: string, fileName: string, libraryPath: string, managed: boolean): Record<string, string> => {
  const site = libraryPath.split("/")[1] ?? libraryPath;
  return {
    Id: guid(`ual:${id}`),
    RecordType: "6",
    UserType: "0",
    Version: "1",
    OrganizationId: TENANT_ID,
    EventSource: "SharePoint",
    Site: guid(`site:${site}`),
    WebId: guid(`web:${site}`),
    ListId: guid(`list:${libraryPath}`),
    ListItemUniqueId: guid(`item:${fileName}`),
    CorrelationId: guid(`corr:${id}`),
    BrowserName: "Edge",
    BrowserVersion: "151.0.0.0",
    IsManagedDevice: String(managed),
    HighPriorityMediaProcessing: "false",
  };
};

/** Diagnostic-log envelope and portal user agent an Entra AuditLogs record carries. */
const auditEnvelope = (id: string, corr: string, ua: string): Record<string, unknown> => ({
  "azure.auditlogs.resourceId": `/tenants/${TENANT_ID}/providers/Microsoft.aadiam`,
  "azure.auditlogs.tenantId": TENANT_ID,
  "azure.auditlogs.operationVersion": "1.0",
  "azure.auditlogs.resultSignature": "None",
  "azure.auditlogs.level": "Informational",
  "azure.auditlogs.properties.id": `Directory_${corr}_${opaque(`auditid:${id}`, 5).toUpperCase()}`,
  "azure.auditlogs.properties.additionalDetails[0].key": "User-Agent",
  "azure.auditlogs.properties.additionalDetails[0].value": ua,
});

const pwMfa = (t: string, mfaOk = true) => [
  { authenticationStepDateTime: t, authenticationMethod: "Password", authenticationMethodDetail: "Password in the cloud", succeeded: true, authenticationStepResultDetail: "Correct password", authenticationStepRequirement: "Primary authentication" },
  mfaOk
    ? { authenticationStepDateTime: t, authenticationMethod: "Mobile app notification", authenticationMethodDetail: "Microsoft Authenticator", succeeded: true, authenticationStepResultDetail: "MFA completed in Azure AD", authenticationStepRequirement: "Multifactor authentication" }
    : { authenticationStepDateTime: t, authenticationMethod: "Mobile app notification", authenticationMethodDetail: "", succeeded: false, authenticationStepResultDetail: "MFA registration required", authenticationStepRequirement: "Multifactor authentication" },
];

// ══════════════════════════════════════════════════════════════════════════════
// 1. ai-helpdesk-voice-reset
// ══════════════════════════════════════════════════════════════════════════════

function buildVoiceReset(): TelemetryEvent[] {
  const cx = "nexacorp" as const;
  const VICTIM = "d.cohen@nexacorp.com";
  const VICTIM_ID = "4b7d1e92-6a35-4c08-9f2e-8d1a5c7b3e60";
  const DEVICE_ID = "7e31c4a8-5d92-4f10-a6b3-c08e91d2f457";
  const LAPTOP = "WS-HR-1182";
  const AGENT = "j.oduya@nexacorp.com";
  const AGENT_ID = "c9e21f57-3d84-4a06-b7e5-12f8a0d94c63";
  const AGENT_IP = "10.60.4.18";
  const NEW_IP = "80.94.95.118";   // 80.94.* resolves to Bucharest, Romania (shared geo table)
  const TICKET = "INC0051764";
  const T_SHORT = "Locked out after phone replacement — urgent MFA reset needed before 09:00 leadership review";
  const T_DESC = "Caller reports being locked out after replacing a mobile phone and asks for an urgent reset of the password and Microsoft Authenticator so the account can be used before a 09:00 leadership review. Desk agent noted the caller's voice was recognised.";
  // Fields every ServiceNow incident row carries whatever the update was, plus the Elastic
  // ServiceNow integration's event envelope (event.module / dataset / provider).
  const snowRow = (ts: string) => ({
    "servicenow.category": "Access", "servicenow.subcategory": "MFA Reset", "servicenow.contact_type": "Phone",
    "servicenow.opened_by": AGENT, "servicenow.opened_at": "2026-09-22 08:34:09", "servicenow.sys_created_on": "2026-09-22 08:34:09",
    "servicenow.description": T_DESC, "servicenow.cmdb_ci": "Microsoft Entra ID", "servicenow.approval": "not requested",
    "event.provider": "ServiceNow", "event.module": "servicenow", "event.dataset": "servicenow.event",
    "event.created": ingested(ts, 1_240), "log.level": "info",
  });

  return [
    // 1. Baseline — the account's normal pattern.
    {
      ...entraSignIn({
        companyId: cx, id: "aihvr1", ts: "2026-09-22T07:58:31.402Z", srcIp: OFFICE_IP, user: VICTIM, userId: VICTIM_ID,
        correlationId: "0e9b4d27-83c1-4a56-b2f0-6d1a95c73e48", sessionId: "d8a41f63-2b70-4e95-9c1d-5a37e0b82f14",
        app: "Microsoft Teams", appId: "1fec8e78-bce4-4aaf-ab1b-5451cc387264", resource: "Microsoft Graph", mfa: true, isInteractive: true,
        managed: true, compliant: true, deviceId: DEVICE_ID, deviceName: LAPTOP, os: "Windows 11", browser: "Edge 151.0.0", trustType: "Azure AD joined",
        userAgent: EDGE_UA, asn: 2856, tokenIssuerType: "AzureAD", incomingTokenType: "none", riskLevel: "none", riskDetail: "none",
        riskEventTypes: [], conditionalAccess: "success", geo: OFFICE_GEO, severity: "informational",
        extra: { "azure.signinlogs.properties.authenticationDetails": pwMfa("2026-09-22T07:58:31.402Z") },
        description: "d.cohen signed in to Microsoft Teams at 07:58 from the corporate office egress address on the Entra-joined, compliant laptop WS-HR-1182, password plus an Authenticator push. This is the account's normal pattern.",
      }),
      hostname: LAPTOP,
    },

    // 2. The call — a routine-looking MFA-reset ticket opened by phone.
    serviceNowRecord({
      companyId: cx, id: "aihvr2", ts: "2026-09-22T08:34:09.771Z", table: "incident", number: TICKET, state: "New",
      shortDescription: T_SHORT,
      callerId: VICTIM, mitre: "T1656", tactic: "Defense Evasion", severity: "low",
      extra: {
        ...snowRow("2026-09-22T08:34:09.771Z"),
        "servicenow.priority": "2 - High", "servicenow.urgency": "1 - High", "servicenow.impact": "3 - Low",
        "servicenow.assignment_group": "IT Service Desk", "servicenow.assigned_to": AGENT,
        "servicenow.sys_updated_on": "2026-09-22 08:34:09",
        "servicenow.u_identity_verification": "Employee ID stated by caller; voice recognised by service desk agent",
      },
      description: "ServiceNow incident INC0051764 was opened by phone at the IT Service Desk in the name of d.cohen: the caller reports being locked out after replacing a phone and asks for an urgent MFA reset before a 09:00 leadership review. The agent noted that the caller's voice was recognised.",
    }),

    // 3. The account owner is demonstrably at their desk while the call is open.
    {
      ...entraSignIn({
        companyId: cx, id: "aihvr3", ts: "2026-09-22T08:39:47.208Z", srcIp: OFFICE_IP, user: VICTIM, userId: VICTIM_ID,
        correlationId: "5c2f8a10-9d47-4b63-8e15-a0d3b76c4f92", sessionId: "d8a41f63-2b70-4e95-9c1d-5a37e0b82f14",
        app: "SharePoint Online", appId: "00000003-0000-0ff1-ce00-000000000000", resource: "Office 365 SharePoint Online", mfa: true, isInteractive: true,
        managed: true, compliant: true, deviceId: DEVICE_ID, deviceName: LAPTOP, os: "Windows 11", browser: "Edge 151.0.0", trustType: "Azure AD joined",
        userAgent: EDGE_UA, asn: 2856, tokenIssuerType: "AzureAD", incomingTokenType: "none", riskLevel: "none", riskDetail: "none",
        riskEventTypes: [], conditionalAccess: "success", geo: OFFICE_GEO, severity: "informational",
        extra: { "azure.signinlogs.properties.authenticationDetails": pwMfa("2026-09-22T08:39:47.208Z") },
        description: "d.cohen signed in to SharePoint Online at 08:39 from the same office address and the same compliant laptop, MFA by Authenticator push — under six minutes after the help desk ticket was opened in this account's name and while that ticket was still open.",
      }),
      hostname: LAPTOP,
    },

    // 4. Ticket resolved — verification was a voice match and an employee id.
    serviceNowRecord({
      companyId: cx, id: "aihvr4", ts: "2026-09-22T08:46:52.334Z", table: "incident", number: TICKET, state: "Resolved",
      shortDescription: T_SHORT,
      callerId: VICTIM, mitre: "T1656", tactic: "Defense Evasion", severity: "low",
      extra: {
        ...snowRow("2026-09-22T08:46:52.334Z"),
        "servicenow.priority": "2 - High", "servicenow.urgency": "1 - High", "servicenow.impact": "3 - Low",
        "servicenow.close_code": "Solved (Permanently)",
        "servicenow.close_notes": "Password reset via admin portal and registered authentication methods cleared so the caller can re-enroll Microsoft Authenticator at next sign-in.",
        "servicenow.work_notes": "Identity check: employee ID given by caller, voice recognised by agent. Call-back to the number on file not performed because the caller stated the phone was lost.",
        "servicenow.resolved_by": AGENT, "servicenow.resolved_at": "2026-09-22 08:46:52",
        "servicenow.assignment_group": "IT Service Desk", "servicenow.assigned_to": AGENT, "servicenow.sys_updated_on": "2026-09-22 08:46:52",
      },
      description: "INC0051764 was resolved by j.oduya at 08:46: password reset and registered authentication methods cleared for d.cohen. The recorded identity check is an employee ID plus voice recognition, and no call-back to the number on file was made.",
    }),

    // 5. Password reset by the help-desk admin (privilege chain: Authentication Administrator).
    entraAudit({
      companyId: cx, id: "aihvr5", ts: "2026-09-22T08:47:58.615Z", operationName: "Reset password (by admin)", loggedByService: "Core Directory",
      result: "success", correlationId: "a7e63d02-4b91-4c58-8f27-d15b0c9e3a64",
      initiatedByUpn: AGENT, initiatedById: AGENT_ID, initiatedByIp: AGENT_IP, initiatedByRoles: ["Authentication Administrator"],
      targetUpn: VICTIM, targetId: VICTIM_ID, mitre: "T1098", tactic: "Persistence", severity: "medium",
      extra: auditEnvelope("aihvr5", "a7e63d02-4b91-4c58-8f27-d15b0c9e3a64", EDGE_UA),
      description: "j.oduya, holding the Authentication Administrator role and working from the internal help desk network, reset the password of d.cohen's account one minute after closing INC0051764.",
    }),

    // 6. Registered authentication methods wiped (T1556.006).
    entraAudit({
      companyId: cx, id: "aihvr6", ts: "2026-09-22T08:48:31.097Z", operationName: "Admin deleted security info", loggedByService: "Authentication Methods",
      result: "success", correlationId: "3d90b8f5-71a2-4e64-9b08-c62e4a17d5f3",
      initiatedByUpn: AGENT, initiatedById: AGENT_ID, initiatedByIp: AGENT_IP, initiatedByRoles: ["Authentication Administrator"],
      targetUpn: VICTIM, targetId: VICTIM_ID, mitre: "T1556.006", tactic: "Defense Evasion", severity: "high",
      extra: {
        ...auditEnvelope("aihvr6", "3d90b8f5-71a2-4e64-9b08-c62e4a17d5f3", EDGE_UA),
        "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].displayName": "StrongAuthenticationMethod",
        "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].oldValue": "[{\"MethodType\":\"PhoneAppNotification\",\"Default\":true}]",
        "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].newValue": "[]",
      },
      description: "j.oduya deleted the registered Microsoft Authenticator method on d.cohen's account 33 seconds after the password reset, leaving the account with a password and no second factor until new security info is registered.",
    }),

    // 7. First sign-in from an unseen address is interrupted: the account must enroll MFA.
    entraSignIn({
      companyId: cx, id: "aihvr7", ts: "2026-09-22T08:51:44.904Z", srcIp: NEW_IP, user: VICTIM, userId: VICTIM_ID,
      correlationId: "b4106e9a-2f75-4d38-a1c3-7e58d09f6b21", sessionId: "6f2a9c84-0d13-4b7e-85a6-e3c17d40b592",
      app: "Microsoft Office", appId: "d3590ed6-52b3-4102-aeff-aad2292ab01c", resource: "Microsoft Graph", result: "failure", errorCode: "50072", mfa: true, isInteractive: true,
      managed: false, compliant: false, deviceId: "", os: "Windows 10", browser: "Chrome 151.0.0", userAgent: CHROME_WIN_UA, asn: 9009,
      tokenIssuerType: "AzureAD", incomingTokenType: "none", riskLevel: "none", riskDetail: "none", riskEventTypes: [], conditionalAccess: "notApplicable",
      severity: "medium", mitre: "T1078.004", tactic: "Initial Access",
      extra: {
        "azure.signinlogs.resultDescription": "User needs to enroll for second factor authentication (interrupt)",
        "azure.signinlogs.properties.authenticationDetails": pwMfa("2026-09-22T08:51:44.904Z", false),
      },
      description: "A sign-in to d.cohen's account from 80.94.95.118 (Bucharest, Romania), an address not seen for this account, passed the password step and was interrupted with error 50072 because the account now has no second factor and must enroll. Device is an unmanaged Windows 10 machine running Chrome.",
    }),

    // 8. New Authenticator registered from the same unseen address (T1098.005).
    entraAudit({
      companyId: cx, id: "aihvr8", ts: "2026-09-22T08:53:40.119Z", operationName: "User registered security info", loggedByService: "Authentication Methods",
      result: "success", resultReason: "User registered security info: Microsoft Authenticator app", correlationId: "e58c2b07-9a14-4f63-b0d5-18a7c36e4d90",
      initiatedByUpn: VICTIM, initiatedById: VICTIM_ID, initiatedByIp: NEW_IP, initiatedByRoles: [],
      targetUpn: VICTIM, targetId: VICTIM_ID, mitre: "T1098.005", tactic: "Persistence", severity: "high",
      extra: {
        ...auditEnvelope("aihvr8", "e58c2b07-9a14-4f63-b0d5-18a7c36e4d90", CHROME_WIN_UA),
        "GeoLocation.country_name": "Romania",
        "GeoLocation.city_name": "Bucharest",
        "GeoLocation.latitude": 44.4,
        "GeoLocation.longitude": 26.1,
        "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].displayName": "StrongAuthenticationMethod",
        "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].oldValue": "[]",
        "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].newValue": "[{\"MethodType\":\"PhoneAppNotification\",\"Default\":true}]",
      },
      description: "A new Microsoft Authenticator app was registered as d.cohen's security info from 80.94.95.118, the same Romanian address, five minutes after the methods were wiped. The initiating identity is d.cohen's own, but the IP matches none of the office-address sessions on the account earlier this morning.",
    }),

    // 9. MFA genuinely satisfied on the newly enrolled method (T1078.004).
    entraSignIn({
      companyId: cx, id: "aihvr9", ts: "2026-09-22T08:56:12.560Z", srcIp: NEW_IP, user: VICTIM, userId: VICTIM_ID,
      correlationId: "91d7f3a6-c082-4b59-8e14-5f60a2d8b73c", sessionId: "6f2a9c84-0d13-4b7e-85a6-e3c17d40b592",
      app: "Office 365 Exchange Online", appId: "00000002-0000-0ff1-ce00-000000000000", resource: "Office 365 Exchange Online", mfa: true, isInteractive: true,
      managed: false, compliant: false, deviceId: "", os: "Windows 10", browser: "Chrome 151.0.0", userAgent: CHROME_WIN_UA, asn: 9009,
      tokenIssuerType: "AzureAD", incomingTokenType: "none", riskLevel: "none", riskDetail: "none", riskEventTypes: [], conditionalAccess: "success",
      severity: "critical", mitre: "T1078.004", tactic: "Initial Access",
      extra: { "azure.signinlogs.properties.authenticationDetails": pwMfa("2026-09-22T08:56:12.560Z") },
      description: "d.cohen's account signed in to Exchange Online at 08:56 from 80.94.95.118 on the unmanaged Windows 10 / Chrome device. Password and MFA both completed, Conditional Access succeeded and Entra sign-in risk is none — the newly registered Authenticator satisfied the second factor.",
    }),

    // 10. Mailbox forwarding rule from the new session (T1114.003).
    {
      ...m365Operation({
        companyId: cx, id: "aihvr10", ts: "2026-09-22T09:03:27.842Z", user: VICTIM, operation: "New-InboxRule", workload: "Exchange", srcIp: NEW_IP,
        userAgent: CHROME_WIN_UA, sessionId: "6f2a9c84-0d13-4b7e-85a6-e3c17d40b592",
        parameters: "[{\"Name\":\"ForwardTo\",\"Value\":\"mailbox.archive.2026@proton.me\"},{\"Name\":\"SubjectContainsWords\",\"Value\":\"offer,salary,payroll\"},{\"Name\":\"MarkAsRead\",\"Value\":\"True\"},{\"Name\":\"Name\",\"Value\":\".\"}]",
        extra: {
          RecordType: "1", UserType: "0", ClientInfoString: "Client=OWA;Action=ViaProxy",
          Id: guid("ual:aihvr10"), Version: "1", OrganizationId: TENANT_ID, ExternalAccess: "false",
          OriginatingServer: "LO2P265MB4471 (15.20.7182.019)",
        },
        mitre: "T1114.003", tactic: "Collection", severity: "high",
        description: "From 80.94.95.118 a new inbox rule was created in d.cohen's mailbox that forwards messages with offer, salary or payroll in the subject to an external Proton Mail address and marks them read, seven minutes after the new-device sign-in.",
      }),
      geo: { country: "Romania", city: "Bucharest", latitude: 44.4, longitude: 26.1 },
    },

    // 11. Afterwards: the ticket note that finally names the voice.
    serviceNowRecord({
      companyId: cx, id: "aihvr11", ts: "2026-09-22T09:41:05.276Z", table: "incident", number: TICKET, state: "In Progress",
      shortDescription: T_SHORT,
      callerId: VICTIM, mitre: "T1656", tactic: "Defense Evasion", severity: "high",
      extra: {
        ...snowRow("2026-09-22T09:41:05.276Z"),
        "servicenow.urgency": "1 - High", "servicenow.impact": "1 - High", "servicenow.assigned_to": AGENT,
        "servicenow.work_notes": "09:38 — d.cohen phoned the desk from the office extension: no call was made this morning, no phone was lost, the laptop has been in use throughout. Desk lead replayed the 08:31 call recording: the voice is indistinguishable from d.cohen's on first listen but speech cadence is unnaturally uniform, there is no room noise, and the caller declined a call-back. Suspected synthetic (AI-cloned) voice used to impersonate d.cohen. Security operations notified.",
        "servicenow.priority": "1 - Critical", "servicenow.assignment_group": "IT Service Desk",
        "servicenow.sys_updated_on": "2026-09-22 09:41:05", "servicenow.sys_updated_by": "s.reinhardt@nexacorp.com",
      },
      description: "A work note was added to INC0051764: d.cohen phoned the desk to say no call was made and no phone was lost, and the desk lead's replay of the 08:31 recording describes a voice indistinguishable from d.cohen's but unnaturally uniform, with a refused call-back. The ticket now records a suspected AI-cloned voice used to impersonate d.cohen (ATLAS AML.T0088 Generate Deepfakes, AML.T0052.001).",
    }),
  ];
}

// ══════════════════════════════════════════════════════════════════════════════
// 2. ai-claude-enterprise-departure
// ══════════════════════════════════════════════════════════════════════════════


interface ClaudeOpts {
  id: string; ts: string; type: string;
  email: string; userId: string; ip: string; ua: string;
  projectId?: string; fileId?: string; filename?: string;
  severity: TelemetryEvent["severity"]; description: string;
  mitre?: string; tactic?: string;
}

/**
 * One Claude Enterprise Compliance-API activity as it lands in the SIEM — delegated to the
 * shared emitter (src/lib/sim/emitters/claudeEnterprise.ts) so every Claude log in the
 * platform has the same field set and id formats. No prompt, response or file
 * content is present in this log — only ids, filename, actor and activity type.
 */
function claudeEvent(o: ClaudeOpts): TelemetryEvent {
  return claudeActivity({
    id: o.id, ts: o.ts, org: { key: "nexacorp" },
    type: o.type as ClaudeActivityType,
    email: o.email, ip: o.ip, userAgent: o.ua,
    geo: o.ip === OFFICE_IP ? { country: OFFICE_GEO.country, city: OFFICE_GEO.city, lat: OFFICE_GEO.latitude, lon: OFFICE_GEO.longitude }
      : o.ip === "86.14.203.57" ? { country: "United Kingdom", city: "Manchester", lat: 53.4808, lon: -2.2426 }   // a.kaplan's home ISP
      : undefined,
    projectSeed: o.projectId, fileSeed: o.fileId, filename: o.filename,
    severity: o.severity, description: o.description,
    mitre: o.mitre, tactic: o.tactic,
  });
}

function buildClaudeDeparture(): TelemetryEvent[] {
  const cx = "nexacorp" as const;
  const USER = "a.kaplan@nexacorp.com";
  const USER_ID = "user_01Gm4RzXq7NvKc2Bw9LhYt5D";
  const HOME_IP = "86.14.203.57";
  const HOST = "WS-SALES-1876";
  const PROJECT = `claude_proj_01${opaque("proj:renewals", 22)}`;
  const F1 = { name: "Enterprise_Accounts_Renewals_FY27.xlsx", id: `claude_file_01${opaque("file:1", 22)}` };
  const F2 = { name: "Top50_Customer_Contracts_Redlines.docx", id: `claude_file_01${opaque("file:2", 22)}` };
  const F3 = { name: "Pricing_Model_Discounts_2026.xlsx", id: `claude_file_01${opaque("file:3", 22)}` };
  const F4 = { name: "Pipeline_Q4_Forecast_Detail.xlsx", id: `claude_file_01${opaque("file:4", 22)}` };

  const base = { email: USER, userId: USER_ID, ua: CHROME_WIN_UA };
  const SP_PATH = "sites/Sales-Operations/Shared Documents/Accounts";

  return [
    // 1. HR: the resignation (no MITRE — routine business event).
    {
      id: "aicld1", ts: "2026-09-24T09:14:07.330Z", source: "hr", vendor: "Workday", event_type: "account_modify",
      user_email: USER, severity: "informational",
      description: "A worker lifecycle change was recorded for a.kaplan: a voluntary resignation submitted by the employee with an employment end date of 2026-10-08 and access revocation scheduled for that evening. The notice period is active.",
      raw: {
        "workday.event_type": "Worker_Resignation_Submitted",
        "workday.worker_id": "WD-0068417",
        "workday.worker_email": USER,
        "workday.termination_date": "2026-10-08",
        "workday.termination_reason_category": "Voluntary",
        "workday.initiated_by": USER,
        "workday.notice_period_active": "true",
        "workday.access_revocation_scheduled": "2026-10-08T17:00:00Z",
        "event.action": "Worker_Resignation_Submitted",
        "event.outcome": "success",
        "event.provider": "Workday",
        "event.module": "workday",
        "event.created": "2026-09-24T09:14:09.412Z",
        "log.level": "info",
      },
    },

    // 2. Baseline — ordinary daytime Claude use from the office.
    claudeEvent({
      id: "aicld2", ts: "2026-09-24T11:26:33.140Z", type: "claude_chat_created", ...base, ip: OFFICE_IP,
      severity: "informational",
      description: "a.kaplan started a new Claude Enterprise chat at 11:26 from the corporate office egress address in a normal browser session. No project, no file upload — this is the account's usual daytime pattern on the sanctioned AI workspace.",
    }),

    // 3-4. Evening SharePoint downloads of the sales files, from the home address.
    {
      ...m365Operation({
        companyId: cx, id: "aicld3", ts: "2026-09-24T19:44:52.310Z", user: USER, operation: "FileDownloaded", workload: "SharePoint", srcIp: HOME_IP,
        fileName: F1.name, fileExtension: "xlsx", fileSize: 2_874_112, userAgent: EDGE_UA,
        extra: { SourceRelativeUrl: SP_PATH, ItemType: "File", ...spFileAudit("aicld3", F1.name, SP_PATH, false) },
        mitre: "T1213.002", tactic: "Collection", severity: "medium",
        description: "a.kaplan downloaded Enterprise_Accounts_Renewals_FY27.xlsx from the Sales-Operations SharePoint library at 19:44, from a home internet address, roughly ten and a half hours after the resignation was recorded.",
      }),
      source: "sharepoint" as const,
    },
    {
      ...m365Operation({
        companyId: cx, id: "aicld4", ts: "2026-09-24T19:45:41.775Z", user: USER, operation: "FileDownloaded", workload: "SharePoint", srcIp: HOME_IP,
        fileName: F2.name, fileExtension: "docx", fileSize: 1_402_368, userAgent: EDGE_UA,
        extra: { SourceRelativeUrl: "sites/Sales-Operations/Shared Documents/Contracts", ItemType: "File", ...spFileAudit("aicld4", F2.name, "sites/Sales-Operations/Shared Documents/Contracts", false) },
        mitre: "T1213.002", tactic: "Collection", severity: "medium",
        description: "a.kaplan downloaded Top50_Customer_Contracts_Redlines.docx from the Sales-Operations contracts library 49 seconds after the first download, from the same home address.",
      }),
      source: "sharepoint" as const,
    },

    // 5. SSO into Claude Enterprise, outside business hours, from home.
    claudeEvent({
      id: "aicld5", ts: "2026-09-24T20:03:58.221Z", type: "sso_login_initiated", ...base, ip: HOME_IP,
      severity: "low",
      description: "a.kaplan initiated a Claude Enterprise SSO login at 20:03 from the home internet address, about eight and a half hours after the last daytime session from the office.",
    }),

    // 6. Opens a project.
    claudeEvent({
      id: "aicld6", ts: "2026-09-24T20:05:31.480Z", type: "claude_project_viewed", ...base, ip: HOME_IP, projectId: PROJECT,
      severity: "low",
      description: "a.kaplan opened a Claude Enterprise project at 20:05. The audit record carries the project id only — no project name, prompt or file content.",
    }),

    // 7. First upload — the file just downloaded.
    claudeEvent({
      id: "aicld7", ts: "2026-09-24T20:07:14.902Z", type: "claude_file_uploaded", ...base, ip: HOME_IP, projectId: PROJECT, fileId: F1.id, filename: F1.name,
      severity: "medium",
      mitre: "T1567", tactic: "Exfiltration",
      description: "a.kaplan uploaded Enterprise_Accounts_Renewals_FY27.xlsx to the Claude Enterprise project — the file downloaded from SharePoint about 22 minutes earlier. This is the company's own tenant, so the upload alone is not a leak; the risk is a leaver consolidating customer data in a place from which it can be pulled back out (ATLAS AML.T0025 when an AI workspace is used as the staging channel).",
    }),

    // 8. Endpoint DLP audits the browser upload of the same file (audit-only rule).
    {
      id: "aicld8", ts: "2026-09-24T20:07:19.880Z", source: "dlp", vendor: "Microsoft Purview", event_type: "dlp_alert",
      hostname: HOST, user_email: USER, src_ip: HOME_IP, severity: "medium",
      mitre_technique: "T1567", mitre_tactic: "Exfiltration",
      description: "Microsoft Purview Endpoint DLP matched the browser upload of Enterprise_Accounts_Renewals_FY27.xlsx by chrome.exe on WS-SALES-1876 to claude.ai. The matching rule is audit-only: the activity was logged and nothing was blocked or justified by the user.",
      file: { name: F1.name, path: `C:\\Users\\a.kaplan\\Downloads\\${F1.name}`, extension: "xlsx", size: 2_874_112 },
      raw: {
        "data.office365.Operation": "DlpRuleMatch",
        "data.office365.Workload": "Endpoint",
        "data.office365.UserId": USER,
        "data.office365.ObjectId": `C:\\Users\\a.kaplan\\Downloads\\${F1.name}`,
        "data.office365.IncidentId": "6104827",
        "data.office365.PolicyDetails.PolicyName": "Confidential Sales Data - Cloud Upload Audit",
        "data.office365.PolicyDetails.Rules.RuleName": "Audit upload of labeled sales files to cloud AI services",
        "data.office365.PolicyDetails.Rules.RuleMode": "Enforce",
        "data.office365.PolicyDetails.Rules.Severity": "Medium",
        "data.office365.PolicyDetails.Rules.Actions": ["Audit"],
        "data.office365.PolicyDetails.Rules.ConditionsMatched.SensitiveInformation.SensitiveInformationTypeName": "Customer Account Number",
        "data.office365.PolicyDetails.Rules.ConditionsMatched.SensitiveInformation.Count": "218",
        "data.office365.PolicyDetails.Rules.ConditionsMatched.SensitiveInformation.Confidence": "85",
        "data.office365.PolicyDetails.Rules.ConditionsMatched.SensitiveInformation.ClassifierType": "PatternMatch",
        "purview.PolicyName": "Confidential Sales Data - Cloud Upload Audit",
        "purview.RuleName": "Audit upload of labeled sales files to cloud AI services",
        "purview.SensitiveInfoType": "Customer Account Number",
        "purview.Workload": "Endpoint",
        "purview.ActionTaken": "Audit",
        "purview.Override": "false",
        "data.office365.DeviceDisplayName": HOST,
        "data.office365.ClientProcessName": "chrome.exe",
        "data.office365.TargetDomain": "claude.ai",
        "user.name": "NEXACORP\\a.kaplan",
        "host.name": HOST,
        "action_result": "allowed",
      },
    },

    // 9. Second upload.
    claudeEvent({
      id: "aicld9", ts: "2026-09-24T20:07:52.117Z", type: "claude_file_uploaded", ...base, ip: HOME_IP, projectId: PROJECT, fileId: F2.id, filename: F2.name,
      severity: "high",
      mitre: "T1567", tactic: "Exfiltration",
      description: "a.kaplan uploaded Top50_Customer_Contracts_Redlines.docx to the same Claude Enterprise project 37 seconds after the first upload — the second file downloaded from SharePoint earlier the same evening.",
    }),

    // 10-11. Two more files in quick succession.
    claudeEvent({
      id: "aicld10", ts: "2026-09-24T20:12:40.560Z", type: "claude_file_uploaded", ...base, ip: HOME_IP, projectId: PROJECT, fileId: F3.id, filename: F3.name,
      severity: "high",
      mitre: "T1567", tactic: "Exfiltration",
      description: "a.kaplan uploaded Pricing_Model_Discounts_2026.xlsx to the project at 20:12 — a pricing file with no matching SharePoint download in this feed.",
    }),
    claudeEvent({
      id: "aicld11", ts: "2026-09-24T20:12:58.301Z", type: "claude_file_uploaded", ...base, ip: HOME_IP, projectId: PROJECT, fileId: F4.id, filename: F4.name,
      severity: "high",
      mitre: "T1567", tactic: "Exfiltration",
      description: "a.kaplan uploaded Pipeline_Q4_Forecast_Detail.xlsx 18 seconds after the pricing file: four commercially sensitive files (renewals, contracts, pricing, pipeline) are now in one Claude Enterprise project, all uploaded between 20:07 and 20:12 by an employee who resigned that morning.",
    }),

    // 12. A chat inside the project.
    claudeEvent({
      id: "aicld12", ts: "2026-09-24T20:16:26.348Z", type: "claude_chat_created", ...base, ip: HOME_IP, projectId: PROJECT,
      severity: "medium",
      description: "a.kaplan created a new chat inside the project holding the four uploaded files at 20:16. The audit log records that the chat exists, not what was asked or answered — establishing what was done with the data needs the Compliance API session content, HR and legal.",
    }),
  ];
}

// ══════════════════════════════════════════════════════════════════════════════
// 3. ai-copilot-oversharing-probe
// ══════════════════════════════════════════════════════════════════════════════

function buildCopilotProbe(): TelemetryEvent[] {
  const cx = "nexacorp" as const;
  const USER = "s.patel@nexacorp.com";
  const USER_KEY = "12d24f71-6b3e-4a95-8c07-f8884f3f373e";
  const ORG = "6d1f9a3e-4b27-4c85-9e10-a7c53f82b9d4";
  const THREAD = "19:Xn3uQZYgZ7f2ue0vp5w9MglEVjFyp5pza1efaC6g2U41@thread.v2";
  const LABEL_HR = "a8f3c6d1-2b47-4e90-9c15-7d0e3b6a4f28";
  const LABEL_FIN = "5e91b7a4-c3d8-4f26-8a70-1b9d4e6c2f35";
  const LABEL_IT = "0c72d5e8-91a3-4b64-a7f0-38e5d1b9c604";

  type Res = { name: string; type: string; label?: string };
  const copilot = (
    id: string, ts: string, jailbreak: boolean, resources: Res[],
    severity: TelemetryEvent["severity"], description: string, mitre?: string, tactic?: string,
  ): TelemetryEvent => {
    const t = Date.parse(ts);
    return {
      id, ts, source: "o365", vendor: "Microsoft Purview", event_type: "cloud_api_call",
      severity, user_email: USER, src_ip: OFFICE_IP,
      ...(mitre ? { mitre_technique: mitre, mitre_tactic: tactic } : {}),
      description,
      raw: {
        "data.office365.Operation": "CopilotInteraction",
        "data.office365.RecordType": "261",
        "data.office365.Workload": "Copilot",
        "data.office365.Id": `${hexOf(`ci:${id}`, 8)}-${hexOf(`cj:${id}`, 4)}-4${hexOf(`ck:${id}`, 3)}-9${hexOf(`cl:${id}`, 3)}-${hexOf(`cm:${id}`, 12)}`,
        "data.office365.CreationTime": ts.replace(/\.\d{3}Z$/, ""),
        "data.office365.OrganizationId": ORG,
        "data.office365.UserId": USER,
        "data.office365.UserKey": USER_KEY,
        "data.office365.UserType": "0",
        "data.office365.ClientIP": OFFICE_IP,
        "data.office365.AppIdentity": "Copilot.MicrosoftCopilot.BizChat",
        "data.office365.CopilotEventData.AppHost": "BizChat",
        "data.office365.CopilotEventData.ThreadId": THREAD,
        "data.office365.CopilotEventData.Messages": [
          { Id: String(t), isPrompt: true, JailbreakDetected: jailbreak },
          { Id: String(t + 1113), isPrompt: false },
        ],
        "data.office365.CopilotEventData.AccessedResources": resources.map(r => ({
          Action: "Read",
          Id: `01${opaque(`res:${r.name}`, 32).toUpperCase()}`,
          Name: r.name,
          Type: r.type,
          ...(r.label ? { SensitivityLabelId: r.label } : {}),
          Status: "success",
        })),
        "data.office365.Version": "1",
        "GeoLocation.country_name": OFFICE_GEO.country,
        "GeoLocation.city_name": OFFICE_GEO.city,
        "GeoLocation.latitude": OFFICE_GEO.latitude,
        "GeoLocation.longitude": OFFICE_GEO.longitude,
        "source.ip": OFFICE_IP,
        "user.email": USER,
        "user.name": "NEXACORP\\s.patel",
        "event.action": "CopilotInteraction",
        "event.type": "access",
        "event.outcome": "success",
        "event.module": "o365",
        "event.dataset": "o365.audit",
        "event.provider": "Copilot",
        "event.created": ingested(ts, 2_840),
        "action_result": "allowed",
      },
    };
  };

  const spOp = (id: string, ts: string, operation: "FileAccessed" | "FileDownloaded", fileName: string, path: string,
    severity: TelemetryEvent["severity"], description: string): TelemetryEvent => ({
    ...m365Operation({
      companyId: cx, id, ts, user: USER, operation, workload: "SharePoint", srcIp: OFFICE_IP,
      fileName, fileExtension: fileName.split(".").pop(), userAgent: EDGE_UA,
      extra: { SourceRelativeUrl: path, ItemType: "File", ...spFileAudit(id, fileName, path, true) },
      mitre: "T1213.002", tactic: "Collection", severity, description,
    }),
    source: "sharepoint" as const,
  });

  return [
    // 1. Baseline — routine Copilot use over the user's own team files.
    copilot("aicop1", "2026-09-23T10:41:22.508Z", false, [
      { name: "Campaign_Calendar_Q4.pptx", type: "pptx" },
      { name: "Brand_Guidelines_2026.pdf", type: "pdf" },
    ], "informational",
    "s.patel used Microsoft 365 Copilot (BizChat) at 10:41 and it read two ordinary team files, a campaign calendar and brand guidelines: no jailbreak flag, no sensitivity labels. This is the account's normal Copilot pattern."),

    // 2. First flagged prompt — detected, nothing retrieved.
    copilot("aicop2", "2026-09-23T13:07:44.121Z", true, [], "medium",
    "A Copilot interaction by s.patel at 13:07 has JailbreakDetected=true on the prompt and no accessed resources. The record holds only message ids and the flag, not the prompt text (ATLAS AML.T0054 LLM Jailbreak, AML.T0051.000 direct prompt injection).",
    "T1213", "Collection"),

    // 3. Second flagged prompt — detected, but three labelled HR files were still read.
    copilot("aicop3", "2026-09-23T13:10:02.774Z", true, [
      { name: "Payroll_Register_Sep2026.xlsx", type: "xlsx", label: LABEL_HR },
      { name: "Exec_Compensation_Bands_2026.xlsx", type: "xlsx", label: LABEL_HR },
      { name: "Salary_Review_Proposals_FY27.xlsx", type: "xlsx", label: LABEL_HR },
    ], "high",
    "A second Copilot interaction at 13:10 again has JailbreakDetected=true, and this time Copilot read three files from the HR library, each carrying the HR sensitivity label a8f3c6d1 (payroll register, executive compensation bands, salary review proposals), all with Status success. The flag is detection, not prevention: the content was still retrieved for a marketing user.",
    "T1213", "Collection"),

    // 4. Reworded prompt — no jailbreak flag, five more labelled HR files.
    copilot("aicop4", "2026-09-23T13:14:37.309Z", false, [
      { name: "Bonus_Pool_Allocation_FY27.xlsx", type: "xlsx", label: LABEL_HR },
      { name: "Severance_Terms_Template.docx", type: "docx", label: LABEL_HR },
      { name: "Headcount_Reduction_Plan_Q1.xlsx", type: "xlsx", label: LABEL_HR },
      { name: "Performance_Ratings_2026.xlsx", type: "xlsx", label: LABEL_HR },
      { name: "Retention_Risk_Register.xlsx", type: "xlsx", label: LABEL_HR },
    ], "high",
    "A Copilot interaction at 13:14 with JailbreakDetected=false read five more HR-labelled files (bonus pool, severance terms, headcount reduction plan, performance ratings, retention risk register), all with Status success. The prompt was apparently reworded after two flagged attempts and, unflagged, retrieved more.",
    "T1213", "Collection"),

    // 5. The user opens one of the surfaced files directly.
    spOp("aicop5", "2026-09-23T13:16:20.481Z", "FileAccessed", "Exec_Compensation_Bands_2026.xlsx",
      "sites/HR-Compensation/Shared Documents/Compensation", "medium",
      "s.patel opened Exec_Compensation_Bands_2026.xlsx directly in the HR-Compensation SharePoint library at 13:16, about six minutes after Copilot first read it. This is a marketing-role account reading an HR compensation file."),

    // 6. Credential-hunting: IT admin library files, flagged again.
    copilot("aicop6", "2026-09-23T13:24:51.036Z", true, [
      { name: "Admin_Handover_Notes.docx", type: "docx", label: LABEL_IT },
      { name: "Break-Glass_Access_Procedure.docx", type: "docx", label: LABEL_IT },
      { name: "Network_Device_Logins_2025.xlsx", type: "xlsx", label: LABEL_IT },
      { name: "Shared_Mailbox_Access_Matrix.xlsx", type: "xlsx", label: LABEL_IT },
    ], "high",
    "A Copilot interaction at 13:24 has JailbreakDetected=true and read four IT-labelled files: admin handover notes, the break-glass access procedure, a network device logins spreadsheet and a shared mailbox access matrix — the kind of documents that hold credentials and privileged-access procedures.",
    "T1552.001", "Credential Access"),

    // 7. Finance / board documents, flagged again.
    copilot("aicop7", "2026-09-23T13:31:08.652Z", true, [
      { name: "Q3_Board_Financials_DRAFT.xlsx", type: "xlsx", label: LABEL_FIN },
      { name: "Acquisition_Target_Shortlist.xlsx", type: "xlsx", label: LABEL_FIN },
      { name: "Treasury_Cash_Positions_Sep.xlsx", type: "xlsx", label: LABEL_FIN },
    ], "high",
    "A fourth flagged Copilot interaction at 13:31 (JailbreakDetected=true) read three Finance-labelled files: draft board financials, an acquisition target shortlist and treasury cash positions. In 23 minutes the account has now pulled HR, IT and Finance content through Copilot.",
    "T1213", "Collection"),

    // 8. UEBA deviation over the whole session.
    {
      id: "aicop8", ts: "2026-09-23T13:36:00.000Z", source: "ueba", vendor: "Microsoft Sentinel UEBA", event_type: "ueba_anomaly",
      severity: "high", user_email: USER, src_ip: OFFICE_IP,
      mitre_technique: "T1213.002", mitre_tactic: "Collection",
      description: "Microsoft Sentinel UEBA flagged s.patel's activity: first-time access to HR, IT and Finance content areas, none of which the account had touched in its lookback window, all reached in one 30-minute burst through Copilot plus a direct SharePoint open and download.",
      // One BehaviorAnalytics-style record (the UEBA table's own shape: a single activity with its
      // insight flags and the user entity), not the Anomalies table's ExtendedProperties bag.
      raw: {
        "Type": "BehaviorAnalytics",
        "TimeGenerated": "2026-09-23T13:36:00.000Z",
        "event.id": guid("aicop8:record"),
        "event.action": "BehaviorAnomalyDetected",
        "event.category": "file",
        "event.type": "access",
        "event.outcome": "alerted",
        "event.provider": "Microsoft Sentinel",
        "event.created": ingested("2026-09-23T13:36:00.000Z", 4_318),
        "entity.type": "user",
        "entity.name": "s.patel",
        "entity.id": USER_KEY,
        "user.name": "NEXACORP\\s.patel",
        "user.email": USER,
        "user.domain": "NEXACORP",
        "user.department": "Marketing",
        "source.ip": OFFICE_IP,
        "source.geo.country_name": OFFICE_GEO.country,
        "source.geo.city_name": OFFICE_GEO.city,
        "application.name": "Microsoft 365 Copilot",
        "FirstTimeUserPerformedAction": "True",
        "ActionUncommonlyPerformedByUser": "True",
        "behavior.name": "Uncommon content access",
        "behavior.category": "Data access",
        "behavior.description": "Copilot read sensitivity-labelled files from HR, IT and Finance libraries never accessed by this user; Copilot prompts with JailbreakDetected=true on four of five interactions in the same hour",
      },
    },

    // 9. Direct download of the salary proposals file.
    spOp("aicop9", "2026-09-23T13:41:18.930Z", "FileDownloaded", "Salary_Review_Proposals_FY27.xlsx",
      "sites/HR-Compensation/Shared Documents/Compensation", "high",
      "s.patel downloaded Salary_Review_Proposals_FY27.xlsx from the HR-Compensation library at 13:41 — a file Copilot had read at 13:10 — ending the session by taking a local copy of the salary data."),
  ];
}

// ══════════════════════════════════════════════════════════════════════════════
// Export
// ══════════════════════════════════════════════════════════════════════════════

export const AI_CORE_STORIES: AiStoryDef[] = [
  {
    id: "ai-helpdesk-voice-reset",
    title: "Help Desk Voice-Clone MFA Reset → New-Device Sign-In → Mailbox Forwarding Rule",
    complexity: "core",
    companies: ["nexacorp", "medcore", "globallogis"],
    events: buildVoiceReset(),
  },
  {
    id: "ai-claude-enterprise-departure",
    title: "Departing Employee — After-Hours Bulk Uploads to Claude Enterprise",
    complexity: "core",
    companies: ["nexacorp", "medcore", "globallogis"],
    events: buildClaudeDeparture(),
  },
  {
    id: "ai-copilot-oversharing-probe",
    title: "Copilot Oversharing Probe — Jailbreak Prompts Pulling HR, IT and Finance Files",
    complexity: "core",
    companies: ["nexacorp", "medcore", "globallogis"],
    events: buildCopilotProbe(),
  },
];
