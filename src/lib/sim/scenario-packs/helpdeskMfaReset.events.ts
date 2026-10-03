/**
 * Events-only half of the ./helpdeskMfaReset.ts scenario pack.
 *
 * The dashboard's live feed runs in the browser (attackStories.ts), so what it
 * imports ships in a public /_next/static chunk. The answer key (questions,
 * answers, explanations, IOCs, killchain, narrative) stays in the builder in
 * ./helpdeskMfaReset.ts, which composes this module on the server. Keep anything
 * answer-bearing out of this file: every visitor can read it.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { entraSignIn, entraAudit } from "@/lib/sim/emitters/entra";
import { serviceNowRecord } from "@/lib/sim/emitters/servicenow";
import { csProcess } from "@/lib/sim/emitters/crowdstrike";
import { sentinelAlert } from "@/lib/sim/emitters/sentinel";

/** Telemetry half of `buildHelpdeskMfaResetScenario`: the events and the story title, no answer key. */
export function helpdeskMfaResetScenarioEvents() {
  const B = new Date("2026-07-14T09:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  const victim = {
    email: "l.ferreira@nexacorp.com",
    display: "Lucia Ferreira",
    id: "e63a9c07-1a4e-4f26-8ac1-6f7ab53e0e97",
    hostname: "LT-OPS-2214",
    deviceId: "c481f0e9-6b3d-4a72-8f15-9e0c2d7a5b31",
    homeIp: "82.132.14.55",
  };

  const helpdesk = {
    email: "j.oduya@nexacorp.com",
    display: "James Oduya",
    id: "a2c8f314-9e46-4b7c-8b1a-30dc6b5e9f22",
    ip: "10.60.4.18",
  };

  const attackerIp = "5.181.234.19";
  const ticket = "INC0048217";

  const vdiHost = { hostname: "VDI-POOL-014", ip: "10.20.60.14" };

  const baselineSessionId1 = "b1e5a4c7-9d2f-4c8b-8a71-3fe0d6c74a12";
  const baselineSessionId2 = "f4a8e2d6-7b39-4c15-9d80-6a2c37f10e93";
  const attackerSessionId = "7c4e1a9d-3f26-4b58-9d70-2a8e5c319f04";

  // EDR↔scenario integration (Phase 4): control-plane-only incident — a
  // social-engineered helpdesk MFA reset, a rogue authenticator registration, and
  // an account-takeover sign-in, all on the identity plane. The single EDR event
  // (evt_hmr_08) is just the benign start of a logon session (userinit.exe →
  // explorer.exe) — no malicious process tree, no Falcon detection — so there is
  // nothing to investigate in the EDR console. edr_scope "non_edr"; no is_detection
  // (no EDR detections); edr_scope goes on the identity detection that opens the
  // ticket — the new-geo, unmanaged-device sign-in on the reset account.
  const INCIDENT = "inc:hmr:1";

  const cx = "nexacorp" as const;
  const pwPush = (t: string) => [
    { authenticationStepDateTime: t, authenticationMethod: "Password", authenticationMethodDetail: "Password in the cloud", succeeded: true, authenticationStepResultDetail: "Correct password", authenticationStepRequirement: "Primary authentication" },
    { authenticationStepDateTime: t, authenticationMethod: "Mobile app notification", authenticationMethodDetail: "Microsoft Authenticator", succeeded: true, authenticationStepResultDetail: "MFA completed in Azure AD", authenticationStepRequirement: "Multifactor authentication" },
  ];

  const events: TelemetryEvent[] = [
    // 1. BASELINE — an ordinary morning sign-in.
    { ...entraSignIn({
      companyId: cx, id: "evt_hmr_01_baseline_signin", ts: T(0), srcIp: victim.homeIp, user: victim.email, displayName: victim.display,
      userTitle: "Trade Settlements Analyst", userId: victim.id, correlationId: "5b2d7e4a-8c31-4b0d-9f5a-1c37a0e59d84", sessionId: baselineSessionId1,
      app: "Microsoft Office", appId: "d3590ed6-52b3-4102-aeff-aad2292ab01c", resource: "Microsoft Graph", mfa: true, isInteractive: true,
      managed: true, compliant: true, deviceId: victim.deviceId, deviceName: victim.hostname, os: "Windows 11", browser: "Edge 125.0.2535",
      trustType: "Azure AD joined", userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.2535.51", asn: 5378, tokenIssuerType: "AzureAD", incomingTokenType: "none",
      riskLevel: "none", riskDetail: "none", riskEventTypes: [], conditionalAccess: "success",
      geo: { country: "United Kingdom", city: "London", latitude: 51.5074, longitude: -0.1278 }, severity: "informational",
      extra: { "azure.signinlogs.properties.location.state": "England", "azure.signinlogs.properties.authenticationDetails": pwPush(T(0)) },
      description: "l.ferreira signed in to Microsoft Office at 09:00 from her usual London address on the corporate laptop LT-OPS-2214, MFA completed by an Authenticator push.",
    }), is_baseline: true },

    // 2. THE CALL — a ticket that looks like every other MFA-reset call.
    serviceNowRecord({
      companyId: cx, id: "evt_hmr_02_ticket_created", ts: T(41 * MIN), table: "incident", number: ticket, state: "New",
      shortDescription: "Locked out — lost phone, needs password and MFA reset", callerId: victim.email,
      mitre: "T1656", tactic: "Defense Evasion", severity: "low",
      extra: {
        "servicenow.description": "Caller states she is locked out of her account and lost the mobile device used for Microsoft Authenticator. Requesting password reset and MFA re-registration to regain access before the EOD trading window.",
        "servicenow.category": "Access", "servicenow.subcategory": "Password Reset", "servicenow.contact_type": "Phone",
        "servicenow.priority": "3 - Moderate", "servicenow.urgency": "2 - High", "servicenow.impact": "3 - Low",
        "servicenow.opened_by": helpdesk.email, "servicenow.assignment_group": "IT Service Desk", "servicenow.assigned_to": helpdesk.email,
        "servicenow.opened_at": "2026-07-14 09:41:00", "servicenow.u_identity_verification": "Employee ID and date of birth confirmed over the phone",
        "servicenow.u_verification_result": "Passed", "servicenow.sys_created_on": "2026-07-14 09:41:00",
      },
      description: "Ticket INC0048217 was opened by the IT Service Desk: caller reports being locked out and having lost the mobile device enrolled for Microsoft Authenticator, requesting a password and MFA reset.",
    }),

    // 3. The real employee, still working — the impossible-coexistence tell.
    { ...entraSignIn({
      companyId: cx, id: "evt_hmr_03_second_baseline_signin", ts: T(45 * MIN), srcIp: victim.homeIp, user: victim.email, displayName: victim.display,
      userTitle: "Trade Settlements Analyst", userId: victim.id, correlationId: "d3f7c9a1-4b8e-40d2-9c6a-71f3b28e5c40", sessionId: baselineSessionId2,
      app: "SharePoint Online", appId: "00000003-0000-0ff1-ce00-000000000000", resource: "Office 365 SharePoint Online", mfa: true, isInteractive: true,
      managed: true, compliant: true, deviceId: victim.deviceId, deviceName: victim.hostname, os: "Windows 11", browser: "Edge 125.0.2535",
      trustType: "Azure AD joined", userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.2535.51", asn: 5378, tokenIssuerType: "AzureAD", incomingTokenType: "none",
      riskLevel: "none", riskDetail: "none", conditionalAccess: "success",
      geo: { country: "United Kingdom", city: "London", latitude: 51.5074, longitude: -0.1278 }, severity: "informational",
      extra: { "azure.signinlogs.properties.location.state": "England", "azure.signinlogs.properties.authenticationDetails": pwPush(T(45 * MIN)) },
      description: "l.ferreira signed in to SharePoint Online at 09:45 from the same London address and the same laptop, MFA completed by an Authenticator push — seven minutes before the ticket taken on her behalf is resolved.",
    }), is_baseline: true },

    // 4. Ticket resolved — routine close, on its face.
    serviceNowRecord({
      companyId: cx, id: "evt_hmr_04_ticket_resolved", ts: T(52 * MIN), table: "incident", number: ticket, state: "Resolved",
      callerId: victim.email, severity: "low",
      extra: {
        "servicenow.close_code": "Solved (Permanently)",
        "servicenow.close_notes": "Password reset via admin portal. MFA requirement cleared for re-registration per caller's report of a lost device. Caller instructed to re-enroll Microsoft Authenticator on next sign-in.",
        "servicenow.work_notes": "Caller verified by phone with employee ID and date of birth; no video verification performed.",
        "servicenow.resolved_by": helpdesk.email, "servicenow.resolved_at": "2026-07-14 09:52:00",
        "servicenow.assignment_group": "IT Service Desk", "servicenow.assigned_to": helpdesk.email, "servicenow.sys_updated_on": "2026-07-14 09:52:00",
      },
      description: "Ticket INC0048217 was resolved by James Oduya: password reset via the admin portal, MFA requirement cleared per the caller's report of a lost device, caller instructed to re-register Microsoft Authenticator on next sign-in.",
    }),

    // 5. The MFA reset lands in the directory (T1556.006).
    entraAudit({
      companyId: cx, id: "evt_hmr_05_mfa_reset", ts: T(53 * MIN), operationName: "Update user", loggedByService: "Core Directory",
      result: "success", resultReason: "Authentication methods reset by administrator", correlationId: "c7e29a4d-1f8b-4306-9a52-3d7e08c4f1a6",
      initiatedByUpn: helpdesk.email, initiatedById: helpdesk.id, initiatedByIp: helpdesk.ip, initiatedByRoles: ["Helpdesk Administrator"],
      targetUpn: victim.email, targetId: victim.id, mitre: "T1556.006", tactic: "Defense Evasion", severity: "medium",
      extra: {
        "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].displayName": "StrongAuthenticationMethod",
        "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].oldValue": "[{\"MethodType\":\"PhoneAppNotification\",\"Default\":true}]",
        "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].newValue": "[]",
      },
      description: "James Oduya (Helpdesk Administrator) cleared l.ferreira's registered authentication methods from the internal help desk network, one minute after the ticket was closed.",
    }),

    // 6. A NEW authenticator is registered — but from the attacker's address (T1098.005).
    entraAudit({
      companyId: cx, id: "evt_hmr_06_new_device_registered", ts: T(58 * MIN), operationName: "User registered security info",
      loggedByService: "Authentication Methods", result: "success", resultReason: "User registered security info: Microsoft Authenticator app",
      correlationId: "9a1d3f6e-52c8-4b70-8e94-1f6b0a7c3d58", initiatedByUpn: victim.email, initiatedById: victim.id, initiatedByIp: attackerIp, initiatedByRoles: [],
      targetUpn: victim.email, targetId: victim.id, geo: { country: "Netherlands", city: "Amsterdam", latitude: 52.3702, longitude: 4.8952 },
      mitre: "T1098.005", tactic: "Persistence", severity: "high",
      extra: {
        "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].displayName": "StrongAuthenticationMethod",
        "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].oldValue": "[]",
        "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].newValue": "[{\"MethodType\":\"PhoneAppNotification\",\"Default\":true}]",
      },
      description: "A new Microsoft Authenticator app was registered as l.ferreira's security info five minutes after the reset — the initiating identity is l.ferreira, but the IP address is 5.181.234.19 in Amsterdam, not the address recorded on either of her sign-ins this morning.",
    }),

    // 7. The sign-in — MFA genuinely satisfied, on the attacker's phone (T1078.004).
    {
      ...entraSignIn({
        companyId: cx, id: "evt_hmr_07_new_geo_signin", ts: T(61 * MIN), srcIp: attackerIp, user: victim.email, displayName: victim.display,
        userTitle: "Trade Settlements Analyst", userId: victim.id, correlationId: "2f8a6d31-9c47-4e05-8b19-5d3a70c1e894", sessionId: attackerSessionId,
        app: "Office 365 Exchange Online", appId: "00000002-0000-0ff1-ce00-000000000000", resource: "Office 365 Exchange Online", mfa: true, isInteractive: true,
        managed: false, compliant: false, deviceId: "", os: "Windows 10", browser: "Chrome 124.0.0", userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36", asn: 60068,
        tokenIssuerType: "AzureAD", incomingTokenType: "none", riskLevel: "none", riskDetail: "none", riskEventTypes: [], conditionalAccess: "success",
        geo: { country: "Netherlands", city: "Amsterdam", latitude: 52.3702, longitude: 4.8952 }, severity: "critical",
        mitre: "T1078.004", tactic: "Initial Access",
        extra: { "azure.signinlogs.properties.location.state": "North Holland", "azure.signinlogs.properties.authenticationDetails": pwPush(T(61 * MIN)) },
        description: "l.ferreira's account signed in to Office 365 Exchange Online at 10:01 from 5.181.234.19 in Amsterdam, on an unmanaged Windows 10 / Chrome device. Password and MFA both completed successfully.",
      }),
      edr_scope: "non_edr",
    },

    // 7b. The page: a Sentinel analytic correlating the method wipe, the re-registration and the new-country sign-in.
    {
      ...sentinelAlert({
        companyId: cx, id: "evt_hmr_07b_sentinel_alert", ts: T(62 * MIN), user: victim.email, srcIp: attackerIp,
        alertName: "Authentication methods reset followed by a sign-in from a new country",
        severity: "high", eventType: "risk_score_change", mitre: "T1098.005", tactic: "Persistence",
        extendedProperties: { "Methods Cleared By": "Helpdesk Administrator", "Minutes Reset To Sign-in": 10, "Sign-in Country": "NL", "Device Compliance": "unmanaged" },
        description: `Sentinel raised a High alert for ${victim.email.split("@")[0]}: authentication methods cleared by the help desk, a new Authenticator registered, then a sign-in from ${attackerIp} in a country not seen for this account.`,
      }),
      is_detection: true,
    },

    // 8. The session lands on an internal VDI host (benign logon start).
    csProcess({
      companyId: cx, id: "evt_hmr_08_vdi_session", ts: T(66 * MIN), host: vdiHost.hostname, srcIp: vdiHost.ip, user: victim.email,
      processName: "explorer.exe", processPath: "C:\\Windows\\explorer.exe", cmdline: "C:\\Windows\\explorer.exe",
      parentName: "userinit.exe", parentPid: 3312, pid: 4488, integrity: "medium", severity: "high",
      description: "Five minutes after the Amsterdam sign-in, a new interactive session started on VDI-POOL-014 under l.ferreira's account — userinit.exe launched explorer.exe, the standard start of a fresh logon session.",
    }),
  ];

  // Every event belongs to the one helpdesk-MFA-reset account-takeover incident
  // (correlation key; also lets the EDR console associate the identity-plane case).
  for (const e of events) e.incident_id = INCIDENT;

  return { title: "Help Desk MFA Reset — Social Engineering Account Takeover", events, T, MIN, victim, attackerIp, vdiHost };
}
