/**
 * Scenario pack: "Help Desk MFA Reset — Social Engineering Account Takeover"
 *
 * CORE tier. The Scattered-Spider-style help-desk social-engineering pattern
 * behind the largest 2023-2025 identity breaches. No malware, no exploit —
 * a phone call.
 *
 * An attacker calls the IT help desk impersonating a real employee (T1656),
 * convinces the agent to reset her password and clear her MFA. The ticket is
 * opened and resolved like any other MFA-reset call — because on its face it
 * is one; NexaCorp's help desk handles several of these a week. Within
 * minutes a NEW Microsoft Authenticator is registered on the account
 * (T1098.005) and a genuinely-MFA-satisfied sign-in arrives from a new IP and
 * a new country (T1078.004) — while the real employee's own session, opened
 * earlier the same morning from her own laptop, is still live.
 *
 * The teaching point is deliberately uncomfortable: nothing in any single
 * record is malicious. The ticket looks like routine support. The reset
 * looks like routine administration. The new sign-in genuinely completes
 * password + MFA, because the attacker now holds a working second factor.
 * Entra's own risk engine has nothing to key on. The only thing that gives
 * this away is the SEQUENCE — ticket, reset, new device, new geo, all inside
 * nineteen minutes — compared against the plain fact that the account's
 * legitimate owner was demonstrably still working from London ten minutes
 * before the reset even started.
 *
 * Covers T1656 (Impersonation), T1556.006 (Modify Authentication Process:
 * Multi-Factor Authentication), T1098.005 (Account Manipulation: Device
 * Registration) and T1078.004 (Valid Accounts: Cloud Accounts) — an
 * identity-help-desk-abuse case the live feed did not previously have.
 *
 * NOTE: register in scenarios.ts with difficulty "core" (ScenarioBundle
 * itself carries no difficulty field). Company allowlist: nexacorp, medcore,
 * globallogis — the three profiles running Microsoft 365 / Entra ID.
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";

export function buildHelpdeskMfaResetScenario(
  scenarioId = "helpdesk-mfa-reset-2026",
): ScenarioBundle {
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

  const attackerIp = "185.220.101.47";
  const ticket = "INC0048217";

  const vdiHost = { hostname: "VDI-POOL-014", ip: "10.20.60.14" };

  const baselineSessionId1 = "b1e5a4c7-9d2f-4c8b-8a71-3fe0d6c74a12";
  const baselineSessionId2 = "f4a8e2d6-7b39-4c15-9d80-6a2c37f10e93";
  const attackerSessionId = "7c4e1a9d-3f26-4b58-9d70-2a8e5c319f04";

  const events: TelemetryEvent[] = [
    // ---------------------------------------------------------------------
    // 1. BASELINE — a completely ordinary morning sign-in.
    // ---------------------------------------------------------------------
    {
      id: "evt_hmr_01_baseline_signin",
      ts: T(0),
      source: "o365",
      vendor: "Microsoft Entra ID",
      event_type: "auth_success",
      severity: "informational",
      user_email: victim.email,
      user_title: "Trade Settlements Analyst",
      hostname: victim.hostname,
      src_ip: victim.homeIp,
      geo: { country: "United Kingdom", city: "London", latitude: 51.5074, longitude: -0.1278 },
      authentication: { method: "Password + Microsoft Authenticator", mfa_type: "push", result: "success" },
      description:
        "l.ferreira signed in to Microsoft Office at 09:00 from her usual London address on the corporate laptop LT-OPS-2214, MFA completed by an Authenticator push.",
      raw: {
        "azure.signinlogs.category": "SignInLogs",
        "azure.signinlogs.operationName": "Sign-in activity",
        "azure.signinlogs.properties.id": "5b2d7e4a-8c31-4b0d-9f5a-1c37a0e59d84",
        "azure.signinlogs.properties.createdDateTime": T(0),
        "azure.signinlogs.properties.userPrincipalName": victim.email,
        "azure.signinlogs.properties.userDisplayName": victim.display,
        "azure.signinlogs.properties.userId": victim.id,
        "azure.signinlogs.properties.correlationId": "5b2d7e4a-8c31-4b0d-9f5a-1c37a0e59d84",
        "azure.signinlogs.properties.sessionId": baselineSessionId1,
        "azure.signinlogs.properties.appDisplayName": "Microsoft Office",
        "azure.signinlogs.properties.appId": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        "azure.signinlogs.properties.resourceDisplayName": "Microsoft Graph",
        "azure.signinlogs.properties.clientAppUsed": "Browser",
        "azure.signinlogs.properties.isInteractive": true,
        "azure.signinlogs.properties.ipAddress": victim.homeIp,
        "azure.signinlogs.properties.autonomousSystemNumber": 5378,
        "azure.signinlogs.properties.location.city": "London",
        "azure.signinlogs.properties.location.state": "England",
        "azure.signinlogs.properties.location.countryOrRegion": "GB",
        "azure.signinlogs.properties.location.geoCoordinates.latitude": 51.5074,
        "azure.signinlogs.properties.location.geoCoordinates.longitude": -0.1278,
        "azure.signinlogs.properties.deviceDetail.deviceId": victim.deviceId,
        "azure.signinlogs.properties.deviceDetail.displayName": victim.hostname,
        "azure.signinlogs.properties.deviceDetail.operatingSystem": "Windows 11",
        "azure.signinlogs.properties.deviceDetail.browser": "Edge 125.0.2535",
        "azure.signinlogs.properties.deviceDetail.isCompliant": true,
        "azure.signinlogs.properties.deviceDetail.isManaged": true,
        "azure.signinlogs.properties.deviceDetail.trustType": "Azure AD joined",
        "azure.signinlogs.properties.userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.2535.51",
        "azure.signinlogs.properties.authenticationRequirement": "multiFactorAuthentication",
        "azure.signinlogs.properties.authenticationDetails": [
          {
            authenticationStepDateTime: T(0),
            authenticationMethod: "Password",
            authenticationMethodDetail: "Password in the cloud",
            succeeded: true,
            authenticationStepResultDetail: "Correct password",
            authenticationStepRequirement: "Primary authentication",
          },
          {
            authenticationStepDateTime: T(0),
            authenticationMethod: "Mobile app notification",
            authenticationMethodDetail: "Microsoft Authenticator",
            succeeded: true,
            authenticationStepResultDetail: "MFA completed in Azure AD",
            authenticationStepRequirement: "Multifactor authentication",
          },
        ],
        "azure.signinlogs.properties.conditionalAccessStatus": "success",
        "azure.signinlogs.properties.riskLevelDuringSignIn": "none",
        "azure.signinlogs.properties.riskState": "none",
        "azure.signinlogs.properties.riskEventTypes_v2": [],
        "azure.signinlogs.properties.tokenIssuerType": "AzureAD",
        "azure.signinlogs.properties.incomingTokenType": "none",
        "azure.signinlogs.properties.status.errorCode": 0,
        "azure.signinlogs.resultType": "0",
      },
    },

    // ---------------------------------------------------------------------
    // 2. The call. A ticket that looks like every other MFA-reset call.
    // ---------------------------------------------------------------------
    {
      id: "evt_hmr_02_ticket_created",
      ts: T(41 * MIN),
      source: "soar",
      vendor: "ServiceNow ITSM",
      event_type: "policy_modification",
      severity: "low",
      mitre_technique: "T1656",
      mitre_tactic: "Defense Evasion",
      user_email: victim.email,
      description:
        "Ticket INC0048217 was opened by the IT Service Desk: caller reports being locked out and having lost the mobile device enrolled for Microsoft Authenticator, requesting a password and MFA reset.",
      raw: {
        "servicenow.table": "incident",
        "servicenow.number": ticket,
        "servicenow.short_description": "Locked out — lost phone, needs password and MFA reset",
        "servicenow.description":
          "Caller states she is locked out of her account and lost the mobile device used for Microsoft Authenticator. Requesting password reset and MFA re-registration to regain access before the EOD trading window.",
        "servicenow.category": "Access",
        "servicenow.subcategory": "Password Reset",
        "servicenow.contact_type": "Phone",
        "servicenow.priority": "3 - Moderate",
        "servicenow.urgency": "2 - High",
        "servicenow.impact": "3 - Low",
        "servicenow.state": "New",
        "servicenow.caller_id": victim.email,
        "servicenow.opened_by": helpdesk.email,
        "servicenow.assignment_group": "IT Service Desk",
        "servicenow.assigned_to": helpdesk.email,
        "servicenow.opened_at": "2026-07-14 09:41:00",
        "servicenow.u_identity_verification": "Employee ID and date of birth confirmed over the phone",
        "servicenow.u_verification_result": "Passed",
        "servicenow.sys_created_on": "2026-07-14 09:41:00",
      },
    },

    // ---------------------------------------------------------------------
    // 3. The real employee, still working — the impossible-coexistence tell.
    // ---------------------------------------------------------------------
    {
      id: "evt_hmr_03_second_baseline_signin",
      ts: T(45 * MIN),
      source: "o365",
      vendor: "Microsoft Entra ID",
      event_type: "auth_success",
      severity: "informational",
      user_email: victim.email,
      user_title: "Trade Settlements Analyst",
      hostname: victim.hostname,
      src_ip: victim.homeIp,
      geo: { country: "United Kingdom", city: "London", latitude: 51.5074, longitude: -0.1278 },
      authentication: { method: "Password + Microsoft Authenticator", mfa_type: "push", result: "success" },
      description:
        "l.ferreira signed in to SharePoint Online at 09:45 from the same London address and the same laptop, MFA completed by an Authenticator push — seven minutes before the ticket taken on her behalf is resolved.",
      raw: {
        "azure.signinlogs.category": "SignInLogs",
        "azure.signinlogs.operationName": "Sign-in activity",
        "azure.signinlogs.properties.id": "d3f7c9a1-4b8e-40d2-9c6a-71f3b28e5c40",
        "azure.signinlogs.properties.createdDateTime": T(45 * MIN),
        "azure.signinlogs.properties.userPrincipalName": victim.email,
        "azure.signinlogs.properties.userDisplayName": victim.display,
        "azure.signinlogs.properties.userId": victim.id,
        "azure.signinlogs.properties.correlationId": "d3f7c9a1-4b8e-40d2-9c6a-71f3b28e5c40",
        "azure.signinlogs.properties.sessionId": baselineSessionId2,
        "azure.signinlogs.properties.appDisplayName": "SharePoint Online",
        "azure.signinlogs.properties.appId": "00000003-0000-0ff1-ce00-000000000000",
        "azure.signinlogs.properties.resourceDisplayName": "Office 365 SharePoint Online",
        "azure.signinlogs.properties.clientAppUsed": "Browser",
        "azure.signinlogs.properties.isInteractive": true,
        "azure.signinlogs.properties.ipAddress": victim.homeIp,
        "azure.signinlogs.properties.autonomousSystemNumber": 5378,
        "azure.signinlogs.properties.location.city": "London",
        "azure.signinlogs.properties.location.state": "England",
        "azure.signinlogs.properties.location.countryOrRegion": "GB",
        "azure.signinlogs.properties.location.geoCoordinates.latitude": 51.5074,
        "azure.signinlogs.properties.location.geoCoordinates.longitude": -0.1278,
        "azure.signinlogs.properties.deviceDetail.deviceId": victim.deviceId,
        "azure.signinlogs.properties.deviceDetail.displayName": victim.hostname,
        "azure.signinlogs.properties.deviceDetail.operatingSystem": "Windows 11",
        "azure.signinlogs.properties.deviceDetail.browser": "Edge 125.0.2535",
        "azure.signinlogs.properties.deviceDetail.isCompliant": true,
        "azure.signinlogs.properties.deviceDetail.isManaged": true,
        "azure.signinlogs.properties.deviceDetail.trustType": "Azure AD joined",
        "azure.signinlogs.properties.userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.2535.51",
        "azure.signinlogs.properties.authenticationRequirement": "multiFactorAuthentication",
        "azure.signinlogs.properties.authenticationDetails": [
          {
            authenticationStepDateTime: T(45 * MIN),
            authenticationMethod: "Password",
            authenticationMethodDetail: "Password in the cloud",
            succeeded: true,
            authenticationStepResultDetail: "Correct password",
            authenticationStepRequirement: "Primary authentication",
          },
          {
            authenticationStepDateTime: T(45 * MIN),
            authenticationMethod: "Mobile app notification",
            authenticationMethodDetail: "Microsoft Authenticator",
            succeeded: true,
            authenticationStepResultDetail: "MFA completed in Azure AD",
            authenticationStepRequirement: "Multifactor authentication",
          },
        ],
        "azure.signinlogs.properties.conditionalAccessStatus": "success",
        "azure.signinlogs.properties.riskLevelDuringSignIn": "none",
        "azure.signinlogs.properties.riskState": "none",
        "azure.signinlogs.properties.tokenIssuerType": "AzureAD",
        "azure.signinlogs.properties.incomingTokenType": "none",
        "azure.signinlogs.properties.status.errorCode": 0,
        "azure.signinlogs.resultType": "0",
      },
    },

    // ---------------------------------------------------------------------
    // 4. Ticket resolved — routine close, on its face.
    // ---------------------------------------------------------------------
    {
      id: "evt_hmr_04_ticket_resolved",
      ts: T(52 * MIN),
      source: "soar",
      vendor: "ServiceNow ITSM",
      event_type: "policy_modification",
      severity: "low",
      user_email: victim.email,
      description:
        "Ticket INC0048217 was resolved by James Oduya: password reset via the admin portal, MFA requirement cleared per the caller's report of a lost device, caller instructed to re-register Microsoft Authenticator on next sign-in.",
      raw: {
        "servicenow.table": "incident",
        "servicenow.number": ticket,
        "servicenow.state": "Resolved",
        "servicenow.close_code": "Solved (Permanently)",
        "servicenow.close_notes":
          "Password reset via admin portal. MFA requirement cleared for re-registration per caller's report of a lost device. Caller instructed to re-enroll Microsoft Authenticator on next sign-in.",
        "servicenow.work_notes": "Caller verified by phone with employee ID and date of birth; no video verification performed.",
        "servicenow.resolved_by": helpdesk.email,
        "servicenow.resolved_at": "2026-07-14 09:52:00",
        "servicenow.assignment_group": "IT Service Desk",
        "servicenow.assigned_to": helpdesk.email,
        "servicenow.sys_updated_on": "2026-07-14 09:52:00",
      },
    },

    // ---------------------------------------------------------------------
    // 5. The MFA reset actually lands in the directory.
    // ---------------------------------------------------------------------
    {
      id: "evt_hmr_05_mfa_reset",
      ts: T(53 * MIN),
      source: "o365",
      vendor: "Microsoft Entra ID",
      event_type: "account_modify",
      severity: "medium",
      mitre_technique: "T1556.006",
      mitre_tactic: "Defense Evasion",
      user_email: victim.email,
      src_ip: helpdesk.ip,
      description:
        "James Oduya (Helpdesk Administrator) cleared l.ferreira's registered authentication methods from the internal help desk network, one minute after the ticket was closed.",
      raw: {
        "azure.auditlogs.category": "AuditLogs",
        "azure.auditlogs.operationName": "Update user",
        "azure.auditlogs.properties.activityDisplayName": "Update user",
        "azure.auditlogs.properties.activityDateTime": T(53 * MIN),
        "azure.auditlogs.properties.category": "UserManagement",
        "azure.auditlogs.properties.loggedByService": "Core Directory",
        "azure.auditlogs.properties.operationType": "Update",
        "azure.auditlogs.properties.result": "success",
        "azure.auditlogs.properties.resultReason": "Authentication methods reset by administrator",
        "azure.auditlogs.properties.correlationId": "c7e29a4d-1f8b-4306-9a52-3d7e08c4f1a6",
        "azure.auditlogs.properties.initiatedBy.user.userPrincipalName": helpdesk.email,
        "azure.auditlogs.properties.initiatedBy.user.id": helpdesk.id,
        "azure.auditlogs.properties.initiatedBy.user.ipAddress": helpdesk.ip,
        "azure.auditlogs.properties.initiatedBy.user.roles": ["Helpdesk Administrator"],
        "azure.auditlogs.properties.targetResources[0].type": "User",
        "azure.auditlogs.properties.targetResources[0].userPrincipalName": victim.email,
        "azure.auditlogs.properties.targetResources[0].id": victim.id,
        "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].displayName": "StrongAuthenticationMethod",
        "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].oldValue":
          "[{\"MethodType\":\"PhoneAppNotification\",\"Default\":true}]",
        "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].newValue": "[]",
        "source.ip": helpdesk.ip,
      },
    },

    // ---------------------------------------------------------------------
    // 6. A NEW authenticator is registered — but from where?
    // ---------------------------------------------------------------------
    {
      id: "evt_hmr_06_new_device_registered",
      ts: T(58 * MIN),
      source: "o365",
      vendor: "Microsoft Entra ID",
      event_type: "account_modify",
      severity: "high",
      mitre_technique: "T1098.005",
      mitre_tactic: "Persistence",
      user_email: victim.email,
      src_ip: attackerIp,
      geo: { country: "Netherlands", city: "Amsterdam", latitude: 52.3702, longitude: 4.8952 },
      description:
        "A new Microsoft Authenticator app was registered as l.ferreira's security info five minutes after the reset — the initiating identity is l.ferreira, but the IP address is 185.220.101.47 in Amsterdam, not the address recorded on either of her sign-ins this morning.",
      raw: {
        "azure.auditlogs.category": "AuditLogs",
        "azure.auditlogs.operationName": "User registered security info",
        "azure.auditlogs.properties.activityDisplayName": "User registered security info",
        "azure.auditlogs.properties.activityDateTime": T(58 * MIN),
        "azure.auditlogs.properties.category": "UserManagement",
        "azure.auditlogs.properties.loggedByService": "Authentication Methods",
        "azure.auditlogs.properties.operationType": "Update",
        "azure.auditlogs.properties.result": "success",
        "azure.auditlogs.properties.resultReason": "User registered security info: Microsoft Authenticator app",
        "azure.auditlogs.properties.correlationId": "9a1d3f6e-52c8-4b70-8e94-1f6b0a7c3d58",
        "azure.auditlogs.properties.initiatedBy.user.userPrincipalName": victim.email,
        "azure.auditlogs.properties.initiatedBy.user.id": victim.id,
        "azure.auditlogs.properties.initiatedBy.user.ipAddress": attackerIp,
        "azure.auditlogs.properties.initiatedBy.user.roles": [],
        "azure.auditlogs.properties.targetResources[0].type": "User",
        "azure.auditlogs.properties.targetResources[0].userPrincipalName": victim.email,
        "azure.auditlogs.properties.targetResources[0].id": victim.id,
        "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].displayName": "StrongAuthenticationMethod",
        "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].oldValue": "[]",
        "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].newValue":
          "[{\"MethodType\":\"PhoneAppNotification\",\"Default\":true}]",
        "source.ip": attackerIp,
      },
    },

    // ---------------------------------------------------------------------
    // 7. The sign-in. MFA genuinely satisfied — on the attacker's own phone.
    // ---------------------------------------------------------------------
    {
      id: "evt_hmr_07_new_geo_signin",
      ts: T(61 * MIN),
      source: "o365",
      vendor: "Microsoft Entra ID",
      event_type: "auth_success",
      severity: "critical",
      mitre_technique: "T1078.004",
      mitre_tactic: "Initial Access",
      user_email: victim.email,
      user_title: "Trade Settlements Analyst",
      src_ip: attackerIp,
      geo: { country: "Netherlands", city: "Amsterdam", latitude: 52.3702, longitude: 4.8952 },
      authentication: { method: "Password + Microsoft Authenticator", mfa_type: "push", result: "success" },
      description:
        "l.ferreira's account signed in to Office 365 Exchange Online at 10:01 from 185.220.101.47 in Amsterdam, on an unmanaged Windows 10 / Chrome device. Password and MFA both completed successfully.",
      raw: {
        "azure.signinlogs.category": "SignInLogs",
        "azure.signinlogs.operationName": "Sign-in activity",
        "azure.signinlogs.properties.id": "2f8a6d31-9c47-4e05-8b19-5d3a70c1e894",
        "azure.signinlogs.properties.createdDateTime": T(61 * MIN),
        "azure.signinlogs.properties.userPrincipalName": victim.email,
        "azure.signinlogs.properties.userDisplayName": victim.display,
        "azure.signinlogs.properties.userId": victim.id,
        "azure.signinlogs.properties.correlationId": "2f8a6d31-9c47-4e05-8b19-5d3a70c1e894",
        "azure.signinlogs.properties.sessionId": attackerSessionId,
        "azure.signinlogs.properties.appDisplayName": "Office 365 Exchange Online",
        "azure.signinlogs.properties.appId": "00000002-0000-0ff1-ce00-000000000000",
        "azure.signinlogs.properties.resourceDisplayName": "Office 365 Exchange Online",
        "azure.signinlogs.properties.clientAppUsed": "Browser",
        "azure.signinlogs.properties.isInteractive": true,
        "azure.signinlogs.properties.ipAddress": attackerIp,
        "azure.signinlogs.properties.autonomousSystemNumber": 60068,
        "azure.signinlogs.properties.location.city": "Amsterdam",
        "azure.signinlogs.properties.location.state": "North Holland",
        "azure.signinlogs.properties.location.countryOrRegion": "NL",
        "azure.signinlogs.properties.location.geoCoordinates.latitude": 52.3702,
        "azure.signinlogs.properties.location.geoCoordinates.longitude": 4.8952,
        "azure.signinlogs.properties.deviceDetail.deviceId": "",
        "azure.signinlogs.properties.deviceDetail.displayName": "",
        "azure.signinlogs.properties.deviceDetail.operatingSystem": "Windows 10",
        "azure.signinlogs.properties.deviceDetail.browser": "Chrome 124.0.0",
        "azure.signinlogs.properties.deviceDetail.isCompliant": false,
        "azure.signinlogs.properties.deviceDetail.isManaged": false,
        "azure.signinlogs.properties.deviceDetail.trustType": "",
        "azure.signinlogs.properties.userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "azure.signinlogs.properties.authenticationRequirement": "multiFactorAuthentication",
        "azure.signinlogs.properties.authenticationDetails": [
          {
            authenticationStepDateTime: T(61 * MIN),
            authenticationMethod: "Password",
            authenticationMethodDetail: "Password in the cloud",
            succeeded: true,
            authenticationStepResultDetail: "Correct password",
            authenticationStepRequirement: "Primary authentication",
          },
          {
            authenticationStepDateTime: T(61 * MIN),
            authenticationMethod: "Mobile app notification",
            authenticationMethodDetail: "Microsoft Authenticator",
            succeeded: true,
            authenticationStepResultDetail: "MFA completed in Azure AD",
            authenticationStepRequirement: "Multifactor authentication",
          },
        ],
        "azure.signinlogs.properties.conditionalAccessStatus": "success",
        "azure.signinlogs.properties.riskLevelDuringSignIn": "none",
        "azure.signinlogs.properties.riskState": "none",
        "azure.signinlogs.properties.riskEventTypes_v2": [],
        "azure.signinlogs.properties.tokenIssuerType": "AzureAD",
        "azure.signinlogs.properties.incomingTokenType": "none",
        "azure.signinlogs.properties.status.errorCode": 0,
        "azure.signinlogs.resultType": "0",
      },
    },

    // ---------------------------------------------------------------------
    // 8. The session lands on an internal VDI host.
    // ---------------------------------------------------------------------
    {
      id: "evt_hmr_08_vdi_session",
      ts: T(66 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      severity: "high",
      hostname: vdiHost.hostname,
      user_email: victim.email,
      src_ip: vdiHost.ip,
      description:
        "Five minutes after the Amsterdam sign-in, a new interactive session started on VDI-POOL-014 under l.ferreira's account — userinit.exe launched explorer.exe, the standard start of a fresh logon session.",
      process: {
        name: "explorer.exe",
        pid: 4488,
        path: "C:\\Windows\\explorer.exe",
        parent_name: "userinit.exe",
        parent_pid: 3312,
        cmdline: "C:\\Windows\\explorer.exe",
        user: "NEXACORP\\l.ferreira",
        integrity: "medium",
      },
      raw: {
        "crowdstrike.event_simpleName": "ProcessRollup2",
        "crowdstrike.sensor.id": "d92f5e1b7c3a4680b2ce6f9a1d0873e5",
        "crowdstrike.network_containment_state": "Not Contained",
        "event.action": "process_created",
        "process.name": "explorer.exe",
        "process.pid": "4488",
        "process.executable": "C:\\Windows\\explorer.exe",
        "process.command_line": "C:\\Windows\\explorer.exe",
        "process.parent.name": "userinit.exe",
        "process.parent.pid": "3312",
        "user.name": "NEXACORP\\l.ferreira",
        "host.name": vdiHost.hostname,
        "host.ip": vdiHost.ip,
      },
    },
  ];

  const iocs: IOC[] = [
    {
      type: "ip",
      value: attackerIp,
      first_seen: T(58 * MIN),
      last_seen: T(61 * MIN),
      reputation: "malicious",
      tags: ["hosting-provider", "asn-60068", "amsterdam", "new-mfa-device"],
    },
    {
      type: "user",
      value: victim.email,
      first_seen: T(0),
      last_seen: T(66 * MIN),
      reputation: "suspicious",
      tags: ["compromised-account", "helpdesk-mfa-reset"],
    },
    {
      type: "host",
      value: vdiHost.hostname,
      first_seen: T(66 * MIN),
      last_seen: T(66 * MIN),
      reputation: "unknown",
      tags: ["internal-vdi", "session-landed"],
    },
    {
      type: "ip",
      value: victim.homeIp,
      first_seen: T(0),
      last_seen: T(45 * MIN),
      reputation: "clean",
      tags: ["user-baseline", "london"],
    },
    {
      type: "host",
      value: victim.hostname,
      first_seen: T(0),
      last_seen: T(45 * MIN),
      reputation: "clean",
      tags: ["corporate-laptop", "entra-joined"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "Which pair of events makes this undeniable — not just an odd coincidence of timing?",
      hint: "Compare where l.ferreira's account is authenticating from at 09:45 against where it authenticates from at 10:01.",
      kind: "single",
      options: [
        {
          value: "concurrent_sessions",
          label:
            "evt_hmr_03_second_baseline_signin + evt_hmr_07_new_geo_signin — the same account, genuinely MFA-satisfied, from London and from Amsterdam sixteen minutes apart",
        },
        {
          value: "ticket_pair",
          label: "evt_hmr_02_ticket_created + evt_hmr_04_ticket_resolved — the ticket was opened and closed unusually fast",
        },
        {
          value: "reset_alone",
          label: "evt_hmr_05_mfa_reset on its own — any MFA reset by the help desk is inherently a red flag",
        },
        {
          value: "vdi_alone",
          label: "evt_hmr_08_vdi_session on its own — a session landing on a VDI host is unusual by itself",
        },
      ],
      answer: "concurrent_sessions",
      xp: 50,
      explanation:
        "No commercial flight gets a person from London to Amsterdam in sixteen minutes, and both records show a completed password + Authenticator MFA challenge — this isn't a stale token or a risk-engine guess, it's two independently authenticated sessions on one account at the same time. Option (b) is a normal turnaround for a routine call; NexaCorp's help desk resolves several MFA-reset tickets a week in under fifteen minutes. Option (c) overstates a single field — MFA resets are routine help-desk work, not evidence on their own. Option (d) is real supporting detail but proves nothing without the concurrent-session evidence behind it.",
    },
    {
      id: "q2",
      prompt:
        "A month ago a different employee called this same help desk after genuinely losing her phone: MFA was reset, and she registered a new Authenticator that afternoon from her desk. What in THIS case distinguishes it from that ordinary one?",
      hint: "Ask where the new-device registration actually came from, and what the account owner was doing at the same time.",
      kind: "single",
      options: [
        {
          value: "ip_and_concurrent",
          label:
            "The new device was registered from an IP that matches neither the help desk network nor either of l.ferreira's own sign-ins, while her own session was still active elsewhere",
        },
        {
          value: "verification_dob",
          label: "The caller was verified using date of birth, which on its own always means the call was fraudulent",
        },
        {
          value: "any_reset_bad",
          label: "Any MFA reset performed over the phone rather than in person should be treated as compromise",
        },
        {
          value: "ticket_priority",
          label: "The ticket was logged as priority 3 rather than priority 1, which is inconsistent with a real lockout",
        },
      ],
      answer: "ip_and_concurrent",
      xp: 70,
      explanation:
        "The genuine lost-phone case looks exactly like evt_hmr_02 through evt_hmr_05 on their own — a phone call, a reset, a new registration. What separates an ordinary re-enrollment from this one is where evt_hmr_06 comes from: 185.220.101.47, an address that appears nowhere else in l.ferreira's telemetry, and the fact that her own laptop was still authenticating normally from London in evt_hmr_03 seven minutes before the reset even started. An employee who actually lost her phone doesn't have a second, live, unrelated session running from her own desk while someone else re-enrolls her account. Option (b) overweights a single, common verification method — DOB checks are standard and weak, but weak process alone isn't proof of an incident. Option (c) would flag every legitimate lost-phone case; phone-based MFA resets are how most help desks operate. Option (d) is not a real signal — urgency and priority reflect what the caller claimed, not what happened next.",
    },
    {
      id: "q3",
      prompt:
        "In evt_hmr_06, initiatedBy.user.userPrincipalName reads l.ferreira@nexacorp.com — her own identity performed the registration. Why doesn't that clear her?",
      hint: "InitiatedBy tells you which account was used. It does not tell you who was sitting at the keyboard.",
      kind: "single",
      options: [
        {
          value: "identity_vs_network",
          label:
            "Once MFA is cleared and a password is known, anyone can act as that identity — initiatedBy proves which account was used, not who controlled it; the ipAddress field is what shows this wasn't her",
        },
        {
          value: "field_wrong",
          label: "This field is only populated for admin-initiated actions, so it must be a logging error here",
        },
        {
          value: "self_service_impossible",
          label: "Users cannot register their own security info through self-service, so this record is necessarily forged",
        },
        {
          value: "doesnt_matter",
          label: "It doesn't matter who initiated it, because the activity itself — registering an Authenticator — is not a sensitive action",
        },
      ],
      answer: "identity_vs_network",
      xp: 60,
      explanation:
        "After evt_hmr_05, l.ferreira's account had no registered second factor and a password the caller had just had reset — exactly the state needed for anyone who knows that password to sign in and self-enroll a fresh Authenticator, which is precisely what evt_hmr_06 records. Entra logs faithfully report which account performed the action; it has no way to know whose hands were on the keyboard. That's why ipAddress matters here — it's independent, network-layer evidence that sits alongside the identity claim, and in this record it points to Amsterdam while every other trace of l.ferreira that morning points to London. Option (b) is wrong — self-service registration is exactly how most users legitimately re-enroll after a reset. Option (c) is also wrong for the same reason. Option (d) understates the technique: T1098.005 exists precisely because a self-registered authenticator is a durable foothold that survives a password change.",
    },
    {
      id: "q4",
      prompt: "You're closing this out. Which action set actually removes the attacker's access?",
      hint: "A password reset alone does nothing to an authenticator that's already enrolled.",
      kind: "single",
      options: [
        {
          value: "revoke_and_delete",
          label:
            "Revoke l.ferreira's sessions and refresh tokens, delete the Authenticator method added at evt_hmr_06, reset the password, and verify her identity out-of-band",
        },
        {
          value: "reset_password_only",
          label: "Reset the password a second time, note the earlier reset in the ticket, and consider the matter closed",
        },
        {
          value: "block_ip_only",
          label: "Block 185.220.101.47 at the perimeter — with the attacker IP blocked, their access to the account is gone",
        },
        {
          value: "retrain_agent",
          label: "The account itself is fine; this only calls for retraining James Oduya on the verification procedure he skipped",
        },
      ],
      answer: "revoke_and_delete",
      xp: 70,
      explanation:
        "A second password reset does nothing on its own — the attacker's Authenticator app, registered at evt_hmr_06, still satisfies MFA on the very next sign-in attempt, password change or not. The session opened at evt_hmr_07 also needs to be killed directly; a live session can outlast a credential change. Blocking the IP (option c) stops nothing durable — it's trivial to originate the next sign-in from a different address once the rogue authenticator is already enrolled. Retraining the help desk (option d) is a legitimate process fix for next time, but it does not touch the account that is compromised right now. The only sequence that actually closes this out is: revoke sessions and tokens first (kills the live access), remove the attacker's registered method (closes the persistence), reset the password, and confirm with l.ferreira herself through a channel other than the phone number that called in — the same one an attacker could also spoof.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Help Desk MFA Reset — Social Engineering Account Takeover",
    threat_actor: "Scattered-Spider-style ATO operator (help-desk social engineering)",
    attack_kind: "helpdesk_mfa_reset_ato",
    briefing:
      "A ServiceNow ticket for l.ferreira@nexacorp.com was opened and resolved this morning as a routine MFA reset. Entra sign-in logs show two successful, MFA-satisfied sign-ins for the same account within the same hour, and CrowdStrike recorded a new interactive session landing on an internal VDI host shortly after. Determine whether this is ordinary help-desk support or an account takeover, and what to do about it.",
    narrative: `At 09:00 Lucia Ferreira, a trade settlements analyst, signed in to Office from her usual London address on her corporate laptop, MFA completed by an Authenticator push — an entirely ordinary start to the day.

At 09:41 the IT Service Desk opened ticket INC0048217: the caller reported being locked out and having lost her phone, and asked for a password and MFA reset. James Oduya verified the caller with an employee ID and date of birth over the phone — the bank's standard phone-verification procedure, and also exactly what a caller who has done a little research on their target can usually produce (T1656). At 09:45, four minutes into that call, Lucia's own account signed in again from the same London address on the same laptop — she was at her desk in SharePoint the entire time.

At 09:52 the ticket was resolved: password reset, MFA requirement cleared, caller told to re-enroll on next sign-in — closed exactly the way this help desk closes several tickets like it every week. One minute later the reset itself landed in the directory (T1556.006). Five minutes after that, at 09:58, a new Microsoft Authenticator was registered as Lucia's security info. The identity performing the registration was hers — because by then anyone holding the new password could act as her — but the IP address behind it was 185.220.101.47 in Amsterdam, an address that appears nowhere else in her telemetry (T1098.005).

At 10:01 that account signed in to Exchange Online from the same Amsterdam address, on an unmanaged Windows 10 machine running Chrome. Password and MFA both genuinely completed — Conditional Access shows success, sign-in risk shows none, because the attacker now held a working second factor and Entra's risk engine had nothing unusual to key on (T1078.004). Five minutes later a fresh session started on VDI-POOL-014 under her account.

No single record here reads as malicious. The ticket looks like routine support. The reset looks like routine administration. The sign-in genuinely passes every automated check available to it. What gives this away is only the sequence, laid against one plain fact the automated tooling never checked: the real Lucia Ferreira was still working from London when someone else, five minutes after her ticket closed, registered a new phone on her account from the Netherlands.`,
    learning_objectives: [
      "Recognise help-desk-driven MFA reset abuse (T1656, T1556.006, T1098.005) as an identity attack path that produces no malware and no exploit telemetry at all",
      "Read Entra AuditLogs initiatedBy fields correctly: an action attributed to the victim's own identity is not proof the victim performed it once MFA has been cleared",
      "Use a concurrent, independently-authenticated session as stronger evidence of takeover than an anomalous IP or geography alone",
      "Distinguish a genuine lost-device MFA reset from a social-engineered one using network-layer evidence (source IP) rather than the presence of a reset itself",
      "Select containment that addresses persistence — revoking sessions and removing the attacker-registered authentication method — not just a second password change",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: T(0), phase: "Baseline", action: "l.ferreira signs in normally from London with an Authenticator push" },
      { ts: T(41 * MIN), phase: "Impersonation", action: "Caller impersonates l.ferreira to the help desk, requests password + MFA reset (T1656)" },
      { ts: T(45 * MIN), phase: "Baseline", action: "l.ferreira signs in again from the same London address — still genuinely active" },
      { ts: T(52 * MIN), phase: "Impersonation", action: "Ticket INC0048217 resolved: password reset, MFA cleared" },
      { ts: T(53 * MIN), phase: "Defense Evasion", action: "Registered authentication methods cleared on the account (T1556.006)" },
      { ts: T(58 * MIN), phase: "Persistence", action: "New Microsoft Authenticator registered from 185.220.101.47, Amsterdam (T1098.005)" },
      { ts: T(61 * MIN), phase: "Initial Access", action: "Account signs in from Amsterdam, MFA genuinely satisfied on the new device (T1078.004)" },
      { ts: T(66 * MIN), phase: "Lateral Movement", action: "New session lands on internal host VDI-POOL-014" },
    ],
    questions,
  };
}
