/**
 * Events-only half of the ./goldenSaml.ts scenario pack.
 *
 * The dashboard's live feed runs in the browser (attackStories.ts), so what it
 * imports ships in a public /_next/static chunk. The answer key (questions,
 * answers, explanations, IOCs, killchain, narrative) stays in the builder in
 * ./goldenSaml.ts, which composes this module on the server. Keep anything
 * answer-bearing out of this file: every visitor can read it.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";
import { adfsTokenIssue, winDirectoryAccess, winKeyFileOp, winLogon } from "@/lib/sim/emitters/windowsSecurity";
import { entraSignIn, entraAudit } from "@/lib/sim/emitters/entra";
import { sentinelAlert } from "@/lib/sim/emitters/sentinel";
import { m365Operation } from "@/lib/sim/emitters/m365";
import { csProcess, csFile, csNetwork } from "@/lib/sim/emitters/crowdstrike";

/** Telemetry half of the goldenSaml scenario: the events and the story title, no answer key. */
export function goldenSamlScenarioEvents() {
  const title = "Overnight federated sign-in for a Global Administrator";
  const B = new Date("2026-08-30T03:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;

  // One incident, the whole federation-abuse chain is a single case.
  const INCIDENT = "inc:golden-saml:1";

  // Directory / tenant identifiers.
  const tenantId = "a7f3c9d1-2e84-4b6f-9d05-3c7e1a8b2f60";
  const domain = "nexacorp.com";

  // The compromised on-prem federation server and the DC that holds the DKM key.
  const adfs = { hostname: "ADFS-NEXA-01", fqdn: "ADFS-NEXA-01.nexacorp.com", ip: "10.20.5.15" };
  const dc = { hostname: "DC-NEXA-01", fqdn: "DC-NEXA-01.nexacorp.com", ip: "10.20.5.10" };

  // The AD FS service account whose session reads the DKM key and exports the
  // signing certificate on the compromised server.
  const svcAdfs = { sam: "svc-adfs", domain: "NEXACORP" };
  const svcAdfsEmail = "svc-adfs@nexacorp.com";
  const svcAdfsSid = "S-1-5-21-3421479547-3897544621-1789562108-1149";

  // The AD FS token issuer and the relying party (Microsoft cloud federation).
  const issuerUri = "http://adfs.nexacorp.com/adfs/services/trust";
  const relyingParty = "urn:federation:MicrosoftOnline";

  // The privileged accounts the attacker mints tokens for. They never actually
  // sign in, the assertions are signed offline and presented to the cloud.
  const ga1 = { upn: "a.whitfield@nexacorp.com", sam: "a.whitfield", name: "Alan Whitfield", title: "Global Administrator" };
  const ga2 = { upn: "m.abbott@nexacorp.com", sam: "m.abbott", name: "Marcus Abbott", title: "Cloud Administrator" };
  const ga1Sid = "S-1-5-21-3421479547-3897544621-1789562108-2501";

  // The benign control identity, a genuine federated sign-in with a real
  // on-prem AD FS issuance behind it.
  const benign = { upn: "r.donovan@nexacorp.com", sam: "r.donovan", name: "Rachel Donovan", title: "Finance Analyst" };

  // Addresses: the attacker's external host (drives the forged sign-ins) and the
  // corporate egress the benign user comes from.
  const attackerIp = "185.220.101.61";
  const corpEgressIp = "91.132.92.24";

  // The exported token-signing certificate's private-key file (the stolen key
  // material). Its hash is the durable indicator of the theft.
  const signingKeyFileHash = makeSha256("golden_saml_adfs_token_signing_privatekey_export_2026");

  // The tool that reads the DKM key over LDAP and writes the exported signing key to disk.
  const dumpToolHash = makeSha256("golden_saml_adfsdump_tool_on_adfs_server_2026");
  const dumpToolPath = "C:\\ProgramData\\adfsdump.exe";
  const pfxPath = "C:\\ProgramData\\adfs-tokensigning-export.pfx";
  // The workstation the svc-adfs session reaches the AD FS server from (the foothold itself is out of scope).
  const pivot = { hostname: "WKS-NEXA-141", ip: "10.20.6.141" };
  // Logon sessions are local to a machine: one on the AD FS server, a different one on the DC.
  const adfsLogonId = "0x4C81B7";
  const dcLogonId = "0x9F3A2D8";
  // CNG machine key container of the token-signing certificate's private key (5058/5059).
  const keyContainer = "6a2b9c1e4f7d3a58b0c9e21f7d4a8b63_e5f2a1c7-3b84-4d96-a0c1-9f7e2d4b6a85";
  const keyFile = `C:\\ProgramData\\Microsoft\\Crypto\\Keys\\${keyContainer}`;
  const ga1UserId = "f0e5c284-7b13-4a96-8d20-5c9e1b7a3f42";
  const ga2UserId = "a9c4e017-2f58-4d63-8b10-7e2d9c1a6f04";

  // Correlation ids: the benign AD FS issuance and its Entra sign-in share one;
  // the malicious sign-ins carry ids that resolve to no AD FS issuance at all.
  const benignFedTokenId = "e1c4a97b-2f60-4d83-9a15-7b3e0c6d2f48";

  const cx = "nexacorp" as const;

  // Patch fields the shared emitters cannot express (the emitter output stays the base).
  const withRaw = (e: TelemetryEvent, patch: Record<string, string>): TelemetryEvent => ({ ...e, raw: Object.assign({}, e.raw, patch) });

  // AD FS 1200 audit events are written to the Security log by the "AD FS Auditing" provider.
  const adfsIssue = adfsTokenIssue({
    companyId: cx, id: "evt_gs_00_benign_adfs_issue", ts: "2026-08-28T14:30:04.000Z",
    host: adfs.hostname, fqdn: adfs.fqdn, targetUser: benign.sam, userEmail: benign.upn, clientIp: corpEgressIp,
    instanceId: benignFedTokenId, relyingParty, issuerUri, authnMethods: "http://schemas.microsoft.com/claims/multipleauthn",
    resultStatus: "Success", recordId: "7742013", severity: "informational", expectedVerdict: "fp",
    fpExplanation: "This is the on-prem half of the control case. ADFS-NEXA-01 wrote a token-issuance audit record (Event 1200) for r.donovan: the federation service genuinely minted the assertion after a real MFA, for the Microsoft cloud relying party, from the office egress in business hours. Every legitimately issued federation token leaves a record exactly like this on the server. The malicious sign-ins later in this case have no such record, that absence is the whole point.",
    description: "ADFS-NEXA-01 logged an AD FS token-issuance audit (Event 1200) for r.donovan to the Microsoft cloud relying party at 14:30, after an interactive multi-factor authentication from the office egress.",
  });

  // The cloud sign-ins of the forged tokens share these facts.
  const forged = {
    companyId: cx, srcIp: attackerIp, mfa: true, isInteractive: false, tokenIssuerType: "ADFederationServices", tokenIssuerName: issuerUri,
    authenticationProtocol: "saml20", authStepResultDetail: "MFA requirement satisfied by claim in the token", riskLevel: "none",
    geo: { country: "Germany", city: "Frankfurt", latitude: 50.1109, longitude: 8.6821 },
    // No Conditional Access policy was evaluated for the forged sign-ins (a real value: notApplied).
    extra: { "azure.signinlogs.properties.conditionalAccessStatus": "notApplied" },
  } as const;

  const events: TelemetryEvent[] = [
    // 0. BENIGN CONTROL (on-prem), a real AD FS token issuance (1200) for r.donovan.
    withRaw(adfsIssue, { "winlog.channel": "Security" }),

    // 1. BENIGN CONTROL (cloud), the matching Entra federated sign-in (same shape, fp).
    {
      ...entraSignIn({
        companyId: cx, id: "evt_gs_01_benign_federated_signin", ts: "2026-08-28T14:30:07.000Z",
        srcIp: corpEgressIp, user: benign.upn, displayName: benign.name, userTitle: benign.title,
        userId: "c2b7e419-3a05-4d68-9f14-6b8d2e0a7c53", app: "Office 365 Exchange Online", appId: "00000002-0000-0ff1-ce00-000000000000",
        resource: "Office 365 Exchange Online", mfa: true, isInteractive: true,
        tokenIssuerType: "ADFederationServices", tokenIssuerName: issuerUri, federatedTokenId: benignFedTokenId,
        authenticationProtocol: "saml20", authStepResultDetail: "MFA requirement satisfied by claim in the token", conditionalAccess: "success",
        riskLevel: "none", geo: { country: "United Kingdom", city: "London" }, severity: "informational",
        description: "Entra ID accepted a federated (ADFederationServices) sign-in for r.donovan from the office egress at 14:30, correlating to the AD FS token issuance on ADFS-NEXA-01.",
      }),
      expected_verdict: "fp",
      fp_explanation: "The cloud half of the control. This federated sign-in is structurally identical to the malicious ones, tokenIssuerType ADFederationServices, and an authentication detail reading 'MFA requirement satisfied by claim in the token'. What makes it benign is that it pairs with the AD FS issuance record on ADFS-NEXA-01 (evt 0, same InstanceId, the correlation key this platform uses between the AD FS audit and the sign-in), and it originates from the office egress during the workday. The issuer type and the MFA-by-claim entry do NOT distinguish good from bad here, only the presence of the on-prem issuance does.",
    },

    // 2. THE SESSION THAT RUNS THE TOOLING, svc-adfs logs on to the AD FS server over the network (4624).
    winLogon({
      companyId: cx, id: "evt_gs_01b_adfs_logon", ts: T(-150 * SEC), host: adfs.hostname, fqdn: adfs.fqdn, srcIp: pivot.ip,
      targetUser: svcAdfs.sam, targetSid: svcAdfsSid, userEmail: null, logonType: 3, authPackage: "Kerberos", workstation: pivot.hostname,
      logonId: adfsLogonId, logSource: "windows_security", severity: "medium", incidentId: INCIDENT,
      description: "svc-adfs, the AD FS service account, logged on to ADFS-NEXA-01 over the network from a workstation at 02:57, a session that does not belong to the federation service itself.",
    }),

    // 3. THE TOOLING, PowerShell over WinRM, then the dumper (Falcon, ADFS-NEXA-01).
    csProcess({
      companyId: cx, id: "evt_gs_01c_powershell", ts: T(-110 * SEC), host: adfs.hostname, user: svcAdfsEmail, srcIp: adfs.ip, incidentId: INCIDENT,
      runAsUser: `${svcAdfs.domain}\\${svcAdfs.sam}`, integrity: "high",
      processName: "powershell.exe", processPath: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      cmdline: "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -NoProfile -NonInteractive",
      parentName: "wsmprovhost.exe", parentPid: 5188, pid: 6120, signed: true, signatureSubject: "Microsoft Windows", severity: "medium",
      mitre: "T1021.006", tactic: "Lateral Movement",
      description: "PowerShell started under the WinRM host process on ADFS-NEXA-01 in the svc-adfs session.",
    }),
    csProcess({
      companyId: cx, id: "evt_gs_01d_adfsdump", ts: T(-20 * SEC), host: adfs.hostname, user: svcAdfsEmail, srcIp: adfs.ip, incidentId: INCIDENT,
      runAsUser: `${svcAdfs.domain}\\${svcAdfs.sam}`, integrity: "high",
      processName: "adfsdump.exe", processPath: dumpToolPath, cmdline: `"${dumpToolPath}"`,
      parentName: "powershell.exe", parentPid: 6120, pid: 6244, sha256: dumpToolHash, signed: false, severity: "high",
      mitre: "T1552.004", tactic: "Credential Access",
      description: "An unsigned executable, adfsdump.exe, ran from C:\\ProgramData on ADFS-NEXA-01 under the PowerShell session.",
    }),
    csNetwork({
      companyId: cx, id: "evt_gs_01e_adfsdump_ldap", ts: T(-15 * SEC), host: adfs.hostname, user: svcAdfsEmail, srcIp: adfs.ip, incidentId: INCIDENT,
      remoteIp: dc.ip, remotePort: 389, application: "tls", severity: "medium",
      processName: "adfsdump.exe", processPath: dumpToolPath, pid: 6244, parentName: "powershell.exe", parentPid: 6120, sha256: dumpToolHash,
      cmdline: `"${dumpToolPath}"`,
      description: "adfsdump.exe opened a connection from ADFS-NEXA-01 to DC-NEXA-01 on port 389 (LDAP).",
    }),
    winLogon({
      companyId: cx, id: "evt_gs_01f_dc_logon", ts: T(-10 * SEC), host: dc.hostname, fqdn: dc.fqdn, srcIp: adfs.ip,
      targetUser: svcAdfs.sam, targetSid: svcAdfsSid, userEmail: null, logonType: 3, authPackage: "Kerberos", workstation: adfs.hostname,
      logonId: dcLogonId, severity: "medium", incidentId: INCIDENT,
      description: "svc-adfs logged on to DC-NEXA-01 over the network from ADFS-NEXA-01 (10.20.5.15) at 02:59.",
    }),

    // 4. THE DKM KEY READ, 4662 on the DC, DKM object read via the thumbnailPhoto attribute of the contact object (T1552.004).
    winDirectoryAccess({
      companyId: cx, id: "evt_gs_02_dkm_object_access", ts: T(0), host: dc.hostname, fqdn: dc.fqdn,
      targetUser: svcAdfs.sam, subjectSid: svcAdfsSid, subjectLogonId: dcLogonId,
      objectType: "%{5cb41ed0-0e4c-11d0-a286-00aa003049e2}",
      objectName: "CN=8b2f1d47-3e90-4c6a-9d21-5f0e7c2a4b83,CN=ADFS,CN=Microsoft,CN=Program Data,DC=nexacorp,DC=com",
      accessList: "%%7685", accessMask: "0x10", properties: "%%7685\n\t\t{8d3bca50-1d7e-11d0-a081-00aa006c33ed}\n\t{5cb41ed0-0e4c-11d0-a286-00aa003049e2}",
      recordId: "10488213", mitre: "T1552.004", tactic: "Credential Access", severity: "high", incidentId: INCIDENT,
      description: "A 4662 on DC-NEXA-01 recorded a read of the thumbnailPhoto attribute on the AD FS DKM contact object under CN=ADFS,CN=Microsoft,CN=Program Data, the secret that decrypts the federation token-signing private key, by the svc-adfs session.",
    }),

    // 5. THE SIGNING-KEY READ AND EXPORT, 5058 key-file read, then 5059 key migration, on the AD FS server (T1552.004).
    {
      ...winKeyFileOp({
        companyId: cx, id: "evt_gs_03_signing_key_export", ts: T(2 * MIN), host: adfs.hostname, fqdn: adfs.fqdn,
        targetUser: svcAdfs.sam, subjectSid: svcAdfsSid, subjectLogonId: adfsLogonId,
        operation: "Read persisted key from file.", keyName: keyContainer, keyType: "Machine key.",
        providerName: "Microsoft Software Key Storage Provider", algorithmName: "RSA", returnCode: "0x0",
        keyFilePath: keyFile,
        recordId: "5566902", mitre: "T1552.004", tactic: "Credential Access", severity: "critical", incidentId: INCIDENT,
        description: "A 5058 on ADFS-NEXA-01 recorded a read of the persisted private key of the AD FS token-signing certificate from the machine key store under the svc-adfs session.",
      }),
      source: "windows_security",
    },
    (() => {
      const e = winKeyFileOp({
        companyId: cx, id: "evt_gs_03b_signing_key_migration", ts: T(2 * MIN + 1 * SEC), host: adfs.hostname, fqdn: adfs.fqdn,
        targetUser: svcAdfs.sam, subjectSid: svcAdfsSid, subjectLogonId: adfsLogonId,
        operation: "Export of persistent cryptographic key.", keyName: keyContainer, keyType: "Machine key.",
        providerName: "Microsoft Software Key Storage Provider", algorithmName: "RSA", returnCode: "0x0",
        recordId: "5566903", mitre: "T1552.004", tactic: "Credential Access", severity: "critical", incidentId: INCIDENT,
        description: "A 5059 on ADFS-NEXA-01 recorded an export of the persistent token-signing key (key migration operation) under the same svc-adfs session.",
      });
      return { ...withRaw(e, { "winlog.event_id": "5059", "event.code": "5059", "event.action": "key-migration-operation" }), source: "windows_security" as const };
    })(),
    csFile({
      companyId: cx, id: "evt_gs_03c_pfx_written", ts: T(2 * MIN + 10 * SEC), host: adfs.hostname, user: svcAdfsEmail, srcIp: adfs.ip, incidentId: INCIDENT,
      action: "file_create", path: pfxPath, sha256: signingKeyFileHash, size: 3_624,
      actorProcess: "adfsdump.exe", actorPath: dumpToolPath, actorPid: 6244, actorParentName: "powershell.exe", actorParentPid: 6120,
      actorSha256: dumpToolHash, actorSigned: "unsigned", runAsUser: `${svcAdfs.domain}\\${svcAdfs.sam}`, severity: "critical",
      mitre: "T1552.004", tactic: "Credential Access",
      description: "adfsdump.exe wrote the exported token-signing key to C:\\ProgramData\\adfs-tokensigning-export.pfx on ADFS-NEXA-01.",
    }),

    // 6. THE TELL, a federated sign-in for GA a.whitfield, external IP, no on-prem issuance.
    entraSignIn({
      ...forged, id: "evt_gs_04_signin_ga_whitfield", ts: T(11 * MIN),
      user: ga1.upn, displayName: ga1.name, userTitle: ga1.title, userId: ga1UserId,
      app: "Microsoft Azure Management", appId: "84070985-06ea-473d-82fe-eb82b4011c9d", resource: "Windows Azure Service Management API",
      federatedTokenId: "b3d90c26-51e8-4f77-a4d2-9e6b1c7f0a35",
      mitre: "T1606.002", tactic: "Credential Access", severity: "critical", incidentId: INCIDENT,
      description: "Entra ID accepted a federated (ADFederationServices) sign-in for the Global Administrator a.whitfield from 185.220.101.61 at 03:11, MFA recorded as satisfied by a claim in the token, with no corresponding token-issuance record on ADFS-NEXA-01.",
    }),

    // 7. FORGE ANY USER, a second minted token, this time GA m.abbott (T1078.004).
    entraSignIn({
      ...forged, id: "evt_gs_05_signin_ga_abbott", ts: T(14 * MIN),
      user: ga2.upn, displayName: ga2.name, userTitle: ga2.title, userId: ga2UserId,
      app: "Microsoft Graph", appId: "00000003-0000-0000-c000-000000000000", resource: "Microsoft Graph",
      federatedTokenId: "d5a71e08-3c92-4b46-8f13-2a9e6c0b7d51",
      mitre: "T1078.004", tactic: "Stealth", severity: "critical", incidentId: INCIDENT,
      description: "A second federated sign-in from 185.220.101.61 minutes later, this time for the Cloud Administrator m.abbott, again ADFederationServices, again with no matching AD FS issuance on ADFS-NEXA-01.",
    }),

    // 8. THE TOKEN IN USE, the a.whitfield assertion exchanged into the directory API (T1550.001).
    entraSignIn({
      ...forged, id: "evt_gs_06_token_use_directory", ts: T(17 * MIN),
      user: ga1.upn, displayName: ga1.name, userTitle: ga1.title, userId: ga1UserId,
      app: "Microsoft Graph", appId: "00000003-0000-0000-c000-000000000000", resource: "Microsoft Graph",
      incomingTokenType: "saml", federatedTokenId: "b3d90c26-51e8-4f77-a4d2-9e6b1c7f0a35",
      mitre: "T1550.001", tactic: "Lateral Movement", severity: "high", incidentId: INCIDENT,
      description: "The a.whitfield token was exchanged for an access token to the directory management API from the same external address, a federation assertion carried straight into privileged tenant access with no interactive logon behind it.",
    }),

    // 9. WHAT THE ADMIN THEN DID IN THE TENANT, a credential added to an existing service principal,
    //    a role granted (Entra audit log), and mail read as m.abbott (Unified Audit Log).
    entraAudit({
      companyId: cx, id: "evt_gs_08_add_sp_credentials", ts: T(18 * MIN + 30 * SEC), incidentId: INCIDENT,
      operationName: "Add service principal credentials", category: "ApplicationManagement", loggedByService: "Core Directory", operationType: "Update",
      initiatedByUpn: ga1.upn, initiatedById: ga1UserId, initiatedByIp: attackerIp, initiatedByRoles: ["Global Administrator"],
      geo: { country: "Germany", city: "Frankfurt" }, eventType: "account_modify", severity: "critical",
      mitre: "T1098.001", tactic: "Persistence",
      extra: {
        "azure.auditlogs.properties.targetResources[0].type": "ServicePrincipal",
        "azure.auditlogs.properties.targetResources[0].id": "5d2c8e41-7a93-4f06-b1d8-3e9a0c6f2b57",
        "azure.auditlogs.properties.targetResources[0].displayName": "NexaCorp HR Sync",
        "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].displayName": "KeyDescription",
        "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].oldValue": "[]",
        "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].newValue": "[KeyIdentifier=2f8c1d94-6b07-4e53-a9c2-18d7e0f4b365;KeyType=Password;KeyUsage=Verify;DisplayName=sync-key]",
        "azure.auditlogs.target_resources.display_name": "NexaCorp HR Sync",
        "azure.auditlogs.target_resources.id": "5d2c8e41-7a93-4f06-b1d8-3e9a0c6f2b57",
        "data.office365.ModifiedProperties": "[KeyIdentifier=2f8c1d94-6b07-4e53-a9c2-18d7e0f4b365;KeyType=Password;KeyUsage=Verify;DisplayName=sync-key]",
      },
      description: "a.whitfield, from 185.220.101.61, added a new password credential to the existing service principal NexaCorp HR Sync.",
    }),
    entraAudit({
      companyId: cx, id: "evt_gs_09_add_role_member", ts: T(19 * MIN + 40 * SEC), incidentId: INCIDENT,
      operationName: "Add member to role", category: "RoleManagement", loggedByService: "Core Directory", operationType: "Assign",
      initiatedByUpn: ga1.upn, initiatedById: ga1UserId, initiatedByIp: attackerIp, initiatedByRoles: ["Global Administrator"],
      geo: { country: "Germany", city: "Frankfurt" }, eventType: "role_assignment", severity: "critical",
      mitre: "T1098.003", tactic: "Persistence",
      extra: {
        "azure.auditlogs.properties.targetResources[0].type": "User",
        "azure.auditlogs.properties.targetResources[0].userPrincipalName": ga2.upn,
        "azure.auditlogs.properties.targetResources[0].id": ga2UserId,
        "azure.role.name": "Global Reader",
        "azure.target.upn": ga2.upn,
        "azure.actor.upn": ga1.upn,
        "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].displayName": "Role.DisplayName",
        "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].oldValue": "[]",
        "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].newValue": "\"Global Reader\"",
      },
      description: "a.whitfield, from 185.220.101.61, added m.abbott to the Global Reader role.",
    }),

    // 10. THE DETECTION, Sentinel: SAML tokens accepted with no matching AD FS issuance.
    {
      ...sentinelAlert({
        companyId: cx, id: "evt_gs_07_sentinel_correlation", ts: T(20 * MIN), host: adfs.hostname, srcIp: adfs.ip,
        user: ga1.upn, eventType: "ueba_anomaly", alertName: "Federation token accepted with no matching AD FS issuance",
        ruleId: "SEN-IDENT-0417", severity: "high", mitre: "T1606.002", tactic: "Credential Access",
        fullName: ga1.name, title: ga1.title,
        detail: "Two federated sign-ins with tokenIssuerType ADFederationServices were accepted for privileged accounts with no corresponding token-issuance record on ADFS-NEXA-01 within the correlation window.",
        entities: [
          { "$id": "1", Type: "host", HostName: adfs.hostname, DnsDomain: domain, FQDN: adfs.fqdn },
          { "$id": "2", Type: "account", Name: ga1.sam, UPNSuffix: domain, AadUserId: ga1UserId },
          { "$id": "3", Type: "account", Name: ga2.sam, UPNSuffix: domain, AadUserId: ga2UserId },
          { "$id": "4", Type: "ip", Address: attackerIp },
        ],
        extendedProperties: {
          "Token Issuer Type": "ADFederationServices",
          "Federation Service Issuer": issuerUri,
          "Matching AD FS Issuance": "none",
          "Privileged Accounts In Window": `${ga1.sam}, ${ga2.sam}`,
          "Client IP Address": attackerIp,
          "Correlated On-Prem Events": "4662 DKM object read; 5058/5059 token-signing key read and export",
          "Window Start": T(11 * MIN),
          "Window End": T(17 * MIN),
        },
        description: "Sentinel raised a High alert: two federated sign-ins for privileged accounts (a.whitfield, m.abbott) were accepted by the cloud with an AD FS issuer, but ADFS-NEXA-01 logged no token issuance for either, joined to a DKM key read and a signing-key export on the federation server.",
      }),
      is_detection: true,
      edr_scope: "hybrid",
    },

    // 11. AFTER THE ALERT, the minted m.abbott identity reads mail (Unified Audit Log).
    // The same Frankfurt geolocation the sign-ins from this address carry (one IP, one country).
    { ...m365Operation({
      companyId: cx, id: "evt_gs_10_mail_items_accessed", ts: T(21 * MIN + 10 * SEC), user: ga2.upn, userTitle: ga2.title, srcIp: attackerIp, incidentId: INCIDENT,
      operation: "MailItemsAccessed", workload: "Exchange", userAgent: "python-requests/2.31.0", severity: "high",
      mitre: "T1114.002", tactic: "Collection",
      extra: { "RecordType": "50", "ClientInfoString": "Client=REST;Client=RESTSystem;;" },
      description: "The Exchange audit log recorded MailItemsAccessed for m.abbott from 185.220.101.61.",
    }), geo: { country: "Germany", city: "Frankfurt" } },
  ];

  return { title, events, B, T, MIN, SEC, INCIDENT, tenantId, domain, adfs, dc, svcAdfs, svcAdfsSid, issuerUri, relyingParty, ga1, ga2, ga1Sid, benign, attackerIp, corpEgressIp, signingKeyFileHash, dumpToolHash, pivot, ga1UserId, ga2UserId, benignFedTokenId, cx };
}
