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
import { adfsTokenIssue, winDirectoryAccess, winKeyFileOp } from "@/lib/sim/emitters/windowsSecurity";
import { entraSignIn } from "@/lib/sim/emitters/entra";
import { sentinelAlert } from "@/lib/sim/emitters/sentinel";

/** Telemetry half of the goldenSaml scenario: the events and the story title, no answer key. */
export function goldenSamlScenarioEvents() {
  const title = "Golden SAML — a Federation Token With No Matching AD FS Issuance";
  const B = new Date("2026-08-30T03:00:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;

  // One incident — the whole federation-abuse chain is a single case.
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
  const svcAdfsSid = "S-1-5-21-3421479547-3897544621-1789562108-1149";

  // The AD FS token issuer and the relying party (Microsoft cloud federation).
  const issuerUri = "http://adfs.nexacorp.com/adfs/services/trust";
  const relyingParty = "urn:federation:MicrosoftOnline";

  // The privileged accounts the attacker mints tokens for. They never actually
  // sign in — the assertions are signed offline and presented to the cloud.
  const ga1 = { upn: "a.whitfield@nexacorp.com", sam: "a.whitfield", name: "Alan Whitfield", title: "Global Administrator" };
  const ga2 = { upn: "m.abbott@nexacorp.com", sam: "m.abbott", name: "Marcus Abbott", title: "Cloud Administrator" };
  const ga1Sid = "S-1-5-21-3421479547-3897544621-1789562108-2501";

  // The benign control identity — a genuine federated sign-in with a real
  // on-prem AD FS issuance behind it.
  const benign = { upn: "r.donovan@nexacorp.com", sam: "r.donovan", name: "Rachel Donovan", title: "Finance Analyst" };

  // Addresses: the attacker's external host (drives the forged sign-ins) and the
  // corporate egress the benign user comes from.
  const attackerIp = "185.220.101.61";
  const corpEgressIp = "91.132.92.24";

  // The exported token-signing certificate's private-key file (the stolen key
  // material). Its hash is the durable indicator of the theft.
  const signingKeyFileHash = makeSha256("golden_saml_adfs_token_signing_privatekey_export_2026");

  // Correlation ids: the benign AD FS issuance and its Entra sign-in share one;
  // the malicious sign-ins carry ids that resolve to no AD FS issuance at all.
  const benignFedTokenId = "e1c4a97b-2f60-4d83-9a15-7b3e0c6d2f48";

  const cx = "nexacorp" as const;

  const events: TelemetryEvent[] = [
    // 0. BENIGN CONTROL (on-prem) — a real AD FS token issuance (1200) for r.donovan.
    adfsTokenIssue({
      companyId: cx, id: "evt_gs_00_benign_adfs_issue", ts: "2026-08-28T14:30:04.000Z",
      host: adfs.hostname, fqdn: adfs.fqdn, targetUser: benign.sam, userEmail: benign.upn, clientIp: corpEgressIp,
      instanceId: benignFedTokenId, relyingParty, issuerUri, authnMethods: "http://schemas.microsoft.com/claims/multipleauthn",
      resultStatus: "Success", recordId: "7742013", severity: "informational", expectedVerdict: "fp",
      fpExplanation: "This is the on-prem half of the control case. ADFS-NEXA-01 wrote a token-issuance audit record (Event 1200) for r.donovan: the federation service genuinely minted the assertion after a real MFA, for the Microsoft cloud relying party, from the office egress in business hours. Every legitimately issued federation token leaves a record exactly like this on the server. The malicious sign-ins later in this case have no such record — that absence is the whole point.",
      description: "ADFS-NEXA-01 logged an AD FS token-issuance audit (Event 1200) for r.donovan to the Microsoft cloud relying party at 14:30, after an interactive multi-factor authentication from the office egress.",
    }),

    // 1. BENIGN CONTROL (cloud) — the matching Entra federated sign-in (same shape, fp).
    {
      ...entraSignIn({
        companyId: cx, id: "evt_gs_01_benign_federated_signin", ts: "2026-08-28T14:30:07.000Z",
        srcIp: corpEgressIp, user: benign.upn, displayName: benign.name, userTitle: benign.title,
        userId: "c2b7e419-3a05-4d68-9f14-6b8d2e0a7c53", app: "Office 365 Exchange Online", appId: "00000002-0000-0ff1-ce00-000000000000",
        resource: "Office 365 Exchange Online", mfa: true, isInteractive: true,
        tokenIssuerType: "ADFSFederated", tokenIssuerName: issuerUri, federatedTokenId: benignFedTokenId,
        authenticationProtocol: "saml20", authStepResultDetail: "MFA requirement satisfied by claim in the token", conditionalAccess: "success",
        riskLevel: "none", geo: { country: "United Kingdom", city: "London" }, severity: "informational",
        description: "Entra ID accepted a federated (ADFSFederated) sign-in for r.donovan from the office egress at 14:30, correlating to the AD FS token issuance on ADFS-NEXA-01.",
      }),
      expected_verdict: "fp",
      fp_explanation: "The cloud half of the control. This federated sign-in is structurally identical to the malicious ones — tokenIssuerType ADFSFederated, and an authentication detail reading 'MFA requirement satisfied by claim in the token'. What makes it benign is that it pairs with the AD FS issuance record on ADFS-NEXA-01 (evt 0, same InstanceId), and it originates from the office egress during the workday. The issuer type and the MFA-by-claim entry do NOT distinguish good from bad here — only the presence of the on-prem issuance does.",
    },

    // 2. THE DKM KEY READ — 4662 on the DC, DKM master-key object read (T1552.004).
    winDirectoryAccess({
      companyId: cx, id: "evt_gs_02_dkm_object_access", ts: T(0), host: dc.hostname, fqdn: dc.fqdn, srcIp: adfs.ip,
      targetUser: svcAdfs.sam, subjectSid: svcAdfsSid, subjectLogonId: "0x9F3A211",
      objectType: "%{7b8b558a-93a5-4af7-adb3-9b923604d0e2}",
      objectName: "CN=8b2f1d47-3e90-4c6a-9d21-5f0e7c2a4b83,CN=ADFS,CN=Microsoft,CN=Program Data,DC=nexacorp,DC=com",
      accessList: "%%7688", accessMask: "0x10", properties: "%%7688\n\t{28630ebc-41d5-11d1-a9c1-0000f80367c1}",
      recordId: "10488213", mitre: "T1552.004", tactic: "Credential Access", severity: "high", incidentId: INCIDENT,
      description: "A 4662 on DC-NEXA-01 recorded a read of the AD FS DKM master-key object under CN=ADFS,CN=Microsoft,CN=Program Data — the secret that decrypts the federation token-signing private key — by the svc-adfs session, sourced from ADFS-NEXA-01.",
    }),

    // 3. THE SIGNING-KEY EXPORT — 5058 key-file operation on the AD FS server (T1552.004).
    winKeyFileOp({
      companyId: cx, id: "evt_gs_03_signing_key_export", ts: T(2 * MIN), host: adfs.hostname, fqdn: adfs.fqdn, srcIp: adfs.ip,
      targetUser: svcAdfs.sam, subjectSid: svcAdfsSid, subjectLogonId: "0x9F3A211",
      operation: "Read persisted key from file.", keyName: "ADFS-Signing-nexacorp.com", keyType: "Machine key.",
      providerName: "Microsoft Software Key Storage Provider", algorithmName: "RSA", returnCode: "0x0",
      keyFilePath: "C:\\ProgramData\\adfs-tokensigning-export.pfx", exportedSha256: signingKeyFileHash,
      recordId: "5566902", mitre: "T1552.004", tactic: "Credential Access", severity: "critical", incidentId: INCIDENT,
      description: "A 5058 on ADFS-NEXA-01 recorded a read of the persisted private key for the AD FS token-signing certificate under the svc-adfs session, with an export written to C:\\ProgramData\\adfs-tokensigning-export.pfx.",
    }),

    // 4. THE TELL — a federated sign-in for GA a.whitfield, external IP, no on-prem issuance.
    entraSignIn({
      companyId: cx, id: "evt_gs_04_signin_ga_whitfield", ts: T(11 * MIN), srcIp: attackerIp,
      user: ga1.upn, displayName: ga1.name, userTitle: ga1.title, userId: "f0e5c284-7b13-4a96-8d20-5c9e1b7a3f42",
      app: "Microsoft Azure Management", appId: "84070985-06ea-473d-82fe-eb82b4011c9d", resource: "Windows Azure Service Management API",
      mfa: true, isInteractive: false, tokenIssuerType: "ADFSFederated", tokenIssuerName: issuerUri,
      federatedTokenId: "b3d90c26-51e8-4f77-a4d2-9e6b1c7f0a35", authenticationProtocol: "saml20",
      authStepResultDetail: "MFA requirement satisfied by claim in the token", conditionalAccess: "notApplicable", riskLevel: "none",
      geo: { country: "Germany", city: "Frankfurt", latitude: 50.1109, longitude: 8.6821 },
      mitre: "T1606.002", tactic: "Credential Access", severity: "critical", incidentId: INCIDENT,
      description: "Entra ID accepted a federated (ADFSFederated) sign-in for the Global Administrator a.whitfield from 185.220.101.61 at 03:11, MFA recorded as satisfied by a claim in the token — with no corresponding token-issuance record on ADFS-NEXA-01.",
    }),

    // 5. FORGE ANY USER — a second minted token, this time GA m.abbott (T1078.004).
    entraSignIn({
      companyId: cx, id: "evt_gs_05_signin_ga_abbott", ts: T(14 * MIN), srcIp: attackerIp,
      user: ga2.upn, displayName: ga2.name, userTitle: ga2.title, userId: "a9c4e017-2f58-4d63-8b10-7e2d9c1a6f04",
      app: "Microsoft Graph", appId: "00000003-0000-0000-c000-000000000000", resource: "Microsoft Graph",
      mfa: true, isInteractive: false, tokenIssuerType: "ADFSFederated", tokenIssuerName: issuerUri,
      federatedTokenId: "d5a71e08-3c92-4b46-8f13-2a9e6c0b7d51", authenticationProtocol: "saml20",
      authStepResultDetail: "MFA requirement satisfied by claim in the token", conditionalAccess: "notApplicable", riskLevel: "none",
      geo: { country: "Germany", city: "Frankfurt" },
      mitre: "T1078.004", tactic: "Stealth", severity: "critical", incidentId: INCIDENT,
      description: "A second federated sign-in from 185.220.101.61 minutes later, this time for the Cloud Administrator m.abbott — again ADFSFederated, again with no matching AD FS issuance on ADFS-NEXA-01.",
    }),

    // 6. THE TOKEN IN USE — the a.whitfield assertion exchanged into the directory API (T1550.001).
    entraSignIn({
      companyId: cx, id: "evt_gs_06_token_use_directory", ts: T(17 * MIN), srcIp: attackerIp,
      user: ga1.upn, displayName: ga1.name, userTitle: ga1.title, userId: "f0e5c284-7b13-4a96-8d20-5c9e1b7a3f42",
      app: "Microsoft Graph", appId: "00000003-0000-0000-c000-000000000000", resource: "Microsoft Graph",
      isInteractive: false, incomingTokenType: "saml", tokenIssuerType: "ADFSFederated", tokenIssuerName: issuerUri,
      authenticationProtocol: "saml20", conditionalAccess: "notApplicable",
      geo: { country: "Germany", city: "Frankfurt" },
      mitre: "T1550.001", tactic: "Lateral Movement", severity: "high", incidentId: INCIDENT,
      description: "The a.whitfield token was exchanged for an access token to the directory management API from the same external address — a federation assertion carried straight into privileged tenant access with no interactive logon behind it.",
    }),

    // 7. THE DETECTION — Sentinel: SAML tokens accepted with no matching AD FS issuance.
    {
      ...sentinelAlert({
        companyId: cx, id: "evt_gs_07_sentinel_correlation", ts: T(20 * MIN), host: adfs.hostname, srcIp: attackerIp,
        user: ga1.upn, eventType: "ueba_anomaly", alertName: "Federation token accepted with no matching AD FS issuance",
        ruleId: "SEN-IDENT-0417", severity: "critical", mitre: "T1606.002", tactic: "Credential Access",
        fullName: ga1.name, title: ga1.title,
        detail: "Two federated sign-ins with tokenIssuerType ADFSFederated were accepted for privileged accounts with no corresponding token-issuance record on ADFS-NEXA-01 within the correlation window.",
        extendedProperties: {
          "Token Issuer Type": "ADFSFederated",
          "Federation Service Issuer": issuerUri,
          "Matching AD FS Issuance": "none",
          "Privileged Accounts In Window": `${ga1.sam}, ${ga2.sam}`,
          "Client IP Address": attackerIp,
          "Correlated On-Prem Events": "4662 DKM object read; 5058 token-signing key export",
          "Window Start": T(11 * MIN),
          "Window End": T(17 * MIN),
        },
        description: "Sentinel raised a Critical alert: two federated sign-ins for privileged accounts (a.whitfield, m.abbott) were accepted by the cloud with an AD FS issuer, but ADFS-NEXA-01 logged no token issuance for either — joined to a DKM key read and a signing-key export on the federation server.",
      }),
      is_detection: true,
      edr_scope: "non_edr",
    },
  ];

  return { title, events, B, T, MIN, SEC, INCIDENT, tenantId, domain, adfs, dc, svcAdfs, svcAdfsSid, issuerUri, relyingParty, ga1, ga2, ga1Sid, benign, attackerIp, corpEgressIp, signingKeyFileHash, benignFedTokenId, cx };
}
