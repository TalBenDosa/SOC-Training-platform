/**
 * Scenario pack: "Golden SAML — a Federation Token Accepted by the Cloud With No
 * Matching Issuance on the On-Prem AD FS Server"
 *
 * EXPERT tier — the platform's hardest case. A federation-trust abuse with almost
 * no "loud" artifact: the whole intrusion turns on an ABSENCE. The attacker has
 * already compromised the on-prem AD FS server (foothold out of scope). From
 * there they read the AD FS DKM master key out of Active Directory and export the
 * token-signing certificate's private key. Holding that key, they can mint SAML
 * assertions for ANY user and present them straight to the cloud — Entra ID
 * accepts them because they are signed by the trusted federation key. No real
 * logon ever happens at the identity provider.
 *
 * THE DEFINITIVE TELL: a federated sign-in appears in Entra ID stamped as issued
 * by AD FS (tokenIssuerType = ADFSFederated), yet ADFS-NEXA-01 logged NO
 * token-issuance / authentication event for that session. AD FS writes an audit
 * record every time it actually issues a token; a cloud sign-in that claims an
 * AD FS issuer with no corresponding on-prem issuance can only have been signed
 * away from the service. Reinforcing tells: the sign-ins are for privileged
 * accounts at odd hours from an external address, and each carries an MFA claim
 * that was "satisfied by a claim in the token" though no challenge was ever
 * presented. Modelled on the SolarWinds / APT29 TTP.
 *
 * THE BENIGN CONTROL (evt 0 + evt 1): a legitimate AD FS federated sign-in for
 * r.donovan that DOES have its matching on-prem AD FS issuance event and normal
 * claims. Same "federated SAML sign-in to the cloud" shape — same ADFSFederated
 * issuer type, same MFA-by-claim entry — opposite verdict. The discriminator is
 * exactly what the malicious sign-in is missing: a corresponding token-issuance
 * record on the federation server, from the office egress in business hours.
 *
 * SOURCES (only three registry vendors): microsoft-active-directory (the AD FS
 * server Windows Security events — DKM object access 4662, token-signing key
 * export 5058, and the benign AD FS token-issuance audit), azure-ad (the Entra ID
 * federated SAML sign-ins), microsoft-sentinel (the correlation that flags a SAML
 * token accepted with no matching AD FS authentication).
 *
 * NOTE: register in scenarios.ts with difficulty "expert". The ScenarioBundle
 * itself carries no difficulty field.
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";
import { adfsTokenIssue, winDirectoryAccess, winKeyFileOp } from "@/lib/sim/emitters/windowsSecurity";
import { entraSignIn } from "@/lib/sim/emitters/entra";
import { sentinelAlert } from "@/lib/sim/emitters/sentinel";

export function buildGoldenSamlScenario(
  scenarioId = "golden-saml-2026",
): ScenarioBundle {
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
  // material). Its hash is the durable IOC for the theft.
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
      mitre: "T1078.004", tactic: "Defense Evasion", severity: "critical", incidentId: INCIDENT,
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
      mitre: "T1550.001", tactic: "Defense Evasion", severity: "high", incidentId: INCIDENT,
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

  const iocs: IOC[] = [
    {
      type: "host",
      value: adfs.hostname, // ADFS-NEXA-01 — the compromised federation server / signing-key source
      first_seen: T(0),
      last_seen: T(20 * MIN),
      reputation: "unknown",
      tags: ["federation-server", "signing-key-source", "affected"],
    },
    {
      type: "ip",
      value: attackerIp, // 185.220.101.61 — the external address that presents the minted tokens
      first_seen: T(11 * MIN),
      last_seen: T(20 * MIN),
      reputation: "malicious",
      tags: ["external", "sign-in-source", "control-plane"],
    },
    {
      type: "user",
      value: ga1.sam, // a.whitfield — the privileged account impersonated to the cloud
      first_seen: T(11 * MIN),
      last_seen: T(17 * MIN),
      reputation: "suspicious",
      tags: ["global-administrator", "impersonated-identity", "privileged"],
    },
    {
      type: "user",
      value: ga2.sam, // m.abbott — a second impersonated privileged account
      first_seen: T(14 * MIN),
      last_seen: T(14 * MIN),
      reputation: "suspicious",
      tags: ["cloud-administrator", "impersonated-identity", "privileged"],
    },
    {
      type: "sha256",
      value: signingKeyFileHash, // the exported token-signing private-key file
      first_seen: T(2 * MIN),
      last_seen: T(2 * MIN),
      reputation: "malicious",
      tags: ["token-signing-key", "exported-material", "key-theft"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "Entra ID shows a federated sign-in for a.whitfield stamped as issued by the on-prem AD FS service, yet ADFS-NEXA-01 logged no token-issuance event for that session. Why does that gap prove the assertion was minted offline with the stolen signing key rather than issued by the identity provider?",
      hint: "Ask what AD FS records every time it actually mints a token, and what it means when a cloud sign-in claims that issuer but no such record exists.",
      kind: "single",
      options: [
        { value: "no_issuance", label: "AD FS writes a token-issuance audit record every time it actually mints a token, so a cloud sign-in that claims an AD FS issuer with no such record on the server can only come from an assertion signed away from the service" },
        { value: "clock_skew", label: "Clock drift between the AD FS server and the cloud routinely hides the paired record, so the gap is an artifact of time synchronisation rather than evidence of anything real" },
        { value: "repl_lag", label: "Directory replication latency holds AD FS audit records back for several hours, so the issuance event had simply not reached the log yet when the sign-in appeared" },
        { value: "cached_ticket", label: "The account reused a cached Kerberos ticket from an earlier session, which lets the cloud accept the sign-in without the federation server being contacted at all" },
      ],
      answer: "no_issuance",
      xp: 70,
      explanation:
        "This absence is the whole case. AD FS emits an issuance audit (the benign control, evt 0, is exactly such a record) every time it genuinely mints a federation token. A forged Golden SAML token is built and signed on the attacker's machine using the stolen token-signing key and presented straight to the cloud, so the federation service is never involved and writes nothing. A cloud sign-in that advertises tokenIssuerType=ADFSFederated while ADFS-NEXA-01 shows no matching issuance therefore cannot have come from the identity provider — it was minted offline. (b) is wrong: clock skew shifts a record's timestamp, it does not delete the record. (c) is wrong: AD FS audit is written locally on issuance and does not depend on directory replication. (d) is wrong: Kerberos is on-prem and unrelated — the cloud accepts the signed SAML assertion because it trusts the signing key, not because of any ticket.",
    },
    {
      id: "q2",
      prompt:
        "Which pair of on-prem observations explains how the intruder gained the ability to authenticate as ANY user to the cloud?",
      hint: "The cloud trusts one specific key. Find the two events that together hand that key over.",
      kind: "single",
      options: [
        { value: "dkm_and_export", label: "The 4662 read of the AD FS DKM key object and the 5058 export of the token-signing certificate's private key — together they hand over the material that signs every federation assertion" },
        { value: "role_write", label: "A directory role-assignment write that granted the intruder Domain Admins, carrying an implicit right to issue tokens for the whole tenant" },
        { value: "bulk_reset", label: "A bulk password reset across the privileged accounts, letting the intruder sign in interactively as each of them in turn" },
        { value: "group_add", label: "The addition of the attacker's account to Enterprise Admins, which by itself lets a principal mint cloud tokens for arbitrary users" },
      ],
      answer: "dkm_and_export",
      xp: 65,
      explanation:
        "Signing SAML tokens for arbitrary users needs one thing: the federation token-signing private key. On the AD FS design that key is encrypted in the certificate and can only be decrypted with the AD FS DKM master key, which lives in Active Directory. So the intruder needs both halves — the 4662 shows the DKM key object being read out of the directory (T1552.004), and the 5058 shows the token-signing certificate's private key read for export off the server (T1552.004). With both, tokens can be signed for anyone, and the cloud honours them. (b) and (d) are Active-Directory privilege changes that grant on-prem rights but do not by themselves let a principal sign federation tokens. (c) would leave a trail of real logons and does not touch the signing key at all.",
    },
    {
      id: "q3",
      prompt:
        "The cloud sign-in records that a multi-factor requirement was 'satisfied by a claim in the token', though no challenge was ever presented to a.whitfield. Why can MFA not stop this technique?",
      hint: "Consider what the cloud does with the authentication-method claims inside a token it already trusts the signature of.",
      kind: "single",
      options: [
        { value: "claims_trusted", label: "The cloud trusts the whole signed assertion including its authentication-method claims, so a token that asserts MFA was performed is honoured as complete and no challenge is ever raised" },
        { value: "mfa_fatigue", label: "The account was worn down by repeated push prompts and eventually approved one, and that approval is what the token's MFA claim records" },
        { value: "ca_gap", label: "A Conditional Access exclusion for legacy protocols let the sign-in skip MFA, and closing that policy hole would have blocked the token" },
        { value: "not_enrolled", label: "The user had never enrolled a second factor, so the cloud fell back to password-only and stamped the MFA claim by default" },
      ],
      answer: "claims_trusted",
      xp: 60,
      explanation:
        "In a federation trust the cloud delegates authentication — including how strongly the user was authenticated — to the identity provider and reads that verdict from the signed token's claims. Whoever holds the signing key controls those claims, so a minted token simply asserts that MFA was completed and the cloud accepts it without ever contacting the user. That is why the detail reads 'MFA requirement satisfied by claim in the token' with no challenge behind it. (b) describes a real push-bombing attack, but here no prompt was ever sent. (c) misreads the mechanism: the token is not evading a Conditional Access rule, it is presenting a trusted MFA claim, so the policy sees its condition as already met. (d) is false — Entra does not silently self-assert MFA for unenrolled users.",
    },
    {
      id: "q4",
      prompt:
        "An earlier federated sign-in for r.donovan looks structurally identical — same ADFSFederated issuer type, same MFA-by-claim entry. What actually separates it from the a.whitfield sign-in?",
      hint: "One of the two sign-ins pairs with something on the federation server. The issuer type and the MFA entry are the same on both.",
      kind: "single",
      options: [
        { value: "has_issuance", label: "Her cloud login pairs with a token-issuance entry on the federation server and originated from the office egress during the workday; the privileged one pairs with nothing on that server and came from a foreign host at night" },
        { value: "issuer_type", label: "Her sign-in carries a different token issuer type, and that field alone is what marks a genuine identity-provider login" },
        { value: "result_code", label: "Her sign-in returned a non-zero result code showing the federation service rejected it, whereas the privileged one completed cleanly" },
        { value: "resource", label: "She reached only a mailbox resource while the privileged sign-in reached a management API, and the resource alone tells the two apart" },
      ],
      answer: "has_issuance",
      xp: 65,
      explanation:
        "This is the pedagogical crux: the fields people reach for first — the issuer type and the MFA entry — are identical on both, so neither discriminates. The genuine login (r.donovan) has a paired AD FS issuance record on ADFS-NEXA-01 (evt 0, same InstanceId) and comes from the office egress in business hours. The minted one has no such on-prem record and arrives from an external host overnight. (b) is wrong: both read tokenIssuerType=ADFSFederated. (c) is wrong: both succeeded with result code 0 — a rejected token would never have been accepted by the cloud. (d) over-reads one field: which resource was reached reflects intent, not authenticity, and a genuine token can target any resource the user is entitled to.",
    },
    {
      id: "q5",
      prompt:
        "You are scoping containment. The token-signing key material is assumed stolen and tokens minted with it have already reached the cloud as Global Administrator. Which response matches the evidence?",
      hint: "The cloud's trust is anchored on the signing certificate, and AD FS keeps more than one signing certificate valid at a time.",
      kind: "single",
      options: [
        { value: "roll_revoke", label: "Roll the AD FS token-signing certificate twice to retire the stolen key, revoke sessions and refresh tokens for the affected identities, and treat every federated account as exposed until the new key is in force" },
        { value: "block_ip", label: "Block the external address at the perimeter, which stops the minted tokens from being replayed and lets the incident be closed without further change" },
        { value: "reset_pw", label: "Reset a.whitfield's password and enforce a fresh MFA enrolment, since changing the credential invalidates the assertion the intruder presented to the cloud" },
        { value: "reimage_only", label: "Reimage the AD FS server only, because wiping the host removes the signing key and instantly voids every token already accepted from it" },
      ],
      answer: "roll_revoke",
      xp: 70,
      explanation:
        "The cloud's trust is anchored on the token-signing certificate, so recovery means retiring the stolen key everywhere it is honoured. AD FS keeps a current and a secondary signing certificate valid at once, so you roll the signing certificate twice to fully evict the compromised one, then revoke live sessions and refresh tokens for the impacted identities and treat all federated accounts as exposed until the new key propagates. (b) fails because the key mints tokens from any address — an IP block does nothing about the trust itself. (c) fails because a minted SAML token is signed offline and carries no password, so a reset changes something the attack never used. (d) fails because reimaging removes the local key file but does not invalidate tokens the cloud already trusts, nor the copy the attacker exported — only rolling the certificate and revoking tokens does.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Golden SAML — a Federation Token With No Matching AD FS Issuance",
    threat_actor: "Nation-state-style intrusion set abusing a compromised federation server (SolarWinds / APT29 TTP)",
    attack_kind: "federation_abuse",
    briefing:
      "Microsoft Sentinel raised a High alert at 03:14. The Global Administrator a.whitfield reached the cloud through the company's on-prem federation service from an external address overnight — but ADFS-NEXA-01 recorded no matching authentication for that session. Work out how the account signed in without ever touching the identity provider, which identities are exposed, and how far it reached before you contain it.",
    narrative: `The intruder already held the on-prem AD FS server ADFS-NEXA-01; how they reached it is out of scope. What they did with it is the case. At 03:00 the svc-adfs session read the AD FS DKM master-key object out of Active Directory (a 4662 on DC-NEXA-01), and two minutes later exported the token-signing certificate's private key off the server (a 5058, written to C:\\ProgramData\\adfs-tokensigning-export.pfx). Those two reads together hand over everything needed to sign federation assertions: the DKM key decrypts the signing certificate, and the certificate signs the tokens the cloud trusts.

With that key the intruder no longer needs to authenticate at all. At 03:11 a federated sign-in for the Global Administrator a.whitfield was accepted by the cloud — tokenIssuerType ADFSFederated, MFA recorded as "satisfied by a claim in the token" — from an external address in Frankfurt, at night. Crucially, ADFS-NEXA-01 logged no token issuance for it: a genuine federation login always leaves an issuance record on the server, and this one had none because the assertion was minted offline. Minutes later the same pattern produced a token for a second privileged account, m.abbott, and the a.whitfield token was then carried into the directory management API — a forged assertion turned into standing Global-Administrator access, no real logon anywhere behind it.

The one legitimate comparison in the data is two days earlier: r.donovan's federated sign-in, which looks structurally identical — same ADFSFederated issuer type, same MFA-by-claim entry — but pairs with a real AD FS issuance record on ADFS-NEXA-01 and came from the office egress during the workday. Same shape, opposite meaning; the difference is the presence of the on-prem issuance, which is exactly what a minted token lacks. Sentinel correlated the privileged federated sign-ins against the AD FS issuance log, found tokens accepted with no matching issuance, joined them to the DKM read and the signing-key export, and raised the alert at 03:14.`,
    learning_objectives: [
      "Recognise the defining tell of Golden SAML — a federated (ADFSFederated) sign-in accepted by the cloud with no matching token-issuance event on the on-prem AD FS server — and explain why that absence proves an offline-minted assertion",
      "Trace the signing capability back to its source: the AD FS DKM master-key read (4662) plus the token-signing private-key export (5058), the pair that lets tokens be signed for any user (T1552.004)",
      "Explain why MFA and password resets do not stop a signed federation assertion — the cloud trusts the token's authentication-method claims wholesale, and the token carries no password",
      "Separate a genuine federated sign-in from a minted one when the issuer type and MFA-by-claim entry are identical — using the presence of an on-prem issuance record, source address and time",
      "Scope containment for federation-trust abuse: roll the AD FS token-signing certificate twice, revoke sessions and refresh tokens, and treat every federated identity as exposed",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: "2026-08-28T14:30:04.000Z", phase: "Baseline", action: `Genuine AD FS token issuance for ${benign.sam} on ${adfs.hostname} — the attributable federation path` },
      { ts: T(0), phase: "Credential Access", action: `AD FS DKM master-key object read from AD (4662 on ${dc.hostname}) — decrypts the signing certificate (T1552.004)` },
      { ts: T(2 * MIN), phase: "Credential Access", action: `Token-signing certificate private key exported off ${adfs.hostname} (5058) (T1552.004)` },
      { ts: T(11 * MIN), phase: "Credential Access", action: `Federated sign-in for Global Admin ${ga1.sam} accepted by the cloud with no on-prem AD FS issuance (T1606.002)` },
      { ts: T(14 * MIN), phase: "Defense Evasion", action: `Second minted token for ${ga2.sam} — the key signs tokens for arbitrary users (T1078.004)` },
      { ts: T(17 * MIN), phase: "Defense Evasion", action: `${ga1.sam} token carried into the directory management API (T1550.001)` },
      { ts: T(20 * MIN), phase: "Detection", action: "Sentinel correlates federated sign-ins against the AD FS issuance log and flags the missing issuance" },
    ],
    questions,
  };
}
