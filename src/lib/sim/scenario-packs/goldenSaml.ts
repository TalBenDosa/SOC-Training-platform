import type { ScenarioBundle, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { goldenSamlScenarioEvents } from "./goldenSaml.events";
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


export function buildGoldenSamlScenario(
  scenarioId = "golden-saml-2026",
): ScenarioBundle {
  const { title, events, T, MIN, adfs, dc, ga1, ga2, benign, attackerIp, signingKeyFileHash } = goldenSamlScenarioEvents();

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
        { value: "no_issuance", label: "AD FS audits every token it genuinely mints, so a cloud sign-in claiming that issuer with no matching server record was signed somewhere else" },
        { value: "clock_skew", label: "Clock drift between the AD FS server and the cloud routinely hides the paired record, so the gap is an artifact of time synchronisation rather than evidence" },
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
        { value: "dkm_and_export", label: "The 4662 read of the AD FS DKM key object plus the 5058 export of the token-signing private key — together, the material that signs every assertion" },
        { value: "role_write", label: "A directory role-assignment write that granted the intruder Domain Admins, which carries an implicit right to issue federation tokens for the whole tenant" },
        { value: "bulk_reset", label: "A bulk password reset across the privileged accounts, letting the intruder sign in interactively as each one of them and then reach the cloud in turn" },
        { value: "group_add", label: "The addition of the attacker's account to Enterprise Admins, a forest-wide role which by itself lets a principal mint cloud tokens for arbitrary users" },
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
        { value: "claims_trusted", label: "The cloud trusts the signed assertion including its authentication-method claims, so a token asserting MFA was performed is honoured without any challenge" },
        { value: "mfa_fatigue", label: "The account was worn down by repeated push prompts overnight and eventually approved one, and that approval is what the token's MFA claim now records" },
        { value: "ca_gap", label: "A Conditional Access exclusion for legacy authentication protocols let the sign-in skip MFA, and closing that policy hole would have blocked the minted token" },
        { value: "not_enrolled", label: "The user had never enrolled a second factor, so the cloud fell back to password-only authentication and stamped the MFA claim onto the token by default" },
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
        { value: "has_issuance", label: "Hers pairs with an AD FS issuance record and came from the office egress by day; the privileged one pairs with none and came from an external host overnight" },
        { value: "issuer_type", label: "Her sign-in carries a different tokenIssuerType value, and that field alone is what marks a genuine identity-provider login rather than a forged assertion" },
        { value: "result_code", label: "Her sign-in returned a non-zero result code showing the federation service rejected it, whereas the privileged sign-in completed cleanly with result code 0" },
        { value: "resource", label: "She reached only a mailbox resource while the privileged sign-in reached a management API, and the resource targeted alone is enough to tell the two apart" },
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
        { value: "roll_revoke", label: "Roll the token-signing certificate twice, revoke sessions and refresh tokens for affected identities, and treat all federated accounts as exposed meanwhile" },
        { value: "block_ip", label: "Block the external address at the perimeter and in Conditional Access, which stops the minted tokens being replayed and lets the incident close without further change" },
        { value: "reset_pw", label: "Reset a.whitfield's password and enforce a fresh MFA enrolment, since changing the credential invalidates the assertion the intruder presented to the cloud" },
        { value: "reimage_only", label: "Reimage the AD FS server only, because wiping the host removes the signing key and so voids every token the cloud has already accepted from that server" },
      ],
      answer: "roll_revoke",
      xp: 70,
      explanation:
        "The cloud's trust is anchored on the token-signing certificate, so recovery means retiring the stolen key everywhere it is honoured. AD FS keeps a current and a secondary signing certificate valid at once, so you roll the signing certificate twice to fully evict the compromised one, then revoke live sessions and refresh tokens for the impacted identities and treat all federated accounts as exposed until the new key propagates. (b) fails because the key mints tokens from any address — an IP block does nothing about the trust itself. (c) fails because a minted SAML token is signed offline and carries no password, so a reset changes something the attack never used. (d) fails because reimaging removes the local key file but does not invalidate tokens the cloud already trusts, nor the copy the attacker exported — only rolling the certificate and revoking tokens does.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title,
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
      { ts: T(14 * MIN), phase: "Stealth", action: `Second minted token for ${ga2.sam} — the key signs tokens for arbitrary users (T1078.004)` },
      { ts: T(17 * MIN), phase: "Lateral Movement", action: `${ga1.sam} token carried into the directory management API (T1550.001)` },
      { ts: T(20 * MIN), phase: "Detection", action: "Sentinel correlates federated sign-ins against the AD FS issuance log and flags the missing issuance" },
    ],
    questions,
  };
}
