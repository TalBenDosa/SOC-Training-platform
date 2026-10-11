/**
 * Adversary-in-the-Middle Phishing — Session Token Theft (ADVANCED)
 *
 * Evilginx/Tycoon-style reverse-proxy phishing. The lesson is deliberately
 * uncomfortable: MFA was satisfied correctly, by the real user, on the real
 * identity provider — and the account fell anyway, because what the attacker
 * stole was the post-authentication session cookie, not the password.
 *
 * The discriminating evidence is findable, not narrated: one `sessionId`
 * appears on two Entra sign-ins six minutes apart, from two IPs in two
 * autonomous systems, with two different browser fingerprints — and the second
 * one carries `authenticationRequirement: "multiFactorAuthentication"` that the
 * user never performed.
 */
import type { IOC, ScenarioBundle, ScenarioQuestion } from "@/lib/sim/types";
import { aitmTokenTheftScenarioEvents } from "./aitmTokenTheft.events";

export function buildAitmTokenTheftScenario(scenarioId = "aitm-token-theft-2026"): ScenarioBundle {
  const { title, events, T, MIN, SEC, victim, proxyIp, replayIp, vpnEgress, phishHost, phishUrl } = aitmTokenTheftScenarioEvents();

  const iocs: IOC[] = [
    { type: "domain", value: phishHost,                    first_seen: T(4 * MIN + 6 * SEC),  reputation: "malicious",  tags: ["look-alike", "newly-registered"] },
    { type: "url",    value: phishUrl,                     first_seen: T(4 * MIN),            reputation: "malicious",  tags: ["credential-harvest", "mail-lure"] },
    { type: "ip",     value: proxyIp,                      first_seen: T(4 * MIN + 6 * SEC),  reputation: "malicious",  tags: ["hosting", "as60068", "external"] },
    { type: "ip",     value: replayIp,                     first_seen: T(12 * MIN + 3 * SEC), reputation: "malicious",  tags: ["hosting", "as51167", "external"] },
    { type: "email",  value: "billing@docu-sign-secure.com", first_seen: T(0),                reputation: "malicious",  tags: ["sender", "dmarc-none"] },
    { type: "domain", value: "docu-sign-secure.com",       first_seen: T(0),                  reputation: "malicious",  tags: ["sender-domain", "look-alike"] },
    { type: "user",   value: victim,                       first_seen: T(0),                  reputation: "suspicious", tags: ["compromised-account", "finance"] },
    { type: "ip",     value: vpnEgress,                    first_seen: T(9 * MIN),            reputation: "clean",      tags: ["corporate-vpn", "named-location"] },
  ];

  const killchain = [
    { ts: T(0),                     phase: "Initial Access",      action: "Lure delivered to m.delgado from docu-sign-secure.com with a link to login.nexacorp-sso.com" },
    { ts: T(4 * MIN),               phase: "Initial Access",      action: "User follows the rewritten link; gateway permits the click" },
    { ts: T(4 * MIN + 9 * SEC),     phase: "Collection",          action: "Browser loads the reverse-proxy sign-in page (Zscaler category: Newly Registered Domains)" },
    { ts: T(5 * MIN + 41 * SEC),    phase: "Credential Access",   action: "Credentials and the live MFA response are relayed through the proxy to the real Microsoft endpoint" },
    { ts: T(6 * MIN + 3 * SEC),     phase: "Initial Access",      action: "Entra records a genuine interactive sign-in, MFA satisfied, sourced from the proxy in Amsterdam" },
    { ts: T(6 * MIN + 12 * SEC),    phase: "Stealth",             action: "Victim redirected to the real office.com — the sign-in appears to have simply worked" },
    { ts: T(12 * MIN + 3 * SEC),    phase: "Lateral Movement",    action: "Stolen session cookie replayed from Frankfurt on the same sessionId; MFA satisfied by token claim" },
    { ts: T(12 * MIN + 20 * SEC),   phase: "Lateral Movement",    action: "Replayed session brokers a non-interactive token for Office 365 Exchange Online" },
    { ts: T(13 * MIN + 47 * SEC),   phase: "Collection",          action: "Mailbox bind against the Inbox recorded in the Unified Audit Log with the same SessionId" },
    { ts: T(19 * MIN),              phase: "Persistence",         action: "Second Authenticator method registered on the account by the account — survives a password reset" },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1", xp: 20,
      prompt: "Event aitm_06 is a successful, MFA-satisfied sign-in for m.delgado. What does its ipAddress field tell you when read against the proxy logs?",
      hint: "Compare the Entra client address with the address m.delgado's own browser traffic came from.",
      kind: "single",
      options: [
        { value: "a", label: "It is 45.87.81.126 in Amsterdam — the host her browser posted the sign-in form to" },
        { value: "b", label: "It is 81.174.22.63 in London — the corporate egress, matching her own browsing traffic" },
        { value: "c", label: "It is 91.132.139.204 in Frankfurt — the host that reuses the session six minutes later" },
        { value: "d", label: "It is a Microsoft service address, because the request was relayed inside the tenant" },
      ],
      answer: "a",
      explanation:
        "Zscaler (aitm_04, aitm_05) shows the user's browser leaving from 81.174.22.63 in London, so option b describes where she really was — but that is not what Entra recorded. Entra saw 45.87.81.126, because in a reverse-proxy phish the identity provider talks to the proxy, not to the victim. Option c is the replay host, which appears later in aitm_09. Option d is not how Entra sign-in logging works: ipAddress is always the client that reached the token endpoint. The mismatch between where the user browsed from and where Entra saw the sign-in from is the first structural tell of AitM.",
    },
    {
      id: "q2", xp: 25,
      prompt: "Conditional Access required MFA, the user genuinely approved an Authenticator push, and the account was still taken over. Why did MFA not prevent this?",
      hint: "Ask what the attacker actually ended up holding at the end of the sign-in.",
      kind: "single",
      options: [
        { value: "a", label: "She approved a push she should have rejected, so the second factor was never really satisfied" },
        { value: "b", label: "Conditional Access was misconfigured and did not apply the MFA grant control to this app" },
        { value: "c", label: "The proxy relayed the live MFA response and kept the session cookie Entra issued afterwards" },
        { value: "d", label: "The Authenticator registration was weak, letting the attacker derive valid codes offline" },
      ],
      answer: "c",
      explanation:
        "Option a describes MFA fatigue, a different attack — here the push arrived while she was actively signing in, so approving it was the correct behaviour. Option b is contradicted by the evidence: aitm_06 shows appliedConditionalAccessPolicies 'Require MFA for all users' with result 'success' and enforcedGrantControls ['Mfa']. Option d is not a real property of push-based Authenticator. MFA is an authentication-time control; it says nothing about what happens to the artefact issued after authentication. The proxy sat in the middle, passed the challenge and response through untouched, and harvested the resulting session cookie — which is why aitm_09 needs no authentication step at all.",
    },
    {
      id: "q3", xp: 25,
      prompt: "Which pair of events, read together, proves a stolen session cookie was replayed rather than a second legitimate sign-in occurring?",
      hint: "Look for a field that should be unique to one browser on one machine.",
      kind: "single",
      options: [
        { value: "a", label: "The URL Defense click and the proxy POST — the same look-alike URL shows up in both the click and the form submit" },
        { value: "b", label: "The Amsterdam sign-in and the Frankfurt Chrome 121 sign-in — one sessionId, two IPs, two ASNs, two browsers" },
        { value: "c", label: "The Chrome 121 sign-in and the OWA MailItemsAccessed bind — mailbox access follows it within two minutes" },
        { value: "d", label: "The Amsterdam sign-in and the LT-SLS-0117 Frankfurt sign-in — a London baseline seen in Europe twice at once" },
      ],
      answer: "b",
      explanation:
        "Option a only proves the user visited the phishing site; it says nothing about what happened to the session afterwards. Option c is real follow-on activity but is equally consistent with the attacker having simply logged in with a stolen password. Option d compares two different people — aitm_08 is a.rosen, not m.delgado. Only aitm_06 and aitm_09 carry the identical sessionId 0f2c1e64-3b7a-4c19-9d84-5a6e2f8b17d3 while disagreeing on ipAddress (45.87.81.126 vs 91.132.139.204), autonomousSystemNumber (60068 vs 51167) and deviceDetail.browser (Edge 122 vs Chrome 121). One session identifier cannot legitimately be held by two browsers on two machines 365 km apart six minutes apart. The second record also has isInteractive: false and authenticationStepResultDetail 'MFA requirement satisfied by claim in the token' — nobody authenticated.",
    },
    {
      id: "q4", xp: 20,
      prompt: "aitm_08 shows a.rosen signing in from Frankfurt against a London baseline, which fired the same geo-change logic. What separates it from the replay in aitm_09?",
      hint: "Both records are in Germany. Look at what each one had to do to get its MFA claim.",
      kind: "single",
      options: [
        { value: "a", label: "It has its own sessionId and a fresh Authenticator approval on a compliant Entra-joined device" },
        { value: "b", label: "It is a lower-severity record, and Entra assigned it no sign-in risk at all during authentication" },
        { value: "c", label: "It comes from Germany, which is allow-listed, whereas the replay came in from the Netherlands" },
        { value: "d", label: "It is an interactive sign-in, and interactive sign-ins can never come from a replayed cookie" },
      ],
      answer: "a",
      explanation:
        "Option b is a trap: riskLevelDuringSignIn is 'none' on aitm_09 too, so risk scoring does not discriminate here at all — that is part of the lesson. Option c is factually wrong; the replay in aitm_09 is also in Frankfurt, Germany. Only the proxy front end (aitm_06) was in the Netherlands, and geography alone never separates these cases. Option d overstates a true fact — an attacker can drive an interactive browser session, so isInteractive is supporting evidence, not proof. The real discriminators on aitm_08 are structural: a distinct sessionId, two authenticationDetails entries with timestamps seconds before the sign-in (a second factor actually performed), deviceDetail.isCompliant true with trustType 'Azure AD joined', and a networkLocationDetails entry naming the corporate VPN. aitm_09 has none of these.",
    },
    {
      id: "q5", xp: 20,
      prompt: "Containment has been approved. Which action set actually removes the attacker's access in this incident?",
      hint: "Two artefacts here outlive a password change.",
      kind: "single",
      options: [
        { value: "a", label: "Reset the password, then have the user re-approve MFA on her own phone to restore a trusted session" },
        { value: "b", label: "Block 91.132.139.204 at the perimeter and purge the lure message from every mailbox in the tenant" },
        { value: "c", label: "Revoke refresh tokens and sessions, delete the attacker-registered method, then reset the password" },
        { value: "d", label: "Disable the account for 24 hours and re-enable it once the look-alike domain has been fully taken down" },
      ],
      answer: "c",
      explanation:
        "Option a fails on both artefacts: a password reset does not invalidate an already-issued session cookie, and the extra Authenticator method registered in aitm_12 stays on the account afterwards, letting the attacker complete MFA on a future sign-in. Option b is useful hygiene but the attacker simply moves to another host; IP blocking does not touch the stolen token. Option d buys time and then hands the account back with the rogue method still enrolled. The correct order is revoke first (this is what kills the live session), then remove the registered authentication method, then reset the password — and only afterwards review sign-in logs for any other session that shares sessionId 0f2c1e64-….",
    },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "Storm-1167 (AitM phishing-as-a-service operator)",
    attack_kind: "aitm_session_hijack",
    briefing: "Entra ID flagged two sign-ins for m.delgado (LT-FIN-0442) six minutes apart from different countries, at 07:18 and 07:24. The user reports nothing wrong and is working normally. A separate geo-change alert on a.rosen is attached for comparison.",
    narrative:
      "A finance controller receives a signature-request lure and follows it to login.nexacorp-sso.com, a look-alike host fronting a reverse proxy. She types her password and approves a genuine Microsoft Authenticator push — the sign-in really does complete, MFA really is satisfied, and Conditional Access really does pass. The proxy relays every step to the real Microsoft endpoint and keeps the session cookie Entra issues at the end. Six minutes later that same session identifier reappears from a hosting provider in Frankfurt, on a different browser, in a different autonomous system, with no authentication step performed: the multifactor requirement is satisfied by a claim already inside the token. The attacker brokers a mailbox token, reads the Inbox, and registers a second Authenticator method on the account — a normal self-service action for a standard user, and one that survives the password reset the SOC is about to order. A colleague signing in from Frankfurt on the corporate VPN the same morning trips the same geo-change logic and is entirely benign.",
    learning_objectives: [
      "Trace an AitM reverse-proxy chain from the mail lure through the look-alike domain to a genuine Entra sign-in whose client address is the proxy, not the user",
      "Explain why a satisfied multifactor requirement did not prevent the compromise, and what MFA does and does not protect",
      "Correlate two Entra sign-in records on a shared session identifier to prove session-cookie replay rather than a second legitimate logon",
      "Discriminate token replay from an ordinary travel or VPN geo change using session, authentication-step and device-compliance evidence",
      "Select containment that invalidates the stolen session and removes the attacker-registered authentication method, not just the password",
    ],
    alerts: [], // alerts are attached by the catalogue wiring
    events,
    iocs,
    killchain,
    questions,
  };
}
